#!/usr/bin/env python3
"""Enterprise source, executable and runtime crypto discovery primitives.

The scanner never executes a target. Binary inspection is limited to bounded
file reads and read-only metadata tools such as readelf, nm and objdump.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import stat
import subprocess
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path

from scanner.cpp_semantic import analyze_cpp_source


SOURCE_LANGUAGES = {
    ".c": "c", ".h": "c", ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp",
    ".hh": "cpp", ".hpp": "cpp", ".hxx": "cpp", ".java": "java",
    ".rs": "rust", ".go": "go", ".py": "python", ".pyw": "python",
    ".sh": "shell", ".bash": "shell", ".zsh": "shell", ".ksh": "shell",
}
CONFIG_EXTENSIONS = {
    ".conf", ".cnf", ".cfg", ".ini", ".yaml", ".yml", ".json",
    ".properties", ".xml", ".txt", ".md", ".js", ".ts", ".toml",
    ".gradle", ".pom",
}
SOURCE_FILENAMES = {"Dockerfile": "config", "Makefile": "config", "pom.xml": "java"}
DEFAULT_EXCLUDES = {
    ".git", ".hg", ".svn", ".venv", "venv", "node_modules", "vendor",
    "experiment-results", "runtime-data", "__pycache__",
}


@dataclass(frozen=True)
class Rule:
    language: str
    library: str
    algorithm: str
    pattern: re.Pattern[str]
    evidence_type: str = "source_api_call"


def rule(language: str, library: str, algorithm: str, pattern: str, evidence_type: str = "source_api_call") -> Rule:
    return Rule(language, library, algorithm, re.compile(pattern, re.I), evidence_type)


def _compile_tokens(entry: dict) -> list[str]:
    arguments = entry.get("arguments")
    if isinstance(arguments, list) and all(isinstance(item, str) for item in arguments):
        return list(arguments)
    command = entry.get("command")
    if isinstance(command, str):
        try:
            return shlex.split(command)
        except ValueError:
            return []
    return []


def _compile_context(entry: dict, database: Path) -> tuple[str, dict] | None:
    """Parse compile_commands.json without executing compiler-controlled flags."""
    directory = Path(str(entry.get("directory") or database.parent))
    if not directory.is_absolute():
        directory = (database.parent / directory).resolve()
    source = Path(str(entry.get("file") or ""))
    if not str(source):
        return None
    if not source.is_absolute():
        source = (directory / source).resolve()
    tokens = _compile_tokens(entry)
    includes: list[str] = []
    definitions: dict[str, str] = {}
    semantic_arguments: list[str] = []
    standard = ""
    index = 1
    while index < len(tokens):
        token = tokens[index]
        value = ""
        if token in {"-I", "-isystem", "-iquote"} and index + 1 < len(tokens):
            value = tokens[index + 1]
            index += 1
        elif token.startswith("-I") and len(token) > 2:
            value = token[2:]
        elif token.startswith("-isystem") and len(token) > len("-isystem"):
            value = token[len("-isystem"):]
        if value:
            include = Path(value)
            if not include.is_absolute():
                include = (directory / include).resolve()
            includes.append(str(include))
            include_flag = token if token in {"-I", "-isystem", "-iquote"} else "-isystem" if token.startswith("-isystem") else "-I"
            semantic_arguments.extend([include_flag, str(include)])
        definition = ""
        if token == "-D" and index + 1 < len(tokens):
            definition = tokens[index + 1]
            index += 1
        elif token.startswith("-D") and len(token) > 2:
            definition = token[2:]
        if definition:
            name, _, macro_value = definition.partition("=")
            if re.fullmatch(r"[A-Za-z_]\w*", name):
                sensitive = bool(re.search(r"(?:PASS|TOKEN|SECRET|API_?KEY|CREDENTIAL)", name, re.I))
                definitions[name] = "<redacted>" if sensitive else (macro_value or "1")
                if not sensitive:
                    semantic_arguments.append(f"-D{name}={macro_value}" if macro_value else f"-D{name}")
        if token.startswith("-std="):
            standard = token.split("=", 1)[1]
            semantic_arguments.append(token)
        elif token in {"-nostdinc", "-nostdinc++", "-pthread", "-fms-extensions", "-fms-compatibility", "-fdelayed-template-parsing"}:
            semantic_arguments.append(token)
        elif token.startswith(("--target=", "--sysroot=", "-march=", "-mcpu=", "-mfpu=", "-mabi=")) or token in {"-m32", "-m64"}:
            semantic_arguments.append(token)
        elif token in {"-target", "-isysroot", "-U"} and index + 1 < len(tokens):
            semantic_arguments.extend([token, tokens[index + 1]])
            index += 1
        elif token.startswith("-U") and len(token) > 2 and re.fullmatch(r"[A-Za-z_]\w*", token[2:]):
            semantic_arguments.append(token)
        index += 1
    return str(source.resolve()), {
        "database": str(database.resolve()),
        "directory": str(directory.resolve()),
        "compiler": Path(tokens[0]).name if tokens else "",
        "standard": standard,
        "include_paths": sorted(set(includes))[:500],
        "definitions": definitions,
        "command_digest": hashlib.sha256("\0".join(tokens).encode()).hexdigest() if tokens else "",
        "command_executed": False,
        # Private scanner-only field. It is removed before report serialization.
        # The allowlist excludes plugins, response files, linker/output flags and
        # sensitive -D values.
        "_semantic_arguments": semantic_arguments[:2_000],
    }


def _public_compile_context(context: dict | None) -> dict:
    return {key: value for key, value in (context or {}).items() if not str(key).startswith("_")}


def load_compile_commands(paths: list[Path]) -> tuple[dict[str, dict], dict]:
    """Load bounded compilation databases as metadata; commands are never run."""
    contexts: dict[str, dict] = {}
    databases = 0
    invalid = 0
    entries = 0
    for path in paths[:100]:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeError):
            invalid += 1
            continue
        if not isinstance(payload, list):
            invalid += 1
            continue
        databases += 1
        for entry in payload[:100_000]:
            if not isinstance(entry, dict):
                continue
            parsed = _compile_context(entry, path)
            if parsed is None:
                continue
            source, context = parsed
            contexts[source] = context
            entries += 1
    return contexts, {"databases": databases, "entries": entries, "invalid": invalid}


# Rules intentionally identify interfaces, not merely algorithm words.  A small
# generic algorithm layer remains in crypto_inventory.py for configuration files.
SOURCE_RULES = [
    rule("c", "OpenSSL", "TLS", r"\b(?P<method>SSL_(?:CTX_)?(?:new|free|set_[A-Za-z0-9_]+|connect|accept|read|write)|TLS_(?:client|server)_method)\s*\("),
    rule("cpp", "OpenSSL", "TLS", r"\b(?P<method>SSL_(?:CTX_)?(?:new|free|set_[A-Za-z0-9_]+|connect|accept|read|write)|TLS_(?:client|server)_method)\s*\("),
    rule("c", "OpenSSL", "EVP/runtime-selected", r"\b(?P<method>EVP_(?:Cipher|Digest|Encrypt|Decrypt|Sign|Verify|PKEY|KEM)[A-Za-z0-9_]*)\s*\("),
    rule("cpp", "OpenSSL", "EVP/runtime-selected", r"\b(?P<method>EVP_(?:Cipher|Digest|Encrypt|Decrypt|Sign|Verify|PKEY|KEM)[A-Za-z0-9_]*)\s*\("),
    rule("c", "OpenSSL", "RSA", r"\b(?P<method>RSA_[A-Za-z0-9_]+)\s*\("),
    rule("cpp", "OpenSSL", "RSA", r"\b(?P<method>RSA_[A-Za-z0-9_]+)\s*\("),
    rule("c", "OpenSSL", "ECDSA/ECDH", r"\b(?P<method>(?:EC_KEY|ECDSA|ECDH)_[A-Za-z0-9_]+)\s*\("),
    rule("cpp", "OpenSSL", "ECDSA/ECDH", r"\b(?P<method>(?:EC_KEY|ECDSA|ECDH)_[A-Za-z0-9_]+)\s*\("),
    rule("c", "libsodium", "modern-crypto", r"\b(?P<method>(?:sodium|crypto_(?:box|sign|kx|secretbox|aead|pwhash))_[A-Za-z0-9_]+)\s*\("),
    rule("cpp", "libsodium", "modern-crypto", r"\b(?P<method>(?:sodium|crypto_(?:box|sign|kx|secretbox|aead|pwhash))_[A-Za-z0-9_]+)\s*\("),
    rule("cpp", "Botan", "runtime-selected", r"\b(?P<method>Botan::(?:TLS|Cipher_Mode|PK_Signer|PK_Verifier|HashFunction)[A-Za-z0-9_:]*)"),
    rule("cpp", "Crypto++", "runtime-selected", r"\b(?P<method>CryptoPP::(?:RSA|ECDSA|AES|GCM|SHA|DH)[A-Za-z0-9_:]*)"),
    rule("cpp", "wolfSSL", "TLS", r"\b(?P<method>wolfSSL_[A-Za-z0-9_]+)\s*\("),
    rule("cpp", "POSIX dynamic loader", "runtime-selected", r"\b(?P<method>(?:dlopen|dlmopen|dlsym))\s*\(", "dynamic_loading_review"),
    rule("cpp", "Windows dynamic loader", "runtime-selected", r"\b(?P<method>(?:LoadLibrary[AW]?|GetProcAddress))\s*\(", "dynamic_loading_review"),
    rule("cpp", "Qt meta-object", "runtime-selected", r"\b(?P<method>QMetaObject::invokeMethod)\s*\(", "dynamic_loading_review"),

    rule("java", "JCA/JCE", "runtime-selected", r"\b(?P<method>Cipher\.getInstance)\s*\(\s*[\"'](?P<algorithm>[^\"']+)"),
    rule("java", "JCA/JCE", "runtime-selected", r"\b(?P<method>Signature\.getInstance)\s*\(\s*[\"'](?P<algorithm>[^\"']+)"),
    rule("java", "JCA/JCE", "runtime-selected", r"\b(?P<method>KeyPairGenerator\.getInstance)\s*\(\s*[\"'](?P<algorithm>[^\"']+)"),
    rule("java", "JCA/JCE", "hash", r"\b(?P<method>MessageDigest\.getInstance)\s*\(\s*[\"'](?P<algorithm>[^\"']+)"),
    rule("java", "JSSE", "TLS", r"\b(?P<method>SSLContext\.getInstance)\s*\(\s*[\"'](?P<algorithm>[^\"']+)"),
    rule("java", "JCA/JCE", "keystore", r"\b(?P<method>KeyStore\.getInstance)\s*\("),
    rule("java", "BouncyCastle", "runtime-selected", r"\b(?P<method>(?:BouncyCastleProvider|org\.bouncycastle\.[A-Za-z0-9_.]+))"),

    rule("rust", "rustls", "TLS", r"(?P<method>rustls::(?:ClientConfig|ServerConfig|RootCertStore|crypto|pki_types)[A-Za-z0-9_:]*)"),
    rule("rust", "Rust openssl", "runtime-selected", r"(?P<method>openssl::(?:ssl|rsa|ec|encrypt|sign|hash)::[A-Za-z0-9_:]+)"),
    rule("rust", "ring", "runtime-selected", r"(?P<method>ring::(?:aead|agreement|digest|hmac|signature|rand)::[A-Za-z0-9_:]+)"),
    rule("rust", "aws-lc-rs", "runtime-selected", r"(?P<method>aws_lc_rs::[A-Za-z0-9_:]+)"),
    rule("rust", "liboqs", "PQC", r"(?P<method>(?:oqs|pqcrypto)::[A-Za-z0-9_:]+)"),
    rule("rust", "RustCrypto", "runtime-selected", r"(?P<method>(?:aes_gcm|chacha20poly1305|rsa|p256|p384|sha2)::[A-Za-z0-9_:]+)"),

    rule("go", "Go standard library", "TLS", r"\b(?P<method>tls\.(?:Config|Dial|Listen|Client|Server|LoadX509KeyPair))\b"),
    rule("go", "Go standard library", "X.509", r"\b(?P<method>x509\.(?:NewCertPool|SystemCertPool|ParseCertificate|CreateCertificate|LoadSystemCertPool))\b"),
    rule("go", "Go standard library", "RSA", r"\b(?P<method>rsa\.(?:GenerateKey|EncryptOAEP|DecryptOAEP|SignPSS|VerifyPSS))\b"),
    rule("go", "Go standard library", "ECDSA/ECDH", r"\b(?P<method>(?:ecdsa|ecdh)\.(?:GenerateKey|Sign|Verify|P256|P384|P521|X25519))\b"),
    rule("go", "Go standard library", "weak-hash", r"\b(?P<method>(?:sha1|md5)\.New)\b"),
    rule("go", "golang.org/x/crypto", "runtime-selected", r"(?P<method>golang\.org/x/crypto/[A-Za-z0-9_./-]+)"),

    rule("python", "Python ssl", "TLS", r"\b(?P<method>ssl\.(?:SSLContext|create_default_context|wrap_socket))\s*\("),
    rule("python", "cryptography", "runtime-selected", r"(?P<method>cryptography\.(?:hazmat|x509)\.[A-Za-z0-9_.]+)"),
    rule("python", "PyOpenSSL", "TLS", r"\b(?P<method>OpenSSL\.SSL\.[A-Za-z0-9_]+)"),
    rule("python", "PyCryptodome", "runtime-selected", r"\b(?P<method>Crypto\.(?:Cipher|PublicKey|Signature|Hash)\.[A-Za-z0-9_.]+)"),
    rule("python", "hashlib", "weak-hash", r"\b(?P<method>hashlib\.(?:md5|sha1))\s*\("),
    rule("python", "requests", "TLS", r"\b(?P<method>requests\.(?:get|post|put|request))\s*\([^\n]*(?:verify|cert)\s*="),

    rule("shell", "OpenSSL CLI", "runtime-selected", r"(?:^|[;&|]\s*|\b)(?P<method>openssl\s+(?:s_client|s_server|x509|pkey|req|genpkey|dgst|enc|cms|pkcs12))\b", "command_invocation"),
    rule("shell", "curl", "TLS", r"\b(?P<method>curl)\b[^\n]*(?:--cacert|--cert|--key|--ciphers|--curves|--tlsv1\.3)", "command_invocation"),
    rule("shell", "Java keytool", "keystore", r"\b(?P<method>(?:keytool|jarsigner))\b", "command_invocation"),
    rule("shell", "OpenSSH", "SSH", r"\b(?P<method>ssh-keygen)\b", "command_invocation"),
]


BINARY_RULES = [
    rule("cpp", "OpenSSL", "TLS", r"\b(?P<method>SSL_(?:CTX_)?[A-Za-z0-9_]+)\b", "binary_symbol"),
    rule("cpp", "OpenSSL", "EVP/runtime-selected", r"\b(?P<method>EVP_[A-Za-z0-9_]+)\b", "binary_symbol"),
    rule("cpp", "OpenSSL", "RSA", r"\b(?P<method>RSA_[A-Za-z0-9_]+)\b", "binary_symbol"),
    rule("cpp", "OpenSSL", "ECDSA/ECDH", r"\b(?P<method>(?:EC_KEY|ECDSA|ECDH)_[A-Za-z0-9_]+)\b", "binary_symbol"),
    rule("cpp", "libsodium", "modern-crypto", r"\b(?P<method>(?:sodium|crypto_(?:box|sign|kx|secretbox|aead|pwhash))_[A-Za-z0-9_]+)\b", "binary_symbol"),
    rule("cpp", "Botan", "runtime-selected", r"\b(?P<method>Botan::(?:TLS|Cipher_Mode|PK_Signer|PK_Verifier|HashFunction)[A-Za-z0-9_:]*)", "demangled_symbol"),
    rule("cpp", "Crypto++", "runtime-selected", r"\b(?P<method>CryptoPP::(?:RSA|ECDSA|AES|GCM|SHA|DH)[A-Za-z0-9_:]*)", "demangled_symbol"),
    rule("cpp", "wolfSSL", "TLS", r"\b(?P<method>wolfSSL_[A-Za-z0-9_]+)\b", "binary_symbol"),
    rule("cpp", "dynamic-loader", "runtime-selected", r"\b(?P<method>(?:dlopen|dlmopen|dlsym|LoadLibrary[AW]?|GetProcAddress|QMetaObject::invokeMethod))\b", "dynamic_loading_review"),
    rule("java", "JSSE", "TLS", r"(?P<method>javax[/\.]net[/\.]ssl[/\.]SSLContext|SSLContext\.getInstance)", "class_constant"),
    rule("java", "JCA/JCE", "runtime-selected", r"(?P<method>javax[/\.]crypto[/\.]Cipher|Cipher\.getInstance)", "class_constant"),
    rule("java", "JCA/JCE", "runtime-selected", r"(?P<method>java[/\.]security[/\.](?:Signature|KeyStore|MessageDigest|KeyPairGenerator))", "class_constant"),
    rule("java", "BouncyCastle", "runtime-selected", r"(?P<method>org[/\.]bouncycastle[/\.][A-Za-z0-9_/$.-]+)", "class_constant"),
    rule("go", "Go standard library", "TLS", r"(?P<method>crypto/tls(?:\.[A-Za-z0-9_()*]+)?)", "binary_string"),
    rule("go", "Go standard library", "X.509", r"(?P<method>crypto/x509(?:\.[A-Za-z0-9_()*]+)?)", "binary_string"),
    rule("go", "Go standard library", "RSA", r"(?P<method>crypto/rsa(?:\.[A-Za-z0-9_()*]+)?)", "binary_string"),
    rule("rust", "rustls", "TLS", r"(?P<method>rustls(?:::[A-Za-z0-9_$<>.-]+)+)", "binary_string"),
    rule("rust", "ring", "runtime-selected", r"(?P<method>ring::(?:aead|agreement|digest|hmac|signature)[A-Za-z0-9_:<>.-]*)", "binary_string"),
    rule("rust", "Rust openssl", "runtime-selected", r"(?P<method>openssl::(?:ssl|rsa|ec|encrypt|sign|hash)[A-Za-z0-9_:<>.-]*)", "binary_string"),
    rule("rust", "liboqs", "PQC", r"(?P<method>(?:oqs|pqcrypto)::[A-Za-z0-9_:<>.-]+)", "binary_string"),
    rule("python", "Python ssl", "TLS", r"(?P<method>ssl\.(?:SSLContext|create_default_context|wrap_socket))", "binary_string"),
    rule("python", "cryptography", "runtime-selected", r"(?P<method>cryptography\.(?:hazmat|x509)\.[A-Za-z0-9_.]+)", "binary_string"),
    Rule("windows", "CNG/CryptoAPI", "runtime-selected", re.compile(r"\b(?P<method>(?:BCrypt[A-Z]|NCrypt[A-Z]|Crypt(?:Acquire|Release|Encrypt|Decrypt|Gen|Import|Export|Protect|Unprotect|Sign|Verify|Hash|Derive|Get|Set|Duplicate|Enum|Find|Msg|Query|Decode|Encode))[A-Za-z0-9_]*)\b"), "imported_symbol"),
    rule("generic", "PQC", "PQC", r"\b(?P<method>(?:X25519MLKEM768|MLKEM[0-9]+|ML-?KEM|ML-?DSA|SLH-?DSA|Dilithium|Kyber|liboqs|OQS_[A-Za-z0-9_]+))\b", "binary_string"),
]

CRYPTO_LIBRARY = re.compile(
    r"(?:^|/)(?:lib)?(?:ssl|crypto|sodium|gcrypt|nettle|gnutls|mbedtls|wolfssl|botan|oqs|aws-lc|boringssl)[^/\s]*",
    re.I,
)


@dataclass
class Artifact:
    artifact_id: str
    path: str
    artifact_type: str
    file_format: str
    sha256: str
    size: int
    executable: bool
    languages: list[str] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)
    imported_symbols: list[str] = field(default_factory=list)
    demangled_symbols: list[str] = field(default_factory=list)
    confidence: str = "MEDIUM"
    metadata: dict = field(default_factory=dict)


@dataclass
class RuntimeProcess:
    process_id: str
    pid: int
    executable: str
    command: str
    mapped_crypto_libraries: list[str]
    confidence: str = "HIGH"
    metadata: dict = field(default_factory=dict)


def stable_id(prefix: str, *parts: object) -> str:
    blob = "\x1f".join(str(part) for part in parts)
    return f"{prefix}-" + hashlib.sha256(blob.encode()).hexdigest()[:20]


def _run_tool(cmd: list[str], timeout: int = 8) -> tuple[int, str]:
    try:
        result = subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 124, str(exc)
    return result.returncode, (result.stdout + b"\n" + result.stderr).decode("utf-8", "replace")


def _language(path: Path, raw: bytes) -> str:
    language = SOURCE_LANGUAGES.get(path.suffix.lower()) or SOURCE_FILENAMES.get(path.name, "")
    if language:
        return language
    first_line = raw[:256].decode("utf-8", "replace").splitlines()[0] if raw else ""
    if first_line.startswith("#!"):
        lowered = first_line.lower()
        if "python" in lowered:
            return "python"
        if re.search(r"(?:^|[\s/])(?:ba|z|k)?sh(?:\s|$)", lowered):
            return "shell"
    return ""


def scan_source_text(path: Path, text: str, language: str) -> list[dict]:
    output: list[dict] = []
    for line_number, line in enumerate(text.splitlines(), 1):
        for item in SOURCE_RULES:
            if item.language != language:
                continue
            for match in item.pattern.finditer(line):
                groups = match.groupdict()
                method = groups.get("method") or match.group(0)
                algorithm = groups.get("algorithm") or item.algorithm
                output.append({
                    "line": line_number,
                    "evidence_type": item.evidence_type,
                    "algorithm": algorithm,
                    "excerpt": line.strip()[:500],
                    "language": language,
                    "method": method[:240],
                    "library": item.library,
                    "confidence": "HIGH",
                    "artifact_type": "source" if path.suffix else "executable_script",
                    "source": "source_parser",
                })
    return output


CPP_CALL = re.compile(r"(?<![.#])\b([A-Za-z_]\w*(?:::[A-Za-z_]\w*)*)\s*\(")
CPP_FUNCTION = re.compile(
    r"(?:^|[;{}])\s*(?:template\s*<[^;{}]+>\s*)?(?:[A-Za-z_]\w*(?:::[A-Za-z_]\w*)*[\s*&<>:,]+)+"
    r"(?P<name>[A-Za-z_]\w*(?:::[A-Za-z_]\w*)*)\s*\([^;{}]*\)\s*(?:const\s*)?(?:noexcept\s*)?\{"
)
CPP_SKIP_CALLS = {
    "if", "for", "while", "switch", "return", "sizeof", "alignof", "decltype",
    "static_cast", "dynamic_cast", "reinterpret_cast", "const_cast", "catch", "new", "delete",
}


def _cpp_macros(text: str, compile_context: dict | None) -> dict[str, dict]:
    macros: dict[str, dict] = {}
    for name, value in (compile_context or {}).get("definitions", {}).items():
        macros[name] = {"parameters": [], "body": str(value), "source": "compile_commands", "function_like": False}
    pattern = re.compile(r"^\s*#\s*define\s+([A-Za-z_]\w*)(?:\(([^)]*)\))?\s*(.*)$")
    for number, line in enumerate(text.splitlines(), 1):
        match = pattern.match(line)
        if not match:
            continue
        parameters = [item.strip() for item in (match.group(2) or "").split(",") if item.strip()]
        macros[match.group(1)] = {
            "parameters": parameters, "body": match.group(3).strip(), "source": "source", "line": number,
            "function_like": match.group(2) is not None,
        }
    return macros


def _split_cpp_arguments(value: str) -> list[str]:
    output: list[str] = []
    start = 0
    depth = 0
    quote = ""
    escaped = False
    for index, character in enumerate(value):
        if quote:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = ""
            continue
        if character in {'"', "'"}:
            quote = character
        elif character in "([{":
            depth += 1
        elif character in ")]}":
            depth = max(0, depth - 1)
        elif character == "," and depth == 0:
            output.append(value[start:index].strip())
            start = index + 1
    output.append(value[start:].strip())
    return output


def _replace_function_macro(text: str, name: str, parameters: list[str], body: str) -> tuple[str, int]:
    pattern = re.compile(rf"\b{re.escape(name)}\s*\(")
    output: list[str] = []
    cursor = 0
    replacements = 0
    while True:
        match = pattern.search(text, cursor)
        if not match:
            output.append(text[cursor:])
            break
        opening = text.find("(", match.start())
        depth = 1
        quote = ""
        escaped = False
        closing = -1
        for index in range(opening + 1, len(text)):
            character = text[index]
            if quote:
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
                elif character == quote:
                    quote = ""
                continue
            if character in {'"', "'"}:
                quote = character
            elif character == "(":
                depth += 1
            elif character == ")":
                depth -= 1
                if depth == 0:
                    closing = index
                    break
        if closing < 0:
            output.append(text[cursor:])
            break
        arguments = _split_cpp_arguments(text[opening + 1:closing])
        if not parameters and arguments == [""]:
            arguments = []
        if len(arguments) != len(parameters):
            output.append(text[cursor:closing + 1])
            cursor = closing + 1
            continue
        replacement = body
        # Token stringification/pasting is intentionally left to Clang.  The
        # bounded fallback still handles arbitrarily nested ordinary arguments.
        if "##" in replacement or re.search(r"(^|[^#])#\s*[A-Za-z_]", replacement):
            output.append(text[cursor:closing + 1])
            cursor = closing + 1
            continue
        for parameter, argument in zip(parameters, arguments):
            replacement = re.sub(rf"\b{re.escape(parameter)}\b", argument, replacement)
        output.append(text[cursor:match.start()])
        output.append(replacement)
        replacements += 1
        cursor = closing + 1
    return "".join(output), replacements


def _macro_expand(line: str, macros: dict[str, dict]) -> tuple[str, list[str]]:
    """Bounded expansion for nested object/function-like macro aliases."""
    expanded = line
    used: list[str] = []
    for _ in range(32):
        changed = False
        for name, spec in macros.items():
            body = str(spec.get("body", ""))
            parameters = list(spec.get("parameters", []))
            if not body:
                continue
            if not spec.get("function_like"):
                candidate, count = re.subn(rf"\b{re.escape(name)}\b", body, expanded)
            else:
                candidate, count = _replace_function_macro(expanded, name, parameters, body)
            if count:
                if len(candidate) > 200_000:
                    return expanded, sorted(set(used))
                expanded = candidate
                used.append(name)
                changed = True
        if not changed:
            break
    return expanded, sorted(set(used))


def _scan_cpp_dynamic_resolution(path: Path, text: str) -> list[dict]:
    output: list[dict] = []
    symbol_pattern = re.compile(
        r"\b(?P<loader>dlsym|GetProcAddress|QMetaObject::invokeMethod)\s*\([^,]+,\s*(?:Q_ARG\s*\([^,]+,\s*)?[\"'](?P<symbol>[A-Za-z_][A-Za-z0-9_:]*)[\"']",
    )
    library_pattern = re.compile(r"\b(?P<loader>dlopen|dlmopen|LoadLibrary[AW]?)\s*\(\s*[\"'](?P<library>[^\"']+)[\"']")
    for line_number, line in enumerate(text.splitlines(), 1):
        for match in symbol_pattern.finditer(line):
            symbol = match.group("symbol")
            matches = scan_source_text(path, f"{symbol}();", "cpp")
            for signal in matches:
                signal.update({
                    "line": line_number, "source": "cpp_dynamic_symbol_resolution", "confidence": "HIGH",
                    "evidence_type": "dynamic_symbol_resolution", "excerpt": line.strip()[:500],
                    "metadata": {"loader": match.group("loader"), "resolved_symbol": symbol},
                })
                output.append(signal)
        for match in library_pattern.finditer(line):
            library = match.group("library")
            if not CRYPTO_LIBRARY.search("/" + library):
                continue
            output.append({
                "line": line_number, "evidence_type": "dynamic_crypto_library", "algorithm": "runtime-selected",
                "excerpt": line.strip()[:500], "language": "cpp", "method": library,
                "library": library, "confidence": "HIGH", "artifact_type": "source",
                "source": "cpp_dynamic_library_resolution",
                "metadata": {"loader": match.group("loader"), "library_path": library},
            })
    return output


def scan_cpp_source(path: Path, text: str, compile_context: dict | None = None, *,
                    semantic_mode: str = "auto", clang_binary: str = "clang++",
                    clang_timeout: int = 20, max_clang_ast_bytes: int = 32_000_000) -> tuple[list[dict], dict]:
    """Combine fast heuristics with optional bounded Clang AST semantics."""
    macros = _cpp_macros(text, compile_context)
    signals: list[dict] = []
    edges: list[dict] = []
    direct_crypto: dict[str, list[dict]] = {}
    current = "<global>"
    depth = 0
    seen_signals: set[tuple[int, str, str]] = set()
    for line_number, line in enumerate(text.splitlines(), 1):
        definition = CPP_FUNCTION.search(line)
        if definition:
            current = definition.group("name")
            depth = 0
        expanded, used_macros = _macro_expand(line, macros)
        variants = [(line, "source_parser", [])]
        if expanded != line:
            variants.append((expanded, "cpp_macro_expansion", used_macros))
        for variant, source, macro_names in variants:
            for signal in scan_source_text(path, variant, "cpp"):
                signal["line"] = line_number
                signal["source"] = source
                signal["confidence"] = "HIGH" if source == "source_parser" else "MEDIUM"
                signal["metadata"] = {
                    "caller": current,
                    "macros": macro_names,
                    "original_line": line.strip()[:500] if source == "cpp_macro_expansion" else "",
                    "expanded_line": variant.strip()[:500] if source == "cpp_macro_expansion" else "",
                }
                key = (line_number, signal["method"], source)
                if key not in seen_signals:
                    seen_signals.add(key)
                    signals.append(signal)
                    direct_crypto.setdefault(current, []).append(signal)
        for match in CPP_CALL.finditer(expanded):
            callee = match.group(1)
            if callee in CPP_SKIP_CALLS or (definition and callee == definition.group("name")):
                continue
            edges.append({"caller": current, "callee": callee, "line": line_number})
        depth += line.count("{") - line.count("}")
        if current != "<global>" and depth <= 0:
            current = "<global>"
            depth = 0

    # Propagate a crypto marker one level through local wrappers. This is an
    # explicitly heuristic edge, not proof that the wrapper executes at runtime.
    known_crypto = set(direct_crypto)
    for _ in range(8):
        newly_known = {edge["caller"] for edge in edges if edge["callee"] in known_crypto and edge["caller"] not in known_crypto}
        if not newly_known:
            break
        known_crypto.update(newly_known)
    for edge in edges:
        if edge["callee"] not in known_crypto or edge["caller"] in direct_crypto:
            continue
        signals.append({
            "line": edge["line"], "evidence_type": "cpp_call_graph", "algorithm": "runtime-selected",
            "excerpt": f"call graph: {edge['caller']} -> {edge['callee']}", "language": "cpp",
            "method": f"{edge['caller']} -> {edge['callee']}", "library": "transitive-wrapper",
            "confidence": "MEDIUM", "artifact_type": "source", "source": "cpp_call_graph",
            "metadata": {"caller": edge["caller"], "callee": edge["callee"], "heuristic": True},
        })
    signals.extend(_scan_cpp_dynamic_resolution(path, text))

    semantic_metadata: dict = {"status": "disabled"}
    should_analyze = semantic_mode == "on" or (semantic_mode == "auto" and compile_context is not None)
    if should_analyze:
        semantic_signals, semantic_metadata = analyze_cpp_source(
            path, compile_context, clang_binary=clang_binary,
            timeout=clang_timeout, max_ast_bytes=max_clang_ast_bytes,
        )
        semantic_seen = {(int(item.get("line", 0)), item.get("method", ""), item.get("source", "")) for item in signals}
        for signal in semantic_signals:
            key = (int(signal.get("line", 0)), signal.get("method", ""), signal.get("source", ""))
            if key not in semantic_seen:
                semantic_seen.add(key)
                signals.append(signal)

    semantic_status = semantic_metadata.get("status", "disabled")
    if semantic_status in {"succeeded", "partial"}:
        analysis_limits = [
            "runtime_dependent_indirect_targets", "cross_dso_dynamic_targets",
            "packed_binary_requires_runtime_observation", "compile_command_not_executed",
        ]
    else:
        analysis_limits = [
            "bounded_macro_expansion", "heuristic_call_graph", "semantic_analysis_unavailable",
            "compile_command_not_executed",
        ]
    metadata = {
        "compile_commands": _public_compile_context(compile_context),
        "macro_count": len(macros),
        "macro_names": sorted(macros)[:1000],
        "call_graph": edges[:10_000],
        "cpp_semantic": semantic_metadata,
        "analysis_limits": analysis_limits,
    }
    return signals, metadata


def _printable_strings(raw: bytes, minimum: int = 5, limit: int = 30_000) -> list[str]:
    strings = [match.group(0).decode("utf-8", "replace") for match in re.finditer(rb"[\x20-\x7e]{%d,}" % minimum, raw)]
    # Windows and Java artifacts sometimes contain useful UTF-16LE constants.
    wide = []
    for match in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % minimum, raw):
        wide.append(match.group(0).decode("utf-16le", "replace"))
    return (strings + wide)[:limit]


def _file_format(path: Path, raw: bytes) -> str:
    if raw.startswith(b"\x7fELF"):
        return "ELF"
    if raw.startswith(b"MZ"):
        return "PE"
    if raw.startswith(b"\xca\xfe\xba\xbe") and path.suffix.lower() == ".class":
        return "JavaClass"
    if raw.startswith((b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe")):
        return "Mach-O"
    if raw.startswith(b"!<arch>\n"):
        return "static_archive"
    if raw.startswith(b"\x00asm"):
        return "WebAssembly"
    if raw.startswith(b"PK\x03\x04"):
        return "JAR" if path.suffix.lower() in {".jar", ".war", ".ear"} else "ZIP"
    if raw.startswith(b"#!"):
        return "script"
    return "binary"


def _demangle_symbols(symbols: list[str]) -> tuple[list[str], bool]:
    candidates = [item for item in symbols[:50_000] if item]
    if not candidates:
        return [], False
    try:
        process = subprocess.run(
            ["c++filt"], input=("\n".join(candidates) + "\n").encode(),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=8, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return [], False
    if process.returncode != 0:
        return [], False
    output = process.stdout.decode("utf-8", "replace").splitlines()
    return sorted({item for raw, item in zip(candidates, output) if item and item != raw}), True


def _relevant_symbol(name: str) -> bool:
    return any(item.pattern.search(name) for item in BINARY_RULES)


def _elf_metadata(path: Path) -> tuple[list[str], list[str], list[str], dict, list[str]]:
    dependencies: set[str] = set()
    raw_symbols: set[str] = set()
    tools: list[str] = []
    metadata: dict = {}
    rc, dynamic = _run_tool(["readelf", "-d", "--", str(path)])
    if rc == 0:
        tools.append("readelf-dynamic")
        dependencies.update(re.findall(r"Shared library: \[([^\]]+)\]", dynamic))
    rc, symbol_text = _run_tool(["readelf", "-Ws", "--", str(path)])
    if rc == 0:
        tools.append("readelf-symbols")
        for line in symbol_text.splitlines()[:100_000]:
            name = line.split()[-1] if line.split() else ""
            if name and name not in {"Name", "UND"}:
                raw_symbols.add(name.split("@", 1)[0])
    if not raw_symbols:
        rc, symbol_text = _run_tool(["nm", "-D", "--", str(path)])
        if rc == 0:
            tools.append("nm-dynamic")
            for line in symbol_text.splitlines()[:100_000]:
                name = line.split()[-1] if line.split() else ""
                if name:
                    raw_symbols.add(name.split("@", 1)[0])
    rc, section_text = _run_tool(["readelf", "-SW", "--", str(path)])
    if rc == 0:
        tools.append("readelf-sections")
        section_names = sorted(set(re.findall(r"\[\s*\d+\]\s+(\S+)", section_text)))
        metadata.update({
            "section_names": section_names[:500],
            "has_symbol_table": ".symtab" in section_names,
            "has_dynamic_symbols": ".dynsym" in section_names,
            "stripped": ".symtab" not in section_names,
        })
    demangled, used = _demangle_symbols(sorted(raw_symbols))
    if used:
        tools.append("c++filt")
    relevant_raw = sorted(name for name in raw_symbols if _relevant_symbol(name))
    relevant_demangled = sorted(name for name in demangled if _relevant_symbol(name))
    return sorted(dependencies), relevant_raw, relevant_demangled, metadata, tools


def _archive_metadata(path: Path) -> tuple[list[str], list[str], dict, list[str]]:
    members: list[str] = []
    tools: list[str] = []
    rc, listing = _run_tool(["ar", "t", "--", str(path)])
    if rc == 0:
        tools.append("ar-members")
        members = [line.strip() for line in listing.splitlines() if line.strip()][:20_000]
    rc, symbols_text = _run_tool(["nm", "-A", "--", str(path)])
    raw_symbols: set[str] = set()
    if rc == 0:
        tools.append("nm-archive")
        for line in symbols_text.splitlines()[:100_000]:
            name = line.split()[-1] if line.split() else ""
            if name:
                raw_symbols.add(name.split("@", 1)[0])
    demangled, used = _demangle_symbols(sorted(raw_symbols))
    if used:
        tools.append("c++filt")
    relevant_raw = sorted(name for name in raw_symbols if _relevant_symbol(name))
    relevant_demangled = sorted(name for name in demangled if _relevant_symbol(name))
    return relevant_raw, relevant_demangled, {"archive_members": members, "archive_member_count": len(members)}, tools


def _pe_metadata(path: Path) -> tuple[list[str], list[str], list[str]]:
    dependencies: set[str] = set()
    symbols: set[str] = set()
    rc, text = _run_tool(["objdump", "-p", "--", str(path)])
    if rc != 0:
        return [], [], []
    dependencies.update(re.findall(r"DLL Name:\s*(\S+)", text, re.I))
    for match in re.finditer(r"\b((?:BCrypt[A-Z]|NCrypt[A-Z]|Crypt(?:Acquire|Release|Encrypt|Decrypt|Gen|Import|Export|Protect|Unprotect|Sign|Verify|Hash|Derive|Get|Set|Duplicate|Enum|Find|Msg|Query|Decode|Encode))[A-Za-z0-9_]*)\b", text):
        symbols.add(match.group(1))
    return sorted(dependencies), sorted(symbols), ["objdump-pe"]


def _zip_strings(path: Path, max_member_bytes: int = 4_000_000, max_members: int = 10_000, max_total_bytes: int = 32_000_000) -> tuple[list[str], dict]:
    strings: list[str] = []
    members = 0
    class_files = 0
    truncated = False
    total_bytes = 0
    try:
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist():
                if members >= max_members:
                    truncated = True
                    break
                members += 1
                if info.filename.endswith(".class"):
                    class_files += 1
                strings.append(info.filename)
                if info.is_dir() or info.file_size > max_member_bytes:
                    continue
                if total_bytes + info.file_size > max_total_bytes:
                    truncated = True
                    break
                total_bytes += info.file_size
                try:
                    data = archive.read(info)
                except (OSError, RuntimeError, zipfile.BadZipFile):
                    continue
                strings.extend(_printable_strings(data, limit=4_000))
    except (OSError, zipfile.BadZipFile):
        return [], {"members": 0, "class_files": 0, "invalid_archive": True}
    return strings[:30_000], {"members": members, "class_files": class_files, "inspected_uncompressed_bytes": total_bytes, "truncated": truncated}


def _infer_binary_languages(strings: list[str], file_format: str) -> list[str]:
    blob = "\n".join(strings)
    languages: set[str] = set()
    if file_format in {"JAR", "JavaClass"} or re.search(r"java/(?:lang|security)|javax/(?:crypto|net/ssl)", blob):
        languages.add("java")
    if re.search(r"Go build ID|runtime\.main|crypto/(?:tls|x509|rsa)", blob):
        languages.add("go")
    if re.search(r"rust_eh_personality|rustls::|core::panicking|ring::signature", blob):
        languages.add("rust")
    if re.search(r"PyInstaller|Py_Initialize|cryptography\.hazmat|ssl\.SSLContext", blob):
        languages.add("python")
    if re.search(r"SSL_CTX_|EVP_|std::__cxx11|CryptoPP::|Botan::|wolfSSL_|libstdc\+\+|__cxa_", blob):
        languages.add("cpp")
    if not languages:
        languages.add("native" if file_format in {"ELF", "PE", "Mach-O", "static_archive"} else "unknown")
    return sorted(languages)


def _binary_protection_metadata(raw: bytes, metadata: dict) -> dict:
    marker_names = []
    known_markers = {
        b"UPX!": "UPX", b"MPRESS": "MPRESS", b"Themida": "Themida",
        b"VMProtect": "VMProtect", b"ASPack": "ASPack",
    }
    for marker, name in known_markers.items():
        if marker in raw:
            marker_names.append(name)
    section_names = [str(item).lower() for item in metadata.get("section_names", [])]
    suspicious_sections = [
        item for item in section_names
        if item.startswith((".upx", ".vmp", ".packed", ".aspack")) or item in {".petite", ".mpress1", ".mpress2"}
    ]
    packed = bool(marker_names or suspicious_sections)
    stripped = bool(metadata.get("stripped"))
    return {
        "packed_or_protected": packed,
        "packer_markers": sorted(set(marker_names)),
        "suspicious_sections": suspicious_sections[:100],
        "analysis_completeness": "opaque" if packed else "reduced" if stripped else "normal",
    }


def inspect_file(path: Path, max_text_bytes: int, max_binary_bytes: int, max_evidence: int = 2_000,
                 cpp_compile_context: dict | None = None, *, cpp_semantic_mode: str = "auto",
                 clang_binary: str = "clang++", clang_timeout: int = 20,
                 max_clang_ast_bytes: int = 32_000_000) -> tuple[Artifact | None, list[dict], dict]:
    """Inspect one file and return a crypto-relevant artifact plus signals.

    The statistics dictionary is returned even when no cryptographic signal was
    found, allowing the caller to report what it actually inspected.
    """
    try:
        info = path.stat()
        if info.st_size > max_binary_bytes:
            return None, [], {"skipped": "file_too_large"}
        with path.open("rb") as handle:
            raw = handle.read(max_binary_bytes + 1)
        if len(raw) > max_binary_bytes:
            return None, [], {"skipped": "file_grew_too_large"}
    except OSError as exc:
        return None, [], {"skipped": type(exc).__name__}
    digest = hashlib.sha256(raw).hexdigest()
    executable = bool(info.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
    language = _language(path, raw)
    is_text = b"\x00" not in raw[:4096]
    is_source = bool(language) or path.suffix.lower() in CONFIG_EXTENSIONS
    if is_source and is_text and len(raw) <= max_text_bytes:
        text = raw.decode("utf-8", "replace")
        source_language = language or "config"
        cpp_metadata: dict = {}
        if source_language == "cpp":
            signals, cpp_metadata = scan_cpp_source(
                path, text, cpp_compile_context, semantic_mode=cpp_semantic_mode,
                clang_binary=clang_binary, clang_timeout=clang_timeout,
                max_clang_ast_bytes=max_clang_ast_bytes,
            )
            signals = signals[:max_evidence]
        else:
            signals = scan_source_text(path, text, source_language)[:max_evidence]
        if not signals:
            return None, [], {
                "kind": "source", "language": source_language,
                "cpp_semantic": cpp_metadata.get("cpp_semantic", {}).get("status", "not_applicable") if source_language == "cpp" else "not_applicable",
            }
        kind = "executable_script" if raw.startswith(b"#!") and executable else "source"
        artifact = Artifact(
            artifact_id=stable_id("artifact", digest, path.resolve()), path=str(path.resolve()),
            artifact_type=kind, file_format="text", sha256=digest, size=info.st_size,
            executable=executable, languages=[source_language], confidence="HIGH",
            metadata={"inspection": ["bounded_text_parser"] + (["compile_commands", "macro_expansion", "cpp_call_graph", "clang_ast_optional"] if source_language == "cpp" else []), **cpp_metadata},
        )
        for signal in signals:
            signal["artifact_type"] = kind
        return artifact, signals, {
            "kind": "source", "language": source_language,
            "cpp_semantic": cpp_metadata.get("cpp_semantic", {}).get("status", "not_applicable") if source_language == "cpp" else "not_applicable",
        }

    file_format = _file_format(path, raw)
    if file_format == "binary" and not executable:
        return None, [], {"kind": "ignored"}
    dependencies: list[str] = []
    imported_symbols: list[str] = []
    demangled_symbols: list[str] = []
    inspection = ["bounded_printable_strings"]
    metadata: dict = {}
    if file_format == "ELF":
        dependencies, imported_symbols, demangled_symbols, metadata, tools = _elf_metadata(path)
        inspection.extend(tools)
        strings = _printable_strings(raw)
    elif file_format == "PE":
        dependencies, imported_symbols, tools = _pe_metadata(path)
        inspection.extend(tools)
        strings = _printable_strings(raw)
    elif file_format in {"JAR", "ZIP"}:
        strings, metadata = _zip_strings(path)
        if metadata.get("class_files"):
            file_format = "JAR"
        inspection.append("zip_constant_pool_strings")
    elif file_format == "static_archive":
        imported_symbols, demangled_symbols, metadata, tools = _archive_metadata(path)
        inspection.extend(tools)
        strings = _printable_strings(raw)
    else:
        strings = _printable_strings(raw)
    metadata.update(_binary_protection_metadata(raw, metadata))
    mangled_markers = sorted(set(re.findall(r"\b_Z[A-Za-z0-9_$.]+", "\n".join(strings))))[:50_000]
    marker_demangled, marker_tool = _demangle_symbols(mangled_markers)
    if marker_tool and marker_demangled:
        inspection.append("c++filt-printable-symbols")
        demangled_symbols = sorted(set(demangled_symbols) | set(marker_demangled))
    strings.extend(dependencies)
    strings.extend(imported_symbols)
    strings.extend(demangled_symbols)
    languages = _infer_binary_languages(strings, file_format)
    blob = "\n".join(strings)
    symbol_names = set(imported_symbols) | set(demangled_symbols)
    signals: list[dict] = []
    seen: set[tuple[str, str, str]] = set()
    for item in BINARY_RULES:
        for match in item.pattern.finditer(blob):
            method = (match.groupdict().get("method") or match.group(0))[:240]
            key = (item.library, item.algorithm, method)
            if key in seen:
                continue
            seen.add(key)
            source = "symbol_table" if method in symbol_names else "class_constants" if file_format in {"JAR", "JavaClass"} else "printable_strings"
            confidence = "HIGH" if source in {"symbol_table", "class_constants"} else "MEDIUM"
            signals.append({
                "line": 0, "evidence_type": item.evidence_type, "algorithm": item.algorithm,
                "excerpt": f"{source}: {method}", "language": item.language,
                "method": method, "library": item.library, "confidence": confidence,
                "artifact_type": "java_archive" if file_format == "JAR" else "java_class" if file_format == "JavaClass" else "native_executable",
                "source": source,
            })
            if len(signals) >= max_evidence:
                break
        if len(signals) >= max_evidence:
            break
    for dependency in dependencies:
        if len(signals) >= max_evidence:
            break
        if CRYPTO_LIBRARY.search("/" + dependency):
            key = ("dependency", dependency, "")
            if key not in seen:
                seen.add(key)
                signals.append({
                    "line": 0, "evidence_type": "binary_dependency", "algorithm": "runtime-selected",
                    "excerpt": f"dynamic dependency: {dependency}", "language": languages[0],
                    "method": dependency, "library": dependency, "confidence": "HIGH",
                    "artifact_type": "native_executable", "source": "dynamic_section",
                })
    resolvers = sorted(set(re.findall(r"\b(?:dlopen|dlmopen|dlsym|LoadLibrary[AW]?|GetProcAddress)\b", blob)))
    if resolvers:
        crypto_strings = [
            item for item in signals
            if item.get("library") not in {"dynamic-loader", "POSIX dynamic loader", "Windows dynamic loader"}
            and item.get("source") == "printable_strings"
        ]
        for item in crypto_strings[:100]:
            key = ("dynamic-resolution", item["method"], resolvers[0])
            if key in seen or len(signals) >= max_evidence:
                continue
            seen.add(key)
            signals.append({
                **item,
                "evidence_type": "dynamic_symbol_resolution",
                "excerpt": f"dynamic resolver {resolvers[0]} co-occurs with crypto symbol {item['method']}",
                "confidence": "MEDIUM", "source": "binary_dynamic_resolution",
                "metadata": {"resolvers": resolvers, "resolved_symbol_candidate": item["method"]},
            })

    opaque = bool(metadata.get("packed_or_protected"))
    stripped_unresolved = (
        bool(metadata.get("stripped")) and not imported_symbols and not demangled_symbols
        and not any(CRYPTO_LIBRARY.search("/" + item) for item in dependencies)
    )
    if opaque or stripped_unresolved:
        method = "packed-or-protected-binary" if opaque else "fully-stripped-binary"
        signals.append({
            "line": 0, "evidence_type": "binary_analysis_gap", "algorithm": "unknown",
            "excerpt": f"static analysis is incomplete for {method}; correlate with process maps or eBPF",
            "language": languages[0], "method": method, "library": "binary-analysis",
            "confidence": "LOW", "artifact_type": "native_executable",
            "source": "binary_protection_analysis",
            "metadata": {
                "packed_or_protected": opaque, "stripped": bool(metadata.get("stripped")),
                "requires_runtime_observation": True,
            },
        })
    if not signals:
        return None, [], {"kind": "binary", "format": file_format}
    artifact_type = "java_archive" if file_format == "JAR" else "java_class" if file_format == "JavaClass" else "native_executable" if executable or file_format in {"ELF", "PE", "Mach-O"} else "binary_archive"
    artifact = Artifact(
        artifact_id=stable_id("artifact", digest, path.resolve()), path=str(path.resolve()),
        artifact_type=artifact_type, file_format=file_format, sha256=digest, size=info.st_size,
        executable=executable, languages=languages, dependencies=dependencies[:500],
        imported_symbols=imported_symbols[:500], demangled_symbols=demangled_symbols[:500],
        confidence="HIGH" if imported_symbols or demangled_symbols or file_format == "JAR" else "MEDIUM",
        metadata={"inspection": inspection, **metadata},
    )
    for signal in signals:
        signal["artifact_type"] = artifact_type
    return artifact, signals, {"kind": "binary", "format": file_format, "languages": languages}


def _redact_command(command: str) -> str:
    command = re.sub(r"(?i)(--?(?:password|passwd|token|secret|api[-_]?key|credential)(?:=|\s+))\S+", r"\1<redacted>", command)
    return command[:1000]


def scan_processes(proc_root: Path, max_processes: int = 20_000, include_command_lines: bool = False) -> tuple[list[RuntimeProcess], list[dict], dict]:
    processes: list[RuntimeProcess] = []
    signals: list[dict] = []
    inspected = 0
    denied = 0
    try:
        candidates = sorted((p for p in proc_root.iterdir() if p.name.isdigit()), key=lambda p: int(p.name))
    except OSError:
        return [], [], {"inspected": 0, "denied": 1, "crypto_processes": 0}
    for process_dir in candidates[:max_processes]:
        inspected += 1
        try:
            maps_text = (process_dir / "maps").read_text(encoding="utf-8", errors="replace")
        except OSError:
            denied += 1
            continue
        libraries = sorted({
            match.group(0).lstrip("/") for line in maps_text.splitlines()
            for match in CRYPTO_LIBRARY.finditer(line)
        })
        if not libraries:
            continue
        try:
            executable = os.readlink(process_dir / "exe")
        except OSError:
            executable = ""
        command = ""
        if include_command_lines:
            try:
                command = _redact_command((process_dir / "cmdline").read_bytes().replace(b"\x00", b" ").decode("utf-8", "replace").strip())
            except OSError:
                command = ""
        pid = int(process_dir.name)
        record = RuntimeProcess(
            process_id=stable_id("process", pid, executable, command), pid=pid,
            executable=executable, command=command, mapped_crypto_libraries=libraries,
            metadata={"evidence_path": str((process_dir / "maps").resolve()), "command_line_collected": include_command_lines},
        )
        processes.append(record)
        for library in libraries:
            signals.append({
                "path": str((process_dir / "maps").resolve()), "line": 0,
                "evidence_type": "runtime_mapped_library", "algorithm": "runtime-selected",
                "excerpt": f"pid={pid} maps {library}", "language": "runtime",
                "method": library, "library": library, "confidence": "HIGH",
                "artifact_type": "runtime_process", "source": "proc_maps",
                "metadata": {"pid": pid, "process_id": record.process_id, "executable": executable},
            })
    return processes, signals, {"inspected": inspected, "denied": denied, "crypto_processes": len(processes)}


def artifact_dict(artifact: Artifact) -> dict:
    return asdict(artifact)


def process_dict(process: RuntimeProcess) -> dict:
    return asdict(process)
