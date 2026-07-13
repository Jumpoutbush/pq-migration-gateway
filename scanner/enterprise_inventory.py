#!/usr/bin/env python3
"""Enterprise source, executable and runtime crypto discovery primitives.

The scanner never executes a target. Binary inspection is limited to bounded
file reads and read-only metadata tools such as readelf, nm and objdump.
"""
from __future__ import annotations

import hashlib
import os
import re
import stat
import subprocess
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path


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
    rule("cpp", "libsodium", "modern-crypto", r"\b(?P<method>(?:sodium|crypto_(?:box|sign|kx|secretbox|aead|pwhash))_[A-Za-z0-9_]+)\b", "binary_symbol"),
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


def _elf_metadata(path: Path) -> tuple[list[str], list[str], list[str]]:
    dependencies: set[str] = set()
    symbols: set[str] = set()
    tools: list[str] = []
    rc, dynamic = _run_tool(["readelf", "-d", "--", str(path)])
    if rc == 0:
        tools.append("readelf-dynamic")
        dependencies.update(re.findall(r"Shared library: \[([^\]]+)\]", dynamic))
    rc, symbol_text = _run_tool(["readelf", "-Ws", "--", str(path)])
    if rc == 0:
        tools.append("readelf-symbols")
        for line in symbol_text.splitlines():
            name = line.split()[-1] if line.split() else ""
            if any(rule.pattern.search(name) for rule in BINARY_RULES):
                symbols.add(name.split("@", 1)[0])
    if not symbols:
        rc, symbol_text = _run_tool(["nm", "-D", "--", str(path)])
        if rc == 0:
            tools.append("nm-dynamic")
            for line in symbol_text.splitlines():
                name = line.split()[-1] if line.split() else ""
                if any(rule.pattern.search(name) for rule in BINARY_RULES):
                    symbols.add(name.split("@", 1)[0])
    return sorted(dependencies), sorted(symbols), tools


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
    if re.search(r"SSL_CTX_|EVP_|std::__cxx11|CryptoPP::|Botan::|wolfSSL_", blob):
        languages.add("cpp")
    if not languages:
        languages.add("native" if file_format in {"ELF", "PE", "Mach-O", "static_archive"} else "unknown")
    return sorted(languages)


def inspect_file(path: Path, max_text_bytes: int, max_binary_bytes: int, max_evidence: int = 2_000) -> tuple[Artifact | None, list[dict], dict]:
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
        signals = scan_source_text(path, text, source_language)[:max_evidence]
        if not signals:
            return None, [], {"kind": "source", "language": source_language}
        kind = "executable_script" if raw.startswith(b"#!") and executable else "source"
        artifact = Artifact(
            artifact_id=stable_id("artifact", digest, path.resolve()), path=str(path.resolve()),
            artifact_type=kind, file_format="text", sha256=digest, size=info.st_size,
            executable=executable, languages=[source_language], confidence="HIGH",
            metadata={"inspection": ["bounded_text_parser"]},
        )
        for signal in signals:
            signal["artifact_type"] = kind
        return artifact, signals, {"kind": "source", "language": source_language}

    file_format = _file_format(path, raw)
    if file_format == "binary" and not executable:
        return None, [], {"kind": "ignored"}
    dependencies: list[str] = []
    imported_symbols: list[str] = []
    inspection = ["bounded_printable_strings"]
    metadata: dict = {}
    if file_format == "ELF":
        dependencies, imported_symbols, tools = _elf_metadata(path)
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
    else:
        strings = _printable_strings(raw)
    strings.extend(dependencies)
    strings.extend(imported_symbols)
    languages = _infer_binary_languages(strings, file_format)
    blob = "\n".join(strings)
    signals: list[dict] = []
    seen: set[tuple[str, str, str]] = set()
    for item in BINARY_RULES:
        for match in item.pattern.finditer(blob):
            method = (match.groupdict().get("method") or match.group(0))[:240]
            key = (item.library, item.algorithm, method)
            if key in seen:
                continue
            seen.add(key)
            source = "symbol_table" if method in imported_symbols else "class_constants" if file_format in {"JAR", "JavaClass"} else "printable_strings"
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
    if not signals:
        return None, [], {"kind": "binary", "format": file_format}
    artifact_type = "java_archive" if file_format == "JAR" else "java_class" if file_format == "JavaClass" else "native_executable" if executable or file_format in {"ELF", "PE", "Mach-O"} else "binary_archive"
    artifact = Artifact(
        artifact_id=stable_id("artifact", digest, path.resolve()), path=str(path.resolve()),
        artifact_type=artifact_type, file_format=file_format, sha256=digest, size=info.st_size,
        executable=executable, languages=languages, dependencies=dependencies[:500],
        imported_symbols=imported_symbols[:500], confidence="HIGH" if imported_symbols or file_format == "JAR" else "MEDIUM",
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
