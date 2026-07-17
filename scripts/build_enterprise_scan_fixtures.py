#!/usr/bin/env python3
"""Build deterministic multi-language enterprise scanner experiment fixtures."""
from __future__ import annotations

import argparse
import json
import os
import shutil
import struct
import subprocess
import zipfile
from pathlib import Path


SOURCES = {
    "service.cpp": """#include <openssl/ssl.h>
#define CREATE_TLS(method) SSL_CTX_new(method)
void *configure_tls() {
    SSL_CTX *ctx = CREATE_TLS(TLS_client_method());
    EVP_PKEY_encrypt(nullptr, nullptr, nullptr, nullptr, 0);
    RSA_public_encrypt(0, nullptr, nullptr, nullptr, 0);
    return ctx;
}
void *migration_wrapper() { return configure_tls(); }
""",
    "CryptoService.java": """import javax.crypto.Cipher;
import javax.net.ssl.SSLContext;
class CryptoService {
  void configure() throws Exception {
    Cipher.getInstance("AES/GCM/NoPadding");
    SSLContext.getInstance("TLSv1.3");
  }
}
""",
    "service.rs": """fn configure() {
    let _client = rustls::ClientConfig::builder();
    let _signature = ring::signature::ED25519;
}
""",
    "service.go": """package main
import ("crypto/tls"; "crypto/x509")
func configure() { _ = tls.Config{}; _, _ = x509.SystemCertPool() }
func main() { configure() }
""",
    "service.py": """#!/usr/bin/env python3
import ssl
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
""",
    "service.sh": """#!/usr/bin/env bash
openssl s_client -connect gateway.local:443 -tls1_3 </dev/null
""",
}


def write_sources(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    for name, text in SOURCES.items():
        path = root / name
        path.write_text(text, encoding="utf-8")
        if path.suffix in {".py", ".sh"}:
            path.chmod(0o755)
    (root / "compile_commands.json").write_text(json.dumps([{
        "directory": str(root.resolve()), "file": "service.cpp",
        "arguments": ["g++", "-std=c++20", "-DPQ_SCAN_FIXTURE=1", "-Iinclude", "-c", "service.cpp"],
    }], indent=2) + "\n", encoding="utf-8")


def build_native(root: Path) -> tuple[Path, str]:
    root.mkdir(parents=True, exist_ok=True)
    source = root / "native_probe.cpp"
    source.write_text(
        'extern "C" void *SSL_CTX_new(void) __attribute__((weak));\n'
        'extern "C" int EVP_PKEY_encrypt(void*,void*,unsigned long*,const void*,unsigned long) __attribute__((weak));\n'
        'int main(){ return SSL_CTX_new && EVP_PKEY_encrypt ? 0 : 1; }\n',
        encoding="utf-8",
    )
    target = root / "cpp-service"
    compiler = shutil.which("g++")
    if compiler:
        try:
            subprocess.run([compiler, "-O0", str(source), "-o", str(target)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
            mode = "compiled_elf"
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
            compiler = None
    if not compiler:
        target.write_bytes(b"\x7fELF\x02\x01\x01\x00SSL_CTX_new\x00EVP_PKEY_encrypt\x00")
        mode = "synthetic_elf_markers"
    target.chmod(0o755)
    return target, mode


def build_static_archive(root: Path) -> tuple[Path, str]:
    target = root / "libcpp-crypto.a"
    source = root / "static_crypto.cpp"
    source.write_text(
        'namespace CryptoPP { struct RSA { void Encrypt(); }; void RSA::Encrypt(){} }\n'
        'extern "C" void SSL_CTX_new(); void use_ssl(){ SSL_CTX_new(); }\n',
        encoding="utf-8",
    )
    compiler, archiver = shutil.which("g++"), shutil.which("ar")
    if compiler and archiver:
        obj = root / "static_crypto.o"
        try:
            subprocess.run([compiler, "-c", str(source), "-o", str(obj)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
            subprocess.run([archiver, "rcs", str(target), str(obj)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
            return target, "compiled_static_archive"
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass
    target.write_bytes(b"!<arch>\n_ZN8CryptoPP3RSA7EncryptEv\x00SSL_CTX_new\x00")
    return target, "static_archive_marker_fallback"


def copy_marker_elf(base: Path, target: Path, markers: bytes) -> None:
    shutil.copyfile(base, target)
    with target.open("ab") as handle:
        handle.write(b"\x00" + markers + b"\x00")
    target.chmod(0o755)


def valid_minimal_java_class() -> bytes:
    """Return a valid class with a main method and crypto constant references."""
    entries = [
        (1, b"CryptoService"), (7, 1), (1, b"java/lang/Object"), (7, 3),
        (1, b"<init>"), (1, b"()V"), (1, b"Code"), (12, (5, 6)), (10, (4, 8)),
        (1, b"main"), (1, b"([Ljava/lang/String;)V"),
        (1, b"javax/net/ssl/SSLContext"), (1, b"javax/crypto/Cipher"),
        (1, b"java/security/Signature"),
        (1, b"org/bouncycastle/jce/provider/BouncyCastleProvider"),
    ]
    pool = bytearray()
    for tag, value in entries:
        pool.append(tag)
        if tag == 1:
            pool.extend(struct.pack(">H", len(value)))
            pool.extend(value)
        elif tag == 7:
            pool.extend(struct.pack(">H", value))
        elif tag in {10, 12}:
            pool.extend(struct.pack(">HH", *value))
    header = b"\xca\xfe\xba\xbe" + struct.pack(">HHH", 0, 61, len(entries) + 1) + pool
    body = struct.pack(">HHHHHH", 0x0021, 2, 4, 0, 0, 2)
    constructor_code = struct.pack(">HHI", 1, 1, 5) + b"\x2a\xb7\x00\x09\xb1" + struct.pack(">HH", 0, 0)
    constructor = struct.pack(">HHHHH", 0x0001, 5, 6, 1, 7) + struct.pack(">I", len(constructor_code)) + constructor_code
    main_code = struct.pack(">HHI", 0, 1, 1) + b"\xb1" + struct.pack(">HH", 0, 0)
    main = struct.pack(">HHHHH", 0x0009, 10, 11, 1, 7) + struct.pack(">I", len(main_code)) + main_code
    return header + body + constructor + main + struct.pack(">H", 0)


def build_jar(path: Path, work: Path) -> str:
    class_bytes = valid_minimal_java_class()
    compiler = shutil.which("javac")
    if compiler:
        source = work / "CryptoService.java"
        source.write_text(
            "import javax.crypto.Cipher; import javax.net.ssl.SSLContext; "
            "public class CryptoService { public static void main(String[] a) throws Exception { "
            "Cipher.getInstance(\"AES/GCM/NoPadding\"); SSLContext.getInstance(\"TLSv1.3\"); } }\n",
            encoding="utf-8",
        )
        try:
            subprocess.run([compiler, "-d", str(work), str(source)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
            class_bytes = (work / "CryptoService.class").read_bytes()
            mode = "compiled_java_class"
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
            compiler = None
    if not compiler:
        mode = "generated_valid_java_class"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\nMain-Class: CryptoService\n")
        archive.writestr("CryptoService.class", class_bytes)
    return mode


def build_go_binary(root: Path, base: Path) -> str:
    target = root / "go-service"
    compiler = shutil.which("go")
    if compiler:
        source = root / "go_binary.go"
        source.write_text(
            'package main\nimport ("crypto/tls"; "crypto/x509"; "fmt")\n'
            'var marker = "crypto/tls.(*Config)"\n'
            'func main(){ c := &tls.Config{MinVersion: tls.VersionTLS13}; fmt.Print(len(marker), c.MinVersion, x509.NewCertPool()) }\n',
            encoding="utf-8",
        )
        try:
            subprocess.run([compiler, "build", "-o", str(target), str(source)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
            return "compiled_go_elf"
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass
    copy_marker_elf(base, target, b"Go build ID runtime.main crypto/tls.(*Config) crypto/x509.ParseCertificate")
    return "marker_elf_fallback"


def build_rust_binary(root: Path, base: Path) -> str:
    target = root / "rust-service"
    compiler = shutil.which("rustc")
    if compiler:
        source = root / "rust_binary.rs"
        source.write_text(
            'static MARKERS: &str = "rustls::ClientConfig ring::signature::verify";\n'
            'fn main(){ std::hint::black_box(MARKERS); }\n',
            encoding="utf-8",
        )
        try:
            subprocess.run([compiler, "-C", "opt-level=0", str(source), "-o", str(target)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
            return "compiled_rust_elf_with_api_markers"
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass
    copy_marker_elf(base, target, b"rust_eh_personality rustls::ClientConfig ring::signature::verify")
    return "marker_elf_fallback"


def build_executable_scripts(root: Path, execution_marker: Path) -> None:
    python_program = root / "python-service"
    python_program.write_text("#!/usr/bin/env python3\nimport ssl\nssl.create_default_context()\n", encoding="utf-8")
    python_program.chmod(0o755)
    shell_program = root / "shell-service"
    shell_program.write_text("#!/usr/bin/env sh\nopenssl x509 -in server.crt -noout\n", encoding="utf-8")
    shell_program.chmod(0o755)
    trap = root / "must-not-run"
    trap.write_text(
        "#!/usr/bin/env sh\n"
        f"touch '{execution_marker}'\n"
        "openssl s_client -connect forbidden.invalid:443\n",
        encoding="utf-8",
    )
    trap.chmod(0o755)


def build_fake_proc(root: Path) -> None:
    process = root / "4242"
    process.mkdir(parents=True, exist_ok=True)
    (process / "maps").write_text(
        "00400000-00452000 r-xp 00000000 08:02 1 /opt/acme/bin/payment-service\n"
        "7f000000-7f010000 r-xp 00000000 08:02 2 /usr/lib/x86_64-linux-gnu/libssl.so.3\n"
        "7f010000-7f020000 r-xp 00000000 08:02 3 /usr/lib/x86_64-linux-gnu/libcrypto.so.3\n",
        encoding="utf-8",
    )
    (process / "cmdline").write_bytes(b"/opt/acme/bin/payment-service\x00--tls\x00")
    try:
        os.symlink("/opt/acme/bin/payment-service", process / "exe")
    except OSError:
        pass


def build(output: Path) -> dict:
    if output.exists():
        shutil.rmtree(output)
    source_root = output / "source"
    binary_root = output / "executables"
    proc_root = output / "proc"
    output.mkdir(parents=True)
    write_sources(source_root)
    native, native_mode = build_native(binary_root)
    static_archive, static_archive_mode = build_static_archive(binary_root)
    go_mode = build_go_binary(binary_root, native)
    rust_mode = build_rust_binary(binary_root, native)
    java_mode = build_jar(binary_root / "java-service.jar", binary_root)
    execution_marker = output / "TARGET_WAS_EXECUTED"
    build_executable_scripts(binary_root, execution_marker)
    build_fake_proc(proc_root)
    ebpf_trace = output / "ebpf-trace.jsonl"
    ebpf_trace.write_text(json.dumps({
        "pid": 4242, "comm": "payment-service", "method": "RSA_public_encrypt",
        "library": "/usr/lib/x86_64-linux-gnu/libcrypto.so.3",
    }) + "\n", encoding="utf-8")
    manifest = {
        "source_root": str(source_root.resolve()),
        "binary_root": str(binary_root.resolve()),
        "proc_root": str(proc_root.resolve()),
        "native_fixture_mode": native_mode,
        "static_archive": str(static_archive.resolve()),
        "static_archive_mode": static_archive_mode,
        "go_fixture_mode": go_mode,
        "rust_fixture_mode": rust_mode,
        "java_fixture_mode": java_mode,
        "execution_marker": str(execution_marker.resolve()),
        "compile_commands": str((source_root / "compile_commands.json").resolve()),
        "ebpf_trace": str(ebpf_trace.resolve()),
        "languages": ["cpp", "java", "rust", "go", "python", "shell"],
    }
    (output / "fixture-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    print(json.dumps(build(Path(args.out)), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
