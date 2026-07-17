# Enterprise Crypto Discovery (v3.4)

Only scan source trees, hosts, mounted root filesystems and networks for which
authorization has been obtained. The scanner does not execute a target program.

## Discovery layers

| Layer | Input | Evidence produced |
|---|---|---|
| Source and configuration | C/C++, Java, Rust, Go, Python, Shell and common configuration files | Language, library, exact interface/method, algorithm, file and line |
| Executable and package | ELF, PE, Mach-O, static archives, JAR/WAR/EAR, extensionless scripts | File magic, SHA-256, dynamic dependency, imported symbol, bounded strings/class constants |
| Runtime process | Authorized Linux `/proc/<pid>/maps` and `exe` | Process-to-libssl/libcrypto/libsodium/etc. linkage |
| C++ build context | `compile_commands.json` | Compiler, standard, include roots, `-D` definitions and command digest; command is never executed |
| Optional runtime API | Imported trace or explicitly enabled fixed eBPF uprobes | Observed PID, library and crypto interface method |
| Online service | CMDB/batch target/CIDR input | TLS version, certificate, key size, TLS group and fallback capability |

Executable formats are detected by file magic and execute bits, not only by
filename extension. ELF inspection uses `readelf`/`nm` when available and falls
back to bounded printable-string analysis. PE inspection uses `objdump`. JARs
are inspected as bounded ZIP containers; classes are never loaded.

C++ source analysis adds bounded object/function-like macro alias expansion and
a conservative direct-call graph. The call graph is heuristic and is labeled
medium confidence. Compilation database commands are only parsed; potentially
active flags, compiler plugins and build commands are never run. Static archives
use `ar` and `nm`; ELF/archive C++ names are passed through `c++filt` before
interface matching.

## Recognized interfaces

- C/C++: OpenSSL SSL/EVP/RSA/EC, libsodium, Botan, Crypto++, wolfSSL.
- Java: JSSE, JCA/JCE, `Cipher`, `Signature`, `KeyStore`, Bouncy Castle.
- Rust: rustls, ring, Rust OpenSSL, aws-lc-rs, RustCrypto, liboqs/pqcrypto.
- Go: `crypto/tls`, `crypto/x509`, RSA, ECDSA/ECDH, weak hash calls and `x/crypto`.
- Python: `ssl`, cryptography, PyOpenSSL, PyCryptodome, hashlib and requests TLS options.
- Shell: OpenSSL, curl TLS flags, keytool/jarsigner and ssh-keygen invocations.

Each evidence record includes `language`, `library`, `method`, `algorithm`,
`artifact_type`, `source` and `confidence`. Symbol tables, class constants,
source calls and `/proc` maps are high confidence. Binary printable strings are
medium confidence because a string can be present without being executed.

## Commands

Scan the project while retaining the v2-compatible `assets`, `evidence` and
`findings` output fields:

```bash
make inventory
```

Scan common host deployment paths and authorized process maps:

```bash
make enterprise-inventory
```

For an extracted container root filesystem, select explicit roots:

```bash
python3 scripts/crypto_inventory.py \
  --root /mnt/rootfs/usr --root /mnt/rootfs/opt --root /mnt/rootfs/etc \
  --out-json enterprise-crypto-inventory.json \
  --out-csv enterprise-crypto-inventory.csv
```

Process scanning is explicit. It is disabled unless `--scan-processes` is used:

```bash
python3 scripts/crypto_inventory.py \
  --root /opt/apps \
  --scan-processes --proc-root /proc \
  --out-json enterprise-crypto-inventory.json \
  --out-csv enterprise-crypto-inventory.csv
```

Process command lines are not collected by default because they may contain
secrets. `--include-command-lines` enables bounded collection with common
password/token/secret flags redacted.

Import an authorized, previously captured eBPF trace without runtime privileges:

```bash
python3 scripts/crypto_inventory.py \
  --root /opt/apps \
  --ebpf-trace-file /opt/authorized-observations/crypto-api.jsonl \
  --out-json enterprise-crypto-inventory.json \
  --out-csv enterprise-crypto-inventory.csv
```

Live observation requires `bpftrace`, host privileges and explicit
`--enable-ebpf --ebpf-pid --ebpf-library`. It uses a fixed, bounded uprobe
program for known crypto prefixes; callers cannot provide arbitrary eBPF code.

```bash
sudo python3 scripts/crypto_inventory.py \
  --root /opt/apps \
  --enable-ebpf --ebpf-pid 1234 \
  --ebpf-library /usr/lib/x86_64-linux-gnu/libcrypto.so.3 \
  --ebpf-duration 10 \
  --out-json enterprise-crypto-inventory.json \
  --out-csv enterprise-crypto-inventory.csv
```

Safety bounds are configurable with `--max-files`, `--max-text-bytes`,
`--max-binary-bytes`, `--max-evidence-per-file`, `--max-processes` and
repeatable `--exclude`.

## Experiment

```bash
make enterprise-scan-test
cat experiment-results/manual-enterprise-scan/enterprise-scanner-matrix.json
```

The 21-case deterministic matrix covers six source languages, a C++ ELF, Go/Rust ELF
programs and a Java class/JAR compiled by local toolchains when available, safe
format-valid/marker fallbacks when they are not, extensionless Python and Shell
executables, fake authorized process maps, JSON/CSV output and a trap that proves
target programs were not executed. It additionally covers compilation database
metadata, macro expansion, call-graph evidence, static archive symbols, C++ name
demangling and imported eBPF observations. The same matrix runs inside
`run_full_experiment.sh` and is stored under `enterprise-scan/`.

## Interpretation limits

A stripped or statically linked binary may expose only partial evidence. Packed,
encrypted or runtime-generated code may expose none. Therefore a medium-confidence
string hit is not proof that a method executes, and absence of evidence is not
proof that cryptography is absent. Correlate static results with process maps,
online TLS observations, CMDB ownership and application telemetry before making
a migration decision.
