# C++ Semantic Crypto Scanning

This enhancement closes the largest source-analysis gaps in the v3.6 scanner
without executing enterprise programs or trusting arbitrary build commands.

## Analysis pipeline

1. Parse `compile_commands.json` as data.
2. Retain only an allowlist of syntax-relevant flags.
3. Run `clang++ -fsyntax-only -Xclang -ast-dump=json` with per-file time and
   output limits.
4. Parse the AST without loading target compiler plugins.
5. Merge semantic evidence with the existing source, symbol, binary-string,
   process-map and optional eBPF layers.
6. Fall back to the fast scanner when semantic analysis is unavailable.

The allowlist accepts the C++ standard, normalized include paths, target/sysroot
settings, selected architecture settings and non-sensitive macro definitions.
It rejects compiler plugins, `-Xclang`, response files, build/link/output flags
and definitions whose names look like passwords, tokens, secrets or API keys.

## New evidence

| Evidence source | Meaning | Confidence |
|---|---|---|
| `cpp_clang_ast` | Direct crypto declaration referenced by a call | High |
| `cpp_clang_template` | Crypto call found in a template context | High |
| `cpp_clang_macro_expansion` | Crypto call visible after preprocessor expansion | High/medium |
| `cpp_clang_function_pointer` | Indirect call has a statically known crypto-capable target | Medium |
| `cpp_clang_virtual_dispatch` | A virtual call has one or more crypto-capable override candidates | Medium |
| `cpp_clang_call_graph` | Semantic wrapper-to-crypto call path | High/medium |
| `cpp_clang_dynamic_resolution` | A dynamic loader resolves a literal crypto symbol | High/medium |
| `binary_analysis_gap` | A stripped or protected binary requires runtime follow-up | Low |

## API use

```json
{
  "type": "enterprise",
  "roots": ["/workspace/project"],
  "compile_commands": ["/workspace/project/build/compile_commands.json"],
  "cpp_semantic": "auto"
}
```

`auto` analyzes files with compilation-database context. `on` attempts every
C++ source file, while `off` uses only the fast fallback.

CLI equivalent:

```bash
python3 manager/pqapi.py scan create \
  --root /workspace/project \
  --compile-commands /workspace/project/build/compile_commands.json \
  --cpp-semantic auto \
  --wait
```

## Remaining boundary

Static analysis cannot uniquely determine input-dependent function pointers,
cross-library virtual dispatch, symbols assembled at runtime, JIT-generated
code, or the original behavior of encrypted/packed code. These cases now
produce explicit uncertainty metadata instead of a silent negative result.
Use authorized process maps or the fixed eBPF observation layer to confirm the
runtime target. Protected programs are never unpacked or executed automatically.
