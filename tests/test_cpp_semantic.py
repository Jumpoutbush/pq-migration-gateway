from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from scanner.cpp_semantic import analyze_cpp_source, parse_clang_ast
from scanner.enterprise_inventory import inspect_file, load_compile_commands, scan_cpp_source


def ref(decl_id: str, kind: str, name: str) -> dict:
    return {"kind": "DeclRefExpr", "referencedDecl": {"id": decl_id, "kind": kind, "name": name}}


def call(target: dict, line: int, *, kind: str = "CallExpr", arguments: list[dict] | None = None, macro: bool = False) -> dict:
    location = {"line": line}
    if macro:
        location = {"spellingLoc": {"line": line - 1}, "expansionLoc": {"line": line}}
    return {"kind": kind, "range": {"begin": location}, "inner": [target, *(arguments or [])]}


class CompileCommandSafetyTests(unittest.TestCase):
    def test_only_allowlisted_clang_flags_are_retained(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = root / "service.cpp"
            source.write_text("void f(){}\n", encoding="utf-8")
            database = root / "compile_commands.json"
            database.write_text(json.dumps([{
                "directory": str(root), "file": "service.cpp",
                "arguments": [
                    "g++", "-std=c++20", "-I", "include", "-DOK=1", "-DAPI_TOKEN=secret",
                    "-Xclang", "-load", "evil.so", "-fplugin=evil.so", "@response.txt",
                    "-c", "service.cpp", "-o", "service.o",
                ],
            }]), encoding="utf-8")
            contexts, _ = load_compile_commands([database])
            context = contexts[str(source.resolve())]
            semantic = context["_semantic_arguments"]
            self.assertIn("-std=c++20", semantic)
            self.assertIn("-DOK=1", semantic)
            self.assertNotIn("-DAPI_TOKEN=secret", semantic)
            self.assertFalse(any("plugin" in item or item == "-Xclang" or item.startswith("@") for item in semantic))
            self.assertEqual(context["definitions"]["API_TOKEN"], "<redacted>")


class ClangAstParserTests(unittest.TestCase):
    def semantic_ast(self) -> dict:
        crypto = {"kind": "FunctionDecl", "id": "crypto", "name": "EVP_PKEY_encrypt", "loc": {"line": 1}}
        loader = {"kind": "FunctionDecl", "id": "loader", "name": "dlsym", "loc": {"line": 2}}
        leaf = {
            "kind": "FunctionDecl", "id": "leaf", "name": "leaf", "loc": {"line": 10},
            "inner": [call(ref("crypto", "FunctionDecl", "EVP_PKEY_encrypt"), 11)],
        }
        template = {
            "kind": "FunctionTemplateDecl", "id": "template", "name": "template_crypto",
            "inner": [{
                "kind": "FunctionDecl", "id": "template_fn", "name": "template_crypto", "loc": {"line": 20},
                "inner": [call(ref("crypto", "FunctionDecl", "EVP_PKEY_encrypt"), 21, macro=True)],
            }],
        }
        base = {
            "kind": "CXXRecordDecl", "id": "base_record", "name": "Base",
            "inner": [{"kind": "CXXMethodDecl", "id": "base_apply", "name": "apply", "virtual": True, "pure": True, "loc": {"line": 30}}],
        }
        derived = {
            "kind": "CXXRecordDecl", "id": "derived_record", "name": "CryptoDerived",
            "inner": [{
                "kind": "CXXMethodDecl", "id": "derived_apply", "name": "apply", "virtual": True, "loc": {"line": 35},
                "inner": [call(ref("crypto", "FunctionDecl", "EVP_PKEY_encrypt"), 36)],
            }],
        }
        runner = {
            "kind": "FunctionDecl", "id": "runner", "name": "runner", "loc": {"line": 40},
            "inner": [
                {"kind": "VarDecl", "id": "fp", "name": "fp", "inner": [ref("leaf", "FunctionDecl", "leaf")]},
                call(ref("fp", "VarDecl", "fp"), 42),
                call({"kind": "MemberExpr", "referencedMemberDecl": "base_apply", "name": "apply"}, 43, kind="CXXMemberCallExpr"),
                call(ref("loader", "FunctionDecl", "dlsym"), 44, arguments=[{"kind": "StringLiteral", "value": "RSA_public_encrypt"}]),
            ],
        }
        return {"kind": "TranslationUnitDecl", "inner": [crypto, loader, leaf, template, base, derived, runner]}

    def test_templates_virtual_dispatch_function_pointers_and_dynamic_symbols(self):
        signals, metadata = parse_clang_ast(self.semantic_ast(), Path("semantic.cpp"))
        sources = {item["source"] for item in signals}
        self.assertIn("cpp_clang_macro_expansion", sources)
        self.assertIn("cpp_clang_function_pointer", sources)
        self.assertIn("cpp_clang_virtual_dispatch", sources)
        self.assertIn("cpp_clang_dynamic_resolution", sources)
        self.assertGreaterEqual(metadata["templates"], 1)
        self.assertEqual(metadata["function_pointer_crypto_calls"], 1)
        self.assertEqual(metadata["virtual_crypto_dispatches"], 1)

    def test_controlled_clang_runner_accepts_json_ast(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = root / "service.cpp"
            source.write_text("void f(){}\n", encoding="utf-8")
            fake = root / "fake-clang"
            fake.write_text(
                "#!/usr/bin/env python3\nimport json\n"
                f"print(json.dumps({self.semantic_ast()!r}))\n",
                encoding="utf-8",
            )
            fake.chmod(0o755)
            signals, metadata = analyze_cpp_source(source, {"directory": str(root), "_semantic_arguments": ["-std=c++20"]}, clang_binary=str(fake))
            self.assertEqual(metadata["status"], "succeeded")
            self.assertTrue(any(item["source"] == "cpp_clang_function_pointer" for item in signals))


class CppFallbackAndBinaryTests(unittest.TestCase):
    def test_nested_macro_and_dynamic_symbol_fallback(self):
        text = (
            "#define L1(x) SSL_CTX_new(x)\n"
            "#define L2(x) L1((x))\n"
            "#define L3(x) L2((x))\n"
            "#define L4(x) L3((x))\n"
            "void f(){ L4(TLS_client_method()); }\n"
            "void g(void *h){ auto fn = dlsym(h, \"RSA_public_encrypt\"); }\n"
        )
        signals, metadata = scan_cpp_source(Path("nested.cpp"), text, semantic_mode="off")
        self.assertTrue(any(item["source"] == "cpp_macro_expansion" and item["method"] == "SSL_CTX_new" for item in signals))
        self.assertTrue(any(item["source"] == "cpp_dynamic_symbol_resolution" and item["method"] == "RSA_public_encrypt" for item in signals))
        self.assertGreaterEqual(metadata["macro_count"], 4)

    def test_packed_binary_is_retained_as_explicit_analysis_gap(self):
        with tempfile.TemporaryDirectory() as td:
            binary = Path(td) / "packed-service"
            binary.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"UPX!" + b"\x00" * 128)
            binary.chmod(0o755)
            artifact, signals, _ = inspect_file(binary, 1_000_000, 4_000_000)
            self.assertIsNotNone(artifact)
            self.assertTrue(artifact.metadata["packed_or_protected"])
            self.assertTrue(any(item["evidence_type"] == "binary_analysis_gap" for item in signals))

    @unittest.skipUnless(all(shutil.which(item) for item in ("g++", "readelf")), "native ELF toolchain unavailable")
    def test_fully_stripped_elf_is_retained_for_runtime_followup(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = root / "release.cpp"
            binary = root / "release-service"
            source.write_text("int main(){ return 0; }\n", encoding="utf-8")
            subprocess.run(["g++", "-s", str(source), "-o", str(binary)], check=True)
            artifact, signals, _ = inspect_file(binary, 1_000_000, 8_000_000)
            self.assertIsNotNone(artifact)
            self.assertTrue(artifact.metadata["stripped"])
            self.assertEqual(artifact.metadata["analysis_completeness"], "reduced")
            self.assertTrue(any(item["method"] == "fully-stripped-binary" for item in signals))


if __name__ == "__main__":
    unittest.main()
