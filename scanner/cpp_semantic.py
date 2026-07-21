#!/usr/bin/env python3
"""Bounded, read-only Clang AST analysis for C and C++ crypto discovery.

The module never executes the target program and never replays an arbitrary
compile command.  It invokes Clang with ``-fsyntax-only`` and a small allowlist
of compilation flags prepared by :mod:`scanner.enterprise_inventory`.
"""
from __future__ import annotations

import json
import os
import re
import resource
import shutil
import subprocess
import tempfile
from collections import defaultdict
from itertools import chain
from pathlib import Path
from typing import Any, Iterable


FUNCTION_KINDS = {"FunctionDecl", "CXXMethodDecl", "CXXConstructorDecl", "CXXConversionDecl"}
CALL_KINDS = {"CallExpr", "CXXMemberCallExpr", "CXXOperatorCallExpr"}
DYNAMIC_LOADERS = {"dlopen", "dlmopen", "dlsym", "LoadLibraryA", "LoadLibraryW", "GetProcAddress"}
REFLECTION_CALLS = {"QMetaObject::invokeMethod", "invokeMethod"}

CRYPTO_PATTERNS: tuple[tuple[str, str, str, re.Pattern[str]], ...] = (
    ("OpenSSL", "TLS", "source_api_call", re.compile(r"^(?:SSL_(?:CTX_)?|TLS_(?:client|server)_method$)")),
    ("OpenSSL", "EVP/runtime-selected", "source_api_call", re.compile(r"^EVP_(?:Cipher|Digest|Encrypt|Decrypt|Sign|Verify|PKEY|KEM)")),
    ("OpenSSL", "RSA", "source_api_call", re.compile(r"^RSA_")),
    ("OpenSSL", "ECDSA/ECDH", "source_api_call", re.compile(r"^(?:EC_KEY|ECDSA|ECDH)_")),
    ("libsodium", "modern-crypto", "source_api_call", re.compile(r"^(?:sodium|crypto_(?:box|sign|kx|secretbox|aead|pwhash))_")),
    ("wolfSSL", "TLS", "source_api_call", re.compile(r"^wolfSSL_")),
    ("liboqs", "PQC", "source_api_call", re.compile(r"^(?:OQS_|oqs::|pqcrypto::)")),
    ("Botan", "runtime-selected", "source_api_call", re.compile(r"(?:^|::)Botan::(?:TLS|Cipher_Mode|PK_Signer|PK_Verifier|HashFunction)")),
    ("Crypto++", "runtime-selected", "source_api_call", re.compile(r"(?:^|::)CryptoPP::(?:RSA|ECDSA|AES|GCM|SHA|DH)")),
)
CRYPTO_LIBRARY_PATTERN = re.compile(
    r"(?:^|/)(?:lib)?(?:ssl|crypto|sodium|gcrypt|nettle|gnutls|mbedtls|wolfssl|botan|oqs|aws-lc|boringssl)[^/\s]*",
    re.I,
)


def _children(node: dict[str, Any]) -> list[dict[str, Any]]:
    return [item for item in node.get("inner", []) if isinstance(item, dict)]


def _descendants(node: dict[str, Any]) -> Iterable[dict[str, Any]]:
    stack = list(reversed(_children(node)))
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(_children(current)))


def _location(node: dict[str, Any]) -> tuple[int, bool]:
    """Return source line and whether Clang reports a macro expansion."""
    candidates = [node.get("loc", {}), node.get("range", {}).get("begin", {})]
    line = 0
    macro = False
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        spelling = candidate.get("spellingLoc")
        expansion = candidate.get("expansionLoc")
        if isinstance(spelling, dict) or isinstance(expansion, dict):
            macro = True
        for item in (expansion, spelling, candidate):
            if isinstance(item, dict) and item.get("line"):
                line = int(item["line"])
                return line, macro
    return line, macro


def _explicit_file(node: dict[str, Any]) -> str:
    candidates = [node.get("loc", {}), node.get("range", {}).get("begin", {})]
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        for item in (candidate.get("expansionLoc"), candidate.get("spellingLoc"), candidate):
            if isinstance(item, dict) and item.get("file"):
                return str(item["file"])
    return ""


def _is_main_file(value: str, source_path: Path) -> bool:
    if not value:
        return True
    try:
        return Path(value).resolve() == source_path.resolve()
    except OSError:
        return Path(value).name == source_path.name


def _decl_reference(node: dict[str, Any]) -> tuple[str, str, str]:
    """Return referenced declaration id, kind and human-readable name."""
    referenced = node.get("referencedDecl")
    if isinstance(referenced, dict):
        return str(referenced.get("id", "")), str(referenced.get("kind", "")), str(referenced.get("name", ""))
    if node.get("kind") == "MemberExpr":
        return str(node.get("referencedMemberDecl", "")), "CXXMethodDecl", str(node.get("name", ""))
    return "", "", ""


def _references(node: dict[str, Any], kinds: set[str] | None = None) -> list[tuple[str, str, str]]:
    output: list[tuple[str, str, str]] = []
    for current in chain((node,), _descendants(node)):
        if current.get("kind") not in {"DeclRefExpr", "MemberExpr", "UnresolvedLookupExpr"}:
            continue
        decl_id, kind, name = _decl_reference(current)
        if not name and current.get("kind") == "UnresolvedLookupExpr":
            name = str(current.get("name", ""))
            kind = "FunctionTemplateDecl"
        if name and (kinds is None or kind in kinds):
            output.append((decl_id, kind, name))
    return output


def _string_literals(node: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for current in _descendants(node):
        if current.get("kind") != "StringLiteral":
            continue
        value = str(current.get("value", "")).strip('"')
        if value:
            values.append(value[:500])
    return values


def _crypto_descriptor(name: str) -> dict[str, str] | None:
    normalized = name.lstrip("&:")
    # Clang may retain template parameters in a qualified function name.  Test
    # both the full name and its final component without an argument suffix.
    candidates = [normalized, normalized.rsplit("::", 1)[-1]]
    candidates.extend(re.sub(r"<.*>", "", item) for item in list(candidates))
    for candidate in candidates:
        for library, algorithm, evidence_type, pattern in CRYPTO_PATTERNS:
            if pattern.search(candidate) or pattern.search(normalized):
                return {
                    "method": normalized[:240], "library": library,
                    "algorithm": algorithm, "evidence_type": evidence_type,
                }
    return None


def _signal(*, line: int, source: str, method: str, library: str, algorithm: str,
            evidence_type: str = "source_api_call", confidence: str = "HIGH",
            excerpt: str = "", metadata: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "line": line,
        "evidence_type": evidence_type,
        "algorithm": algorithm,
        "excerpt": (excerpt or f"Clang AST: {method}")[:500],
        "language": "cpp",
        "method": method[:240],
        "library": library,
        "confidence": confidence,
        "artifact_type": "source",
        "source": source,
        "metadata": metadata or {},
    }


def parse_clang_ast(ast: dict[str, Any], source_path: Path, *, partial: bool = False) -> tuple[list[dict], dict]:
    """Convert a Clang JSON AST into crypto evidence and semantic metadata."""
    functions: dict[str, dict[str, Any]] = {}
    function_by_name: dict[str, set[str]] = defaultdict(set)
    calls: list[dict[str, Any]] = []
    pointer_targets: dict[str, set[str]] = defaultdict(set)
    pointer_names: dict[str, str] = {}

    main_file = str(source_path.resolve())
    stack: list[tuple[dict[str, Any], str, bool, tuple[str, ...], str]] = [(ast, "", False, (), main_file)]
    while stack:
        node, current_function, template, scopes, current_file = stack.pop()
        kind = str(node.get("kind", ""))
        name = str(node.get("name", ""))
        node_file = _explicit_file(node) or current_file
        child_scopes = scopes
        if kind in {"NamespaceDecl", "CXXRecordDecl", "ClassTemplateDecl"} and name:
            child_scopes = (*scopes, name)
        if kind == "FunctionTemplateDecl":
            template = True
        if kind in FUNCTION_KINDS:
            decl_id = str(node.get("id", "")) or f"anon:{len(functions)}"
            line, macro = _location(node)
            is_virtual = bool(node.get("virtual")) or any(child.get("kind") == "OverrideAttr" for child in _children(node))
            info = functions.setdefault(decl_id, {
                "id": decl_id,
                "name": name,
                "qualified_name": "::".join((*scopes, name)) if scopes and name else name,
                "line": line,
                "virtual": is_virtual,
                "pure": bool(node.get("pure")),
                "template": template,
                "macro": macro,
                "file": node_file,
            })
            if is_virtual:
                info["virtual"] = True
            function_by_name[name].add(decl_id)
            current_function = decl_id

        if kind == "VarDecl":
            decl_id = str(node.get("id", ""))
            pointer_names[decl_id] = name
            for target_id, target_kind, target_name in _references(node, FUNCTION_KINDS | {"FunctionTemplateDecl"}):
                if target_id:
                    pointer_targets[decl_id].add(target_id)
                elif target_name:
                    pointer_targets[decl_id].update(function_by_name.get(target_name, set()))

        if kind == "BinaryOperator" and node.get("opcode") == "=":
            children = _children(node)
            if len(children) >= 2:
                left = _references(children[0], {"VarDecl", "ParmVarDecl", "FieldDecl"})
                right = _references(children[1], FUNCTION_KINDS | {"FunctionTemplateDecl"})
                for variable_id, _kind, variable_name in left:
                    pointer_names[variable_id] = variable_name
                    for target_id, _target_kind, target_name in right:
                        if target_id:
                            pointer_targets[variable_id].add(target_id)
                        else:
                            pointer_targets[variable_id].update(function_by_name.get(target_name, set()))

        if kind in CALL_KINDS:
            children = _children(node)
            callee_tree = children[0] if children else node
            references = _references(callee_tree)
            line, macro = _location(node)
            direct = next((item for item in references if item[1] in FUNCTION_KINDS | {"FunctionTemplateDecl"}), ("", "", ""))
            variable = next((item for item in references if item[1] in {"VarDecl", "ParmVarDecl", "FieldDecl"}), ("", "", ""))
            if not variable[0] and kind == "CXXOperatorCallExpr":
                variable = next((item for item in _references(node, {"VarDecl", "ParmVarDecl", "FieldDecl"})), ("", "", ""))
            calls.append({
                "caller": current_function,
                "callee_id": direct[0], "callee_name": direct[2],
                "variable_id": variable[0], "variable_name": variable[2],
                "kind": kind, "line": line, "macro": macro,
                "file": node_file,
                "strings": _string_literals(node),
            })
        for child in reversed(_children(node)):
            stack.append((child, current_function, template, child_scopes, node_file))

    direct_crypto_functions: set[str] = set()
    edges: list[tuple[str, str]] = []
    signals: list[dict[str, Any]] = []
    dynamic_calls = 0
    pointer_calls = 0
    virtual_calls = 0

    def add(item: dict[str, Any]) -> None:
        signals.append(item)

    for call in calls:
        callee_id = call["callee_id"]
        callee_name = call["callee_name"] or functions.get(callee_id, {}).get("qualified_name", "")
        if call["caller"] and callee_id:
            edges.append((call["caller"], callee_id))
        descriptor = _crypto_descriptor(callee_name) if callee_name else None
        caller = functions.get(call["caller"], {})
        if descriptor:
            if call["caller"]:
                direct_crypto_functions.add(call["caller"])
            if not _is_main_file(call.get("file", ""), source_path):
                continue
            source = "cpp_clang_macro_expansion" if call["macro"] else "cpp_clang_template" if caller.get("template") else "cpp_clang_ast"
            add(_signal(
                line=call["line"], source=source, confidence="MEDIUM" if partial else "HIGH",
                excerpt=f"semantic call: {caller.get('qualified_name', '<global>')} -> {descriptor['method']}",
                metadata={"caller": caller.get("qualified_name", "<global>"), "callee": descriptor["method"],
                          "macro_expansion": call["macro"], "template_context": bool(caller.get("template")),
                          "partial_ast": partial},
                **descriptor,
            ))

        loader_name = callee_name.rsplit("::", 1)[-1] if callee_name else ""
        if loader_name in DYNAMIC_LOADERS or callee_name in REFLECTION_CALLS or loader_name in REFLECTION_CALLS:
            dynamic_calls += 1
            if not _is_main_file(call.get("file", ""), source_path):
                continue
            matched = False
            for value in call["strings"]:
                target = _crypto_descriptor(value)
                if target:
                    matched = True
                    add(_signal(
                        line=call["line"], source="cpp_clang_dynamic_resolution", confidence="HIGH" if not partial else "MEDIUM",
                        excerpt=f"{loader_name} resolves crypto target {value}",
                        metadata={"loader": loader_name, "resolved_symbol": value, "partial_ast": partial},
                        **{**target, "evidence_type": "dynamic_symbol_resolution"},
                    ))
                elif CRYPTO_LIBRARY_PATTERN.search(value):
                    matched = True
                    add(_signal(
                        line=call["line"], source="cpp_clang_dynamic_loading", method=value,
                        library=value, algorithm="runtime-selected", evidence_type="dynamic_crypto_library",
                        confidence="HIGH" if not partial else "MEDIUM", excerpt=f"{loader_name} loads {value}",
                        metadata={"loader": loader_name, "library_path": value, "partial_ast": partial},
                    ))
            if not matched:
                add(_signal(
                    line=call["line"], source="cpp_clang_dynamic_loading", method=loader_name or callee_name,
                    library="dynamic-loader", algorithm="runtime-selected", evidence_type="dynamic_loading_review",
                    confidence="LOW", excerpt=f"dynamic invocation requires runtime correlation: {loader_name or callee_name}",
                    metadata={"loader": loader_name or callee_name, "target_known": False, "partial_ast": partial},
                ))

    # Resolve statically known wrappers to a fixpoint.
    crypto_functions = set(direct_crypto_functions)
    for _ in range(64):
        newly_known = {caller for caller, callee in edges if callee in crypto_functions and caller not in crypto_functions}
        if not newly_known:
            break
        crypto_functions.update(newly_known)

    # Function pointer and std::function calls retain VarDecl references in the
    # AST.  Connect each call with the declaration/assignment target set.
    for call in calls:
        if not _is_main_file(call.get("file", ""), source_path):
            continue
        variable_id = call["variable_id"]
        if not variable_id:
            continue
        targets = pointer_targets.get(variable_id, set())
        crypto_targets = [target for target in targets if target in crypto_functions or _crypto_descriptor(functions.get(target, {}).get("qualified_name", ""))]
        if not crypto_targets:
            continue
        pointer_calls += 1
        names = sorted(functions.get(target, {}).get("qualified_name", target) for target in crypto_targets)
        add(_signal(
            line=call["line"], source="cpp_clang_function_pointer",
            method=f"{call['variable_name'] or pointer_names.get(variable_id, '<function-pointer>')} -> {names[0]}",
            library="indirect-call", algorithm="runtime-selected", evidence_type="function_pointer_call",
            confidence="MEDIUM", excerpt=f"semantic function-pointer target: {', '.join(names[:8])}",
            metadata={"variable": call["variable_name"] or pointer_names.get(variable_id, ""), "candidate_targets": names[:64]},
        ))

    # A virtual call can reach any compatible override.  Clang identifies the
    # declared virtual method; conservative name-based class-hierarchy expansion
    # records the crypto-capable candidates instead of pretending one target is certain.
    virtual_by_name: dict[str, set[str]] = defaultdict(set)
    for decl_id, info in functions.items():
        if info.get("virtual"):
            virtual_by_name[info.get("name", "")].add(decl_id)
    for call in calls:
        if not _is_main_file(call.get("file", ""), source_path):
            continue
        callee = functions.get(call["callee_id"], {})
        if call["kind"] != "CXXMemberCallExpr" or not callee.get("virtual"):
            continue
        candidates = virtual_by_name.get(callee.get("name", ""), set())
        crypto_candidates = [item for item in candidates if item in crypto_functions]
        if not crypto_candidates:
            continue
        virtual_calls += 1
        names = sorted(functions[item].get("qualified_name", item) for item in crypto_candidates)
        add(_signal(
            line=call["line"], source="cpp_clang_virtual_dispatch",
            method=f"{callee.get('qualified_name', callee.get('name', '<virtual>'))} -> {{{', '.join(names[:8])}}}",
            library="virtual-dispatch", algorithm="runtime-selected", evidence_type="virtual_dispatch_call",
            confidence="MEDIUM", excerpt=f"possible crypto virtual targets: {', '.join(names[:8])}",
            metadata={"declared_target": callee.get("qualified_name", ""), "candidate_targets": names[:64],
                      "conservative_class_hierarchy": True},
        ))

    # Semantic wrapper evidence is based on actual declaration references, not
    # text matching.  It complements the direct crypto call at the leaf.
    for caller_id, callee_id in edges:
        if callee_id not in crypto_functions or caller_id in direct_crypto_functions:
            continue
        caller, callee = functions.get(caller_id, {}), functions.get(callee_id, {})
        if not caller or not callee or not _is_main_file(str(caller.get("file", "")), source_path):
            continue
        add(_signal(
            line=caller.get("line", 0), source="cpp_clang_call_graph",
            method=f"{caller.get('qualified_name')} -> {callee.get('qualified_name')}",
            library="transitive-wrapper", algorithm="runtime-selected", evidence_type="cpp_semantic_call_graph",
            confidence="HIGH" if not partial else "MEDIUM",
            excerpt=f"semantic call graph: {caller.get('qualified_name')} -> {callee.get('qualified_name')}",
            metadata={"caller": caller.get("qualified_name"), "callee": callee.get("qualified_name"), "partial_ast": partial},
        ))

    deduplicated: list[dict[str, Any]] = []
    seen: set[tuple[int, str, str]] = set()
    for item in signals:
        key = (int(item["line"]), str(item["method"]), str(item["source"]))
        if key not in seen:
            seen.add(key)
            deduplicated.append(item)
    metadata = {
        "functions": len(functions),
        "semantic_call_edges": len(edges),
        "function_pointer_bindings": sum(bool(value) for value in pointer_targets.values()),
        "function_pointer_crypto_calls": pointer_calls,
        "virtual_crypto_dispatches": virtual_calls,
        "dynamic_loading_calls": dynamic_calls,
        "templates": sum(bool(item.get("template")) for item in functions.values()),
        "partial_ast": partial,
        "source": str(source_path.resolve()),
    }
    return deduplicated, metadata


def _limit_output(max_bytes: int, cpu_seconds: int) -> None:
    resource.setrlimit(resource.RLIMIT_FSIZE, (max_bytes, max_bytes))
    resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds + 1))


def analyze_cpp_source(path: Path, compile_context: dict[str, Any] | None, *,
                       clang_binary: str = "clang++", timeout: int = 20,
                       max_ast_bytes: int = 32_000_000) -> tuple[list[dict], dict]:
    """Run a controlled Clang syntax-only analysis and parse its JSON AST."""
    executable = shutil.which(clang_binary) if not Path(clang_binary).is_absolute() else clang_binary
    if not executable or not Path(executable).is_file():
        return [], {"status": "unavailable", "reason": f"Clang executable not found: {clang_binary}"}
    context = compile_context or {}
    arguments = [str(item) for item in context.get("_semantic_arguments", []) if isinstance(item, str)]
    command = [
        str(executable), "-fsyntax-only", "-fno-color-diagnostics", "-Wno-everything",
        "-Xclang", "-ast-dump=json", *arguments, str(path.resolve()),
    ]
    cwd = Path(str(context.get("directory") or path.parent)).resolve()
    if not cwd.is_dir():
        cwd = path.parent.resolve()
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
        "HOME": "/nonexistent", "TMPDIR": os.environ.get("TMPDIR", "/tmp"),
    }
    preexec = (lambda: _limit_output(max_ast_bytes, max(2, timeout))) if os.name == "posix" else None
    try:
        with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
            process = subprocess.run(
                command, stdin=subprocess.DEVNULL, stdout=stdout_file, stderr=stderr_file,
                timeout=timeout, check=False, cwd=cwd, env=env,
                preexec_fn=preexec,
            )
            size = stdout_file.tell()
            if size >= max_ast_bytes:
                return [], {"status": "bounded", "reason": "Clang AST exceeded byte limit", "ast_bytes": size}
            stdout_file.seek(0)
            raw_ast = stdout_file.read(max_ast_bytes + 1)
            stderr_size = stderr_file.tell()
            stderr_file.seek(max(0, stderr_size - 2000))
            diagnostics = stderr_file.read(2000).decode("utf-8", "replace")
    except subprocess.TimeoutExpired:
        return [], {"status": "timeout", "reason": f"Clang exceeded {timeout}s"}
    except OSError as exc:
        return [], {"status": "failed", "reason": f"{type(exc).__name__}: {exc}"}
    try:
        ast = json.loads(raw_ast)
    except (json.JSONDecodeError, UnicodeError) as exc:
        return [], {
            "status": "failed", "reason": f"invalid Clang AST JSON: {exc}",
            "returncode": process.returncode, "ast_bytes": len(raw_ast),
        }
    partial = process.returncode != 0
    signals, parsed = parse_clang_ast(ast, path, partial=partial)
    return signals, {
        "status": "partial" if partial else "succeeded",
        "engine": "clang-ast-json", "returncode": process.returncode,
        "ast_bytes": len(raw_ast), "diagnostics": diagnostics,
        "safe_argument_count": len(arguments), **parsed,
    }
