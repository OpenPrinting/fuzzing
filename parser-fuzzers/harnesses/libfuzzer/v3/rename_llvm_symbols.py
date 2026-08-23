#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Apply the objcopy symbol operations used by V3 to LLVM bitcode."""

from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path


SYMBOL_TAIL = r"(?=$|[^-A-Za-z0-9_.$])"
IR_FUNCTION_SYMBOL = re.compile(
    r'^\s*(?P<kind>define|declare)\b[^@\n]*@'
    r'(?P<symbol>"(?:[^"\\]|\\.)*"|[-A-Za-z0-9_.$]+)\s*\('
)


def run(*args: str) -> str:
    result = subprocess.run(
        args,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return result.stdout


def read_symbol_map(path: Path) -> dict[str, str]:
    renames: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        fields = line.split()
        if not fields or fields[0].startswith("#"):
            continue
        if len(fields) != 2:
            raise ValueError(f"invalid symbol-map line: {line!r}")
        renames[fields[0]] = fields[1]
    return renames


def bitcode_symbols(path: Path) -> set[str]:
    symbols: set[str] = set()
    for line in run("llvm-nm", "-a", str(path)).splitlines():
        fields = line.split()
        if len(fields) < 2:
            continue
        symbol = fields[-1]
        if symbol.endswith(":") or symbol == str(path):
            continue
        symbols.add(symbol)
    return symbols


def prefix_symbol_map(symbols: set[str], prefix: str) -> dict[str, str]:
    # LLVM intrinsics must retain their reserved names in every valid IR
    # module. The following redefine-syms pass restores undefined symbols
    # anyway, so leaving intrinsics untouched preserves the intended result.
    return {
        symbol: prefix + symbol
        for symbol in symbols
        if not symbol.startswith("llvm.")
    }


def parse_args(argv: list[str]) -> tuple[Path, dict[str, str], set[str]]:
    if len(argv) < 2:
        raise ValueError("expected objcopy options followed by an object")

    object_path = Path(argv[-1])
    options = argv[:-1]
    renames: dict[str, str] = {}
    globalized: set[str] = set()
    index = 0

    while index < len(options):
        option = options[index]
        if option.startswith("--prefix-symbols="):
            prefix = option.split("=", 1)[1]
            renames.update(prefix_symbol_map(bitcode_symbols(object_path), prefix))
        elif option == "--prefix-symbols":
            index += 1
            prefix = options[index]
            renames.update(prefix_symbol_map(bitcode_symbols(object_path), prefix))
        elif option.startswith("--redefine-syms="):
            renames.update(read_symbol_map(Path(option.split("=", 1)[1])))
        elif option == "--redefine-syms":
            index += 1
            renames.update(read_symbol_map(Path(options[index])))
        elif option.startswith("--redefine-sym="):
            old, new = option.split("=", 1)[1].split("=", 1)
            renames[old] = new
        elif option == "--redefine-sym":
            index += 1
            old, new = options[index].split("=", 1)
            renames[old] = new
        elif option.startswith("--globalize-symbol="):
            globalized.add(option.split("=", 1)[1])
        elif option == "--globalize-symbol":
            index += 1
            globalized.add(options[index])
        else:
            raise ValueError(f"unsupported objcopy option: {option}")
        index += 1

    return (
        object_path,
        {old: new for old, new in renames.items() if old != new},
        globalized,
    )


def rewrite_ir(text: str, renames: dict[str, str]) -> str:
    if not renames:
        return text

    alternatives = "|".join(
        re.escape(symbol)
        for symbol in sorted(renames, key=lambda item: (-len(item), item))
        if '"' not in symbol
    )

    # A linkonce_odr function can have an implicit COMDAT group with the same
    # name. Rename both LLVM globals (@name) and COMDAT groups ($name), or the
    # rewritten function will reference a group that no longer has a definition.
    for sigil in ("@", "$"):
        quoted = re.compile(re.escape(sigil) + r'"((?:[^"\\]|\\.)*)"')

        def replace_quoted(match: re.Match[str], marker: str = sigil) -> str:
            symbol = match.group(1)
            return marker + '"' + renames.get(symbol, symbol) + '"'

        text = quoted.sub(replace_quoted, text)
        if alternatives:
            plain = re.compile(re.escape(sigil) + "(" + alternatives + ")" + SYMBOL_TAIL)
            text = plain.sub(
                lambda match, marker=sigil: marker + renames[match.group(1)],
                text,
            )
    return drop_redundant_function_declarations(text)


def drop_redundant_function_declarations(text: str) -> str:
    """Remove declarations that objcopy would merge with a definition."""
    definitions: set[str] = set()
    for line in text.splitlines():
        match = IR_FUNCTION_SYMBOL.match(line)
        if match and match.group("kind") == "define":
            definitions.add(match.group("symbol"))

    lines: list[str] = []
    for line in text.splitlines(keepends=True):
        match = IR_FUNCTION_SYMBOL.match(line)
        if (
            match
            and match.group("kind") == "declare"
            and match.group("symbol") in definitions
        ):
            continue
        lines.append(line)
    return "".join(lines)


def globalize_ir(text: str, symbols: set[str]) -> str:
    for symbol in symbols:
        token = re.escape(symbol)
        text = re.sub(
            rf"^(\s*@{token}\s*=\s*)(?:internal|private)\s+",
            r"\1",
            text,
            flags=re.MULTILINE,
        )
        text = re.sub(
            rf"^(\s*define\s+)(?:internal|private)\s+([^@\n]*@{token}{SYMBOL_TAIL})",
            r"\1\2",
            text,
            flags=re.MULTILINE,
        )
    return text


def main(argv: list[str]) -> int:
    object_path, renames, globalized = parse_args(argv)
    if not object_path.is_file():
        raise FileNotFoundError(object_path)

    with tempfile.TemporaryDirectory(prefix="cf-v3-ir-rename-") as directory:
        root = Path(directory)
        source = root / "object.ll"
        output = root / "object.bc"
        subprocess.run(
            ["clang", "-S", "-emit-llvm", "-x", "ir", str(object_path), "-o", str(source)],
            check=True,
        )
        rewritten = globalize_ir(
            rewrite_ir(source.read_text(encoding="utf-8"), renames),
            globalized,
        )
        source.write_text(rewritten, encoding="utf-8")
        subprocess.run(
            ["clang", "-c", "-emit-llvm", "-x", "ir", str(source), "-o", str(output)],
            check=True,
        )
        output.replace(object_path)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (IndexError, OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"rename_llvm_symbols.py: {error}", file=sys.stderr)
        raise SystemExit(2) from error
