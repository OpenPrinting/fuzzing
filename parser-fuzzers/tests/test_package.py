# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import csv
import subprocess
import unittest
import zipfile
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parents[1]
MANIFESTS = ROOT / "manifests"


def read_lines(path: Path) -> list[str]:
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()]


class PackageIntegrityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.deploy = read_lines(MANIFESTS / "deploy-targets.txt")
        cls.compatibility = read_lines(
            MANIFESTS / "compatibility-targets.txt")
        cls.targets = cls.deploy + cls.compatibility

    def test_stable_target_identity(self) -> None:
        self.assertEqual(25, len(self.deploy))
        self.assertEqual(["fuzz_pdf"], self.compatibility)
        self.assertEqual(len(self.targets), len(set(self.targets)))
        for target in self.targets:
            self.assertTrue(target.startswith("fuzz_"), target)
            self.assertNotIn("v3", target)

    def test_target_map_matches_exported_assets(self) -> None:
        with (MANIFESTS / "target-map.tsv").open(
                encoding="utf-8", newline="") as stream:
            rows = list(csv.DictReader(stream, delimiter="\t"))

        self.assertEqual(set(self.targets),
                         {row["external_target"] for row in rows})
        self.assertEqual(25, sum(row["tier"] == "deploy" for row in rows))
        self.assertEqual(1,
                         sum(row["tier"] == "compatibility" for row in rows))

    def test_every_target_has_valid_corpus_and_dictionary(self) -> None:
        for target in self.targets:
            dictionary = ROOT / "dictionaries" / f"{target}.dict"
            corpus = ROOT / "corpus" / f"{target}_seed_corpus.zip"
            self.assertTrue(dictionary.is_file(), target)
            self.assertGreater(dictionary.stat().st_size, 0, target)
            self.assertTrue(corpus.is_file(), target)

            with zipfile.ZipFile(corpus) as archive:
                entries = [item for item in archive.infolist()
                           if not item.is_dir()]
                self.assertGreater(len(entries), 0, target)
                self.assertEqual(len(entries),
                                 len({item.filename for item in entries}))
                for item in entries:
                    name = PurePosixPath(item.filename)
                    self.assertFalse(name.is_absolute(), item.filename)
                    self.assertNotIn("..", name.parts, item.filename)
                    self.assertGreater(item.file_size, 0, item.filename)
                    self.assertLessEqual(item.file_size, 4 * 1024 * 1024,
                                         item.filename)
                    self.assertEqual(item.file_size,
                                     len(archive.read(item.filename)))

    def test_fuzz_pdf_corpus_is_raw_pdf(self) -> None:
        corpus = ROOT / "corpus" / "fuzz_pdf_seed_corpus.zip"
        with zipfile.ZipFile(corpus) as archive:
            for item in archive.infolist():
                if not item.is_dir():
                    self.assertTrue(archive.read(item.filename).startswith(
                        b"%PDF-"), item.filename)

    def test_source_manifest_is_exact_dependency_closure(self) -> None:
        manifest = read_lines(MANIFESTS / "deploy-source-files.txt")
        actual = sorted(
            path.relative_to(ROOT).as_posix()
            for path in (ROOT / "harnesses").rglob("*")
            if path.is_file()
        )
        self.assertEqual(219, len(manifest))
        self.assertEqual(sorted(manifest), actual)
        for entry in manifest:
            path = PurePosixPath(entry)
            self.assertEqual("harnesses", path.parts[0])
            self.assertNotIn("..", path.parts)

    def test_source_files_have_explicit_license(self) -> None:
        suffixes = {".c", ".cc", ".cpp", ".h"}
        sources = [path for path in (ROOT / "harnesses").rglob("*")
                   if path.suffix in suffixes]
        self.assertGreater(len(sources), 200)
        for source in sources:
            first_line = source.read_text(
                encoding="utf-8", errors="replace").splitlines()[0]
            self.assertEqual("// SPDX-License-Identifier: Apache-2.0",
                             first_line, str(source))

    def test_build_contract_uses_upstream_owned_root(self) -> None:
        build = (ROOT / "oss_fuzz_build.sh").read_text(encoding="utf-8")
        self.assertIn('ROOT="$SRC/fuzzing/parser-fuzzers"', build)
        self.assertIn("$LIB_FUZZING_ENGINE", (
            ROOT / "harnesses/libfuzzer/v3/build_local.sh"
        ).read_text(encoding="utf-8"))
        self.assertIn('"$OUT/$external_target"', build)
        self.assertIn("source-provenance.tsv", build)
        self.assertNotIn("cups-filters-v3-ossfuzz", build)

    def test_shell_entry_points_parse(self) -> None:
        scripts = [
            ROOT / "oss_fuzz_build.sh",
            ROOT / "harnesses/libfuzzer/v3/build_local.sh",
            ROOT / "harnesses/libfuzzer/v3/targets.sh",
            ROOT.parent / "projects/cups-filters/oss_fuzz_build.sh",
        ]
        for script in scripts:
            subprocess.run(["bash", "-n", str(script)], check=True)

    def test_package_contains_no_local_or_secret_markers(self) -> None:
        forbidden = ("/home/" + "gk", "gh" + "p_",
                     "github_" + "pat_", "co" + "dex")
        for path in ROOT.rglob("*"):
            if (not path.is_file() or path.suffix in {".zip", ".pyc"}
                    or "__pycache__" in path.parts):
                continue
            text = path.read_text(encoding="utf-8", errors="replace").lower()
            for marker in forbidden:
                self.assertNotIn(marker, text, str(path))


if __name__ == "__main__":
    unittest.main()
