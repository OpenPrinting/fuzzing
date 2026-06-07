from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from parser_fuzzers.afl_dynamic_bridge import (
    MAGIC,
    DOCUMENT_MARK,
    OPTIONS_MARK,
    PPD_MARK,
    augment_pwg_bundle_seed_dir,
    parse_pwg_bundle,
    write_dynamic_afl_dictionary,
)


class AFLDynamicBridgeTests(unittest.TestCase):
    def test_writes_dynamic_dictionary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            profile = root / "dynamic.json"
            base = root / "base.dict"
            out = root / "dynamic.dict"
            profile.write_text(
                json.dumps(
                    {
                        "schema_version": "dynamic-compare-hints-v1",
                        "tokens": {"PageSize": 5, "application/vnd.cups-pwg": 3},
                        "ppd_options": {"ColorModel": 2},
                        "magic_tokens": {"RaS2": 1},
                        "records": [],
                    }
                ),
                encoding="utf-8",
            )
            base.write_text('"--SMT-PPD--"\n', encoding="utf-8")

            manifest = write_dynamic_afl_dictionary(profile, out, base_dictionary=base)
            content = out.read_text(encoding="utf-8")

        self.assertGreaterEqual(manifest["tokens_added"], 3)
        self.assertIn('"PageSize"', content)
        self.assertIn('"PageSize="', content)
        self.assertIn('"application/vnd.cups-pwg"', content)
        self.assertIn('"ColorModel"', content)

    def test_augments_pwg_bundle_seeds(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            seed_dir = root / "seeds"
            seed_dir.mkdir()
            seed = seed_dir / "seed-0000.pwg-bundle"
            seed.write_bytes(
                MAGIC
                + PPD_MARK
                + b"*PPD-Adobe: \"4.3\"\n"
                + OPTIONS_MARK
                + b"PageSize=Letter"
                + DOCUMENT_MARK
                + b"RaS2\x00\x00"
            )
            profile = root / "dynamic.json"
            profile.write_text(
                json.dumps(
                    {
                        "schema_version": "dynamic-compare-hints-v1",
                        "tokens": {"cupsBitsPerPixel": 4},
                        "ppd_options": {"cupsBitsPerPixel": 4},
                        "magic_tokens": {},
                        "records": [],
                    }
                ),
                encoding="utf-8",
            )

            manifest = augment_pwg_bundle_seed_dir(seed_dir, profile, limit=2)
            generated = sorted(seed_dir.glob("dynamic-option-*.pwg-bundle"))
            parsed = parse_pwg_bundle(generated[0].read_bytes())

        self.assertGreaterEqual(manifest["created"], 1)
        self.assertIsNotNone(parsed)
        assert parsed is not None
        ppd, options, document = parsed
        self.assertIn(b"*cupsBitsPerPixel: 24", ppd)
        self.assertIn(b"cupsBitsPerPixel=24", options)
        self.assertEqual(document, b"RaS2\x00\x00")


if __name__ == "__main__":
    unittest.main()
