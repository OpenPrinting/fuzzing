from __future__ import annotations

import unittest
from types import SimpleNamespace

from parser_fuzzers.document_harness import make_cups_raster, make_image
from parser_fuzzers.multitarget_runner import (
    DiscoveryState,
    TargetProfile,
    planned_semantic_runtime_key,
    record_semantic_crash_suppression,
    runtime_skip_reason,
)
from parser_fuzzers.ppd_templates import make_ppd
from parser_fuzzers.semantic_shapes import (
    build_planned_shape,
    output_depth_score,
    parse_job_options,
    parse_document_bytes,
    parse_output_bytes,
    shape_feature_tokens,
)


class SemanticShapeTests(unittest.TestCase):
    def test_png_semantic_shape_is_structural_and_hashable(self) -> None:
        profile = _profile()
        document = make_image(
            image_format="png_rgb",
            width=17,
            height=3,
            channels=3,
            png_interlace=1,
        )

        shape = build_planned_shape(
            target_id=profile.id,
            ppd_kind=profile.ppd_kind,
            document_kind=profile.document_kind,
            input_mime=profile.input_mime,
            output_mime=profile.output_mime,
            expected_filters=profile.expected_filters,
            ppd_text=make_ppd(profile.ppd_kind, 0),
            document_data=document,
        )
        document_shape = shape["semantic_input"]["document"]
        features = shape_feature_tokens(
            {
                **shape,
                "path_shape": {"stderr_states": ["before-scaling"], "reached_expected_filter": True},
                "failure_shape": {"location": ""},
                "path_shape_hash": "path",
                "failure_shape_hash": "failure",
                "compound_shape_hash": "compound",
            }
        )

        self.assertEqual(document_shape["format"], "png")
        self.assertEqual(document_shape["interlace"], 1)
        self.assertIn("IHDR", document_shape["structure"])
        self.assertTrue(shape["semantic_input_hash"])
        self.assertIn("shape-doc-format:png", features)
        self.assertIn("shape-path-state:before-scaling", features)
        self.assertTrue(any(feature.startswith("shape-path-depth:") for feature in features))
        self.assertNotIn("shape-compound:compound", features)

    def test_job_options_are_part_of_semantic_input_hash(self) -> None:
        profile = _profile()
        document = make_image(image_format="png_rgb", width=4, height=4, channels=3)
        common = {
            "target_id": profile.id,
            "ppd_kind": profile.ppd_kind,
            "document_kind": profile.document_kind,
            "input_mime": profile.input_mime,
            "output_mime": profile.output_mime,
            "expected_filters": profile.expected_filters,
            "ppd_text": make_ppd(profile.ppd_kind, 0),
            "document_data": document,
        }

        gray = build_planned_shape(**common, job_options="PageSize=A4 ColorModel=Gray Resolution=300x300dpi")
        rgb = build_planned_shape(**common, job_options="PageSize=A4 ColorModel=RGB Resolution=300x300dpi")
        parsed = parse_job_options("PageSize=A4 ColorModel=RGB")

        self.assertNotEqual(gray["semantic_input_hash"], rgb["semantic_input_hash"])
        self.assertEqual(parsed["ColorModel"], "RGB")
        self.assertIn("PageSize", parsed["keys"])

    def test_semantic_runtime_skip_requires_repeated_nonretained_failure(self) -> None:
        profile = _profile()
        shape_hash = planned_semantic_runtime_key(profile, 0).split("semantic-input:", 1)[1]
        shape_bundle = {
            "semantic_input_hash": shape_hash,
            "failure_shape_hash": "failure123",
        }
        result = SimpleNamespace(target_id=profile.id)
        state = DiscoveryState(runtime_skip_enabled=True, semantic_skip_after=2)
        signature = "SUMMARY: AddressSanitizer: heap-buffer-overflow cupsfilters/image.c:1 in example"

        self.assertFalse(
            record_semantic_crash_suppression(state, result, shape_bundle, signature, retained=True)
        )
        self.assertEqual(runtime_skip_reason(profile, 0, state), "")
        self.assertFalse(
            record_semantic_crash_suppression(state, result, shape_bundle, signature, retained=False)
        )
        self.assertEqual(runtime_skip_reason(profile, 0, state), "")
        self.assertTrue(
            record_semantic_crash_suppression(state, result, shape_bundle, signature, retained=False)
        )

        self.assertTrue(runtime_skip_reason(profile, 0, state).startswith("runtime-known-crash-semantic-shape:"))

    def test_document_parser_buckets_pnm_shape(self) -> None:
        document = make_image(image_format="pbm", width=31, height=3, channels=1)
        shape = parse_document_bytes(document)

        self.assertEqual(shape["format"], "pnm")
        self.assertEqual(shape["magic"], "P4")
        self.assertIn("width-boundary", shape["image_class"])

    def test_pdf_output_shape_adds_deep_observation_features(self) -> None:
        output = (
            b"%PDF-1.7\n"
            b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
            b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
            b"3 0 obj\n<< /Type /Page /Resources << >> /Contents 4 0 R >>\nendobj\n"
            b"4 0 obj\n<< /Length 5 >>\nstream\nabcde\nendstream\nendobj\n"
            b"xref\n0 5\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n"
        )
        output_shape = parse_output_bytes(output)
        features = shape_feature_tokens(
            {
                "semantic_input_hash": "input",
                "path_shape": {
                    "stderr_states": ["imagetopdf", "before-scaling"],
                    "reached_expected_filter": True,
                    "return_class": "zero",
                    "stdout_size": "512-4k",
                },
                "path_shape_hash": "path",
                "output_shape": output_shape,
                "output_shape_hash": "output",
                "failure_shape": {"location": ""},
                "failure_shape_hash": "failure",
            }
        )

        self.assertEqual(output_shape["format"], "pdf")
        self.assertEqual(output_shape["object_bucket"], "2-4")
        self.assertEqual(output_shape["page_bucket"], "1")
        self.assertTrue(output_shape["has_xref"])
        self.assertTrue(output_shape["has_trailer"])
        self.assertTrue(output_shape["has_eof"])
        self.assertIn("size:", output_shape["structure"])
        self.assertIn("xref:1", output_shape["structure"])
        self.assertIn("filter:none", output_shape["structure"])
        self.assertGreaterEqual(output_depth_score(output_shape), 8)
        self.assertIn("shape-output-format:pdf", features)
        self.assertTrue(any(feature.startswith("shape-output-depth:") for feature in features))

    def test_raster_output_shape_keeps_header_dimensions_in_structure(self) -> None:
        output = make_cups_raster(
            width=127,
            height=31,
            compression=0,
            num_colors=3,
            color_space=1,
            bits_per_pixel=24,
        )
        output_shape = parse_output_bytes(output)

        self.assertEqual(output_shape["format"], "cups-raster")
        self.assertIn("w:65-256", output_shape["structure"])
        self.assertIn("h:17-64", output_shape["structure"])
        self.assertIn("bpp:24", output_shape["structure"])
        self.assertIn("color:1", output_shape["structure"])


def _profile() -> TargetProfile:
    return TargetProfile(
        id="image_to_imagetops_feedback",
        description="test image pipeline",
        ppd_kind="imagetops_coverage_options",
        document_kind="image_feedback_sweep",
        executor="filter",
        input_mime="image/png",
        output_mime="application/postscript",
        expected_filters=["imagetops"],
        cases=1,
        oracle="crash_or_signal",
        filter_binary="",
    )


if __name__ == "__main__":
    unittest.main()
