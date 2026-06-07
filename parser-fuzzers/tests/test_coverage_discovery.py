from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from parser_fuzzers.multitarget_runner import (
    DiscoveryState,
    TargetDiscoveryStats,
    TargetProfile,
    _combined_skip_reason,
    _coverage_stagnated,
    _choose_next_profile,
    _is_novel_discovery,
    _run_dir_size_bytes,
    _target_scheduler_score,
    build_command,
    case_family_key,
    case_hazard_key,
    case_shape_key,
    build_env_overrides,
    build_job_options,
    coverage_skip_reason,
    extract_case_features,
    find_latest_runtime_skip_state,
    load_profiles,
    load_runtime_skip_state,
    record_runtime_crash_suppression,
    remap_filter_binary,
    run_case,
    runtime_skip_reason,
)
from parser_fuzzers.image_templates import image_feedback_instance


class CoverageDiscoveryTests(unittest.TestCase):
    def test_filter_root_remaps_direct_filter_binaries(self) -> None:
        self.assertEqual(
            remap_filter_binary("/data/pre-gsoc/cups-filters/pwgtopdf", "/tmp/filters"),
            "/tmp/filters/pwgtopdf",
        )

    def test_load_profiles_applies_filter_root_only_to_direct_filters(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "targets.yaml"
            config.write_text(
                """
targets:
  - id: direct
    ppd_kind: pwgtopdf_plain
    document_kind: pwg_raster_feedback_sweep
    executor: direct_filter
    filter_binary: /data/pre-gsoc/cups-filters/pwgtopdf
  - id: routed
    ppd_kind: rastertopclx
    document_kind: text
    executor: cupsfilter
""",
                encoding="utf-8",
            )

            direct, routed = load_profiles(config, filter_root="/tmp/filters")

        self.assertEqual(direct.filter_binary, "/tmp/filters/pwgtopdf")
        self.assertEqual(routed.filter_binary, "")

    def test_skips_known_rastertoescpx_dotrowstep_zero_cases(self) -> None:
        profile = _profile("cups_raster_to_rastertoescpx_general", "cups_raster_general_sweep", "rastertoescpx_size_sweep")

        self.assertEqual(coverage_skip_reason(profile, 3), "known-rastertoescpx-dotrowstep-zero-fpe")
        self.assertEqual(coverage_skip_reason(profile, 15), "known-rastertoescpx-dotrowstep-zero-fpe")
        self.assertEqual(coverage_skip_reason(profile, 0), "")

    def test_skips_known_libppd_65536dpi_cases(self) -> None:
        profile = _profile("pwg_to_raster_general", "pwg_raster_general_sweep", "pwg_resolution_general")

        self.assertEqual(coverage_skip_reason(profile, 16), "known-libppd-65536dpi-fpe")
        self.assertEqual(coverage_skip_reason(profile, 33), "known-libppd-65536dpi-fpe")
        self.assertEqual(coverage_skip_reason(profile, 15), "")

    def test_extract_case_features_includes_document_header(self) -> None:
        profile = _profile("feature_test", "cups_raster_coverage_sweep", "rastertopclx_plain")
        with tempfile.TemporaryDirectory() as tmp:
            result = run_case(profile, 0, Path(tmp), timeout_sec=1, capture_stdout=False)
            features = extract_case_features(result)

        self.assertIn("target:feature_test", features)
        self.assertIn("doc-sync:3SaR", features)
        self.assertTrue(any(feature.startswith("doc-size:") for feature in features))

    def test_extract_case_features_recognizes_pdf_and_png(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pdf_result = run_case(
                _profile("pdf_feature_test", "pdf_coverage_sweep", "pdftopdf_coverage_options"),
                0,
                Path(tmp) / "pdf",
                timeout_sec=1,
                capture_stdout=False,
            )
            png_result = run_case(
                _profile("png_feature_test", "image_coverage_sweep", "imagetoraster_coverage_options"),
                0,
                Path(tmp) / "png",
                timeout_sec=1,
                capture_stdout=False,
            )

            pdf_features = extract_case_features(pdf_result)
            png_features = extract_case_features(png_result)

        self.assertIn("doc-format:pdf", pdf_features)
        self.assertIn("doc-format:png", png_features)
        self.assertTrue(any(feature.startswith("doc-image-size:") for feature in png_features))

    def test_runtime_skip_suppresses_seen_crash_shape(self) -> None:
        profile = _profile("image_to_imagetoraster_coverage", "image_coverage_sweep", "imagetoraster_coverage_options")
        state = DiscoveryState(runtime_skip_enabled=True, crash_skip_after=1)
        signature = "SUMMARY: AddressSanitizer: heap-buffer-overflow example/image_scale.c:123 in sample_scale"

        self.assertEqual(runtime_skip_reason(profile, 1, state), "")
        self.assertTrue(record_runtime_crash_suppression(state, profile, 1, signature))

        self.assertEqual(case_shape_key(profile, 1), case_shape_key(profile, 721))
        self.assertTrue(runtime_skip_reason(profile, 721, state).startswith("runtime-known-crash-shape:"))
        self.assertEqual(runtime_skip_reason(profile, 2, state), "")

    def test_image_feedback_epoch_changes_runtime_skip_shape_when_enabled(self) -> None:
        profile = _profile("image_to_imagetoraster_feedback", "image_feedback_sweep", "imagetoraster_coverage_options")
        state = DiscoveryState(runtime_skip_enabled=True, crash_skip_after=1)

        with patch.dict("os.environ", {"SMT_FUZZER_IMAGE_CYCLE_EPOCHS": "8"}, clear=False):
            self.assertNotEqual(case_shape_key(profile, 1), case_shape_key(profile, 721))
            self.assertTrue(record_runtime_crash_suppression(state, profile, 1, "sig"))
            self.assertEqual(runtime_skip_reason(profile, 721, state), "")

    def test_image_feedback_epoch_changes_generated_instance_when_enabled(self) -> None:
        with patch.dict(
            "os.environ",
            {
                "SMT_FUZZER_IMAGE_CYCLE_EPOCHS": "8",
                "SMT_FUZZER_TEMPLATE_EXPANSION_LEVEL": "2",
            },
            clear=False,
        ):
            first = image_feedback_instance(1)
            second = image_feedback_instance(721)

        self.assertNotEqual(
            (
                first.image_format,
                first.width,
                first.height,
                first.payload_delta,
                first.comment_style,
                first.objective,
            ),
            (
                second.image_format,
                second.width,
                second.height,
                second.payload_delta,
                second.comment_style,
                second.objective,
            ),
        )

    def test_runtime_skip_suppresses_repeated_image_hazard(self) -> None:
        profile = _profile("image_to_imagetops_feedback", "image_feedback_sweep", "imagetops_coverage_options")
        state = DiscoveryState(runtime_skip_enabled=True, crash_skip_after=1, hazard_skip_after=2)

        with patch.dict(
            "os.environ",
            {
                "SMT_FUZZER_IMAGE_CYCLE_EPOCHS": "8",
                "SMT_FUZZER_TEMPLATE_EXPANSION_LEVEL": "2",
            },
            clear=False,
        ):
            target_hazard = case_hazard_key(profile, 1)
            matching = [
                index
                for index in range(2, 2000)
                if case_hazard_key(profile, index) == target_hazard
            ]
            self.assertGreaterEqual(len(matching), 2)
            self.assertTrue(record_runtime_crash_suppression(state, profile, 1, "sig"))
            self.assertEqual(runtime_skip_reason(profile, matching[0], state), "")
            self.assertTrue(record_runtime_crash_suppression(state, profile, matching[0], "sig"))

            skipped = _combined_skip_reason(profile, matching[1], "coverage", state, skip_probe_rate=0.0)
            probed = _combined_skip_reason(profile, matching[1], "coverage", state, skip_probe_rate=1.0)

        self.assertTrue(skipped.startswith("runtime-known-crash-hazard:"))
        self.assertEqual(probed, "")

    def test_runtime_skip_can_seed_previous_discovery_state(self) -> None:
        profile = _profile("image_to_imagetoraster_coverage", "image_coverage_sweep", "imagetoraster_coverage_options")
        signature = "SUMMARY: AddressSanitizer: heap-buffer-overflow example/image_scale.c:123 in sample_scale"

        with tempfile.TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "discovery_state.json"
            state_path.write_text(
                json.dumps(
                    {
                        "suppressed_case_shapes": [
                            {
                                "shape": case_shape_key(profile, 1),
                                "signature": signature,
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            state = DiscoveryState(runtime_skip_enabled=True, crash_skip_after=1)
            loaded = load_runtime_skip_state(state, state_path)

        self.assertEqual(loaded, 1)
        self.assertIn(signature, state.seen_crash_signatures)
        self.assertTrue(runtime_skip_reason(profile, 721, state).startswith("runtime-known-crash-shape:"))
        self.assertEqual(runtime_skip_reason(profile, 2, state), "")

    def test_generalized_skip_can_seed_family_suppression(self) -> None:
        profile = _profile("cups_raster_to_rastertoescpx_coverage", "cups_raster_coverage_sweep", "raster_coverage_options")
        signature = "SUMMARY: AddressSanitizer: FPE example/raster_filter.c:42 in process_line"

        with tempfile.TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "discovery_state.json"
            state_path.write_text(
                json.dumps(
                    {
                        "suppressed_case_shapes": [
                            {
                                "shape": case_shape_key(profile, case_id),
                                "signature": signature,
                            }
                            for case_id in range(3)
                        ]
                    }
                ),
                encoding="utf-8",
            )
            state = DiscoveryState(runtime_skip_enabled=True, generalized_skip_enabled=True, family_skip_after=3)
            loaded = load_runtime_skip_state(
                state,
                state_path,
                generalized_skip=True,
                family_skip_after=3,
            )

        self.assertEqual(loaded, 3)
        self.assertIn(case_family_key(profile), state.suppressed_case_families)
        self.assertTrue(runtime_skip_reason(profile, 99, state).startswith("runtime-known-crash-family:"))

    def test_runtime_skip_auto_discovers_latest_useful_state(self) -> None:
        profile = _profile("cups_raster_to_rastertopclx_feedback", "cups_raster_feedback_sweep", "raster_coverage_options")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            older = root / "feedback-campaign" / "20260101-000000"
            newer = root / "structural-campaign" / "20260102-000000"
            empty = root / "feedback-campaign" / "20260103-000000"
            older.mkdir(parents=True)
            newer.mkdir(parents=True)
            empty.mkdir(parents=True)
            (older / "discovery_state.json").write_text(
                json.dumps(
                    {
                        "suppressed_case_shapes": [
                            {"shape": case_shape_key(profile, 1), "signature": "older"}
                        ]
                    }
                ),
                encoding="utf-8",
            )
            (newer / "discovery_state.json").write_text(
                json.dumps(
                    {
                        "suppressed_case_shapes": [
                            {"shape": case_shape_key(profile, 2), "signature": "newer"}
                        ]
                    }
                ),
                encoding="utf-8",
            )
            (empty / "discovery_state.json").write_text(
                json.dumps({"suppressed_case_shapes": []}),
                encoding="utf-8",
            )

            latest = find_latest_runtime_skip_state(root)

        self.assertEqual(latest, newer / "discovery_state.json")

    def test_seed_state_loads_recorded_family_suppression(self) -> None:
        profile = _profile("pwg_to_pdf_feedback", "pwg_raster_feedback_sweep", "pwgtopdf_coverage_options")
        family = case_family_key(profile)

        with tempfile.TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "discovery_state.json"
            state_path.write_text(
                json.dumps(
                    {
                        "suppressed_case_families": [
                            {"family": family, "signature": "SUMMARY: AddressSanitizer: example"}
                        ]
                    }
                ),
                encoding="utf-8",
            )
            state = DiscoveryState(runtime_skip_enabled=True, generalized_skip_enabled=True)
            loaded = load_runtime_skip_state(state, state_path, generalized_skip=True)

        self.assertEqual(loaded, 0)
        self.assertIn(family, state.suppressed_case_families)
        self.assertTrue(runtime_skip_reason(profile, 123, state).startswith("runtime-known-crash-family:"))

    def test_target_family_normalizes_campaign_suffixes(self) -> None:
        coverage_profile = _profile("cups_raster_to_rastertopclx_coverage", "cups_raster_general_sweep", "rastertopclx_plain")
        general_profile = _profile("cups_raster_to_rastertopclx_general", "cups_raster_general_sweep", "rastertopclx_plain")
        feedback_profile = _profile("cups_raster_to_rastertopclx_feedback", "cups_raster_general_sweep", "rastertopclx_plain")

        state = DiscoveryState(runtime_skip_enabled=True, generalized_skip_enabled=True, family_skip_after=1)
        self.assertTrue(record_runtime_crash_suppression(state, coverage_profile, 0, "sig"))

        self.assertEqual(case_family_key(coverage_profile), case_family_key(general_profile))
        self.assertEqual(case_family_key(coverage_profile), case_family_key(feedback_profile))
        self.assertTrue(runtime_skip_reason(general_profile, 10, state).startswith("runtime-known-crash-family:"))
        self.assertTrue(runtime_skip_reason(feedback_profile, 10, state).startswith("runtime-known-crash-family:"))

    def test_novelty_scheduler_prefers_productive_targets(self) -> None:
        cold = _profile("cold_target", "text_coverage_sweep", "texttopdf_coverage_options")
        hot = _profile("hot_target", "text_coverage_sweep", "texttopdf_coverage_options")
        state = DiscoveryState()
        state.target_stats = {
            cold.id: TargetDiscoveryStats(submitted=10, completed=10),
            hot.id: TargetDiscoveryStats(submitted=10, completed=10, retained_cases=5, new_features=20),
        }
        state.scheduler_credit = {cold.id: 0.0, hot.id: 0.0}
        inflight = {cold.id: 0, hot.id: 0}

        picks = [_choose_next_profile([cold, hot], state, inflight, "novelty").id for _ in range(12)]

        self.assertGreater(picks.count(hot.id), picks.count(cold.id))

    def test_scheduler_fills_minimum_target_share(self) -> None:
        starved = _profile("starved_target", "image_feedback_sweep", "imagetoraster_coverage_options")
        hot = _profile("hot_target", "image_feedback_sweep", "imagetopdf_coverage_options")
        state = DiscoveryState()
        state.target_stats = {
            starved.id: TargetDiscoveryStats(submitted=10, completed=10),
            hot.id: TargetDiscoveryStats(submitted=100, completed=100, retained_cases=30, new_features=80),
        }
        state.scheduler_credit = {starved.id: 0.0, hot.id: 0.0}
        inflight = {starved.id: 0, hot.id: 0}

        pick = _choose_next_profile(
            [starved, hot],
            state,
            inflight,
            "novelty",
            min_target_share=0.25,
        )

        self.assertEqual(pick.id, starved.id)

    def test_scheduler_caps_over_budget_hot_target(self) -> None:
        cold = _profile("cold_target", "image_feedback_sweep", "imagetoraster_coverage_options")
        hot = _profile("hot_target", "image_feedback_sweep", "imagetopdf_coverage_options")
        state = DiscoveryState()
        state.target_stats = {
            cold.id: TargetDiscoveryStats(submitted=40, completed=40),
            hot.id: TargetDiscoveryStats(submitted=100, completed=100, retained_cases=50, new_features=120),
        }
        state.scheduler_credit = {cold.id: 0.0, hot.id: 0.0}
        inflight = {cold.id: 0, hot.id: 0}

        pick = _choose_next_profile(
            [cold, hot],
            state,
            inflight,
            "novelty",
            max_target_share=0.60,
        )

        self.assertEqual(pick.id, cold.id)

    def test_scheduler_deweights_crash_dominated_targets(self) -> None:
        state = DiscoveryState()
        state.target_stats = {
            "clean": TargetDiscoveryStats(completed=500, retained_cases=5, new_features=20),
            "crashy": TargetDiscoveryStats(
                completed=500,
                retained_cases=5,
                new_features=20,
                crashes=250,
                repeat_crashes=248,
                runtime_suppressed=200,
            ),
        }

        self.assertLess(_target_scheduler_score(state, "crashy"), _target_scheduler_score(state, "clean") * 0.25)

    def test_scheduler_deweights_skip_only_targets(self) -> None:
        state = DiscoveryState()
        state.target_stats = {
            "fresh": TargetDiscoveryStats(),
            "suppressed": TargetDiscoveryStats(skipped=200, runtime_suppressed=200),
        }

        self.assertLess(_target_scheduler_score(state, "suppressed"), _target_scheduler_score(state, "fresh"))

    def test_scheduler_deweights_seeded_crash_hazard_targets(self) -> None:
        state = DiscoveryState()
        state.target_stats = {
            "clean": TargetDiscoveryStats(completed=20, retained_cases=3, new_features=12),
            "image_to_imagetops_feedback_semantic": TargetDiscoveryStats(
                completed=20,
                retained_cases=3,
                new_features=12,
            ),
        }
        state.suppressed_case_hazards = {
            (
                "target:image_to_imagetops_feedback|ppd:coverage_options|doc:image_feedback_sweep|"
                "fmt:png_rgb|objective:postscript:ps-showpage-image|payload:exact|interlace:0"
            ): "SUMMARY: AddressSanitizer: SEGV example/image.c:75 in close_image"
        }

        self.assertLess(
            _target_scheduler_score(state, "image_to_imagetops_feedback_semantic"),
            _target_scheduler_score(state, "clean"),
        )

    def test_scheduler_periodically_probes_suppressed_targets(self) -> None:
        clean = _profile("clean", "text_semantic_sweep", "texttopdf_coverage_options")
        suppressed = _profile(
            "image_to_imagetops_feedback_semantic",
            "image_feedback_sweep",
            "imagetops_coverage_options",
        )
        state = DiscoveryState()
        state.target_stats = {
            clean.id: TargetDiscoveryStats(submitted=31, completed=31, retained_cases=8, new_features=40),
            suppressed.id: TargetDiscoveryStats(submitted=1, completed=1),
        }
        state.scheduler_credit = {clean.id: 0.0, suppressed.id: 0.0}
        state.suppressed_case_hazards = {
            (
                "target:image_to_imagetops_feedback|ppd:imagetops_coverage_options|doc:image_feedback_sweep|"
                "fmt:png_rgb|objective:postscript:ps-showpage-image|payload:exact|interlace:0"
            ): "SUMMARY: AddressSanitizer: SEGV example/image.c:75 in close_image"
        }

        with patch.dict("os.environ", {"SMT_FUZZER_AVOIDANCE_PROBE_INTERVAL": "32"}, clear=False):
            pick = _choose_next_profile(
                [clean, suppressed],
                state,
                {clean.id: 0, suppressed.id: 0},
                "novelty",
            )

        self.assertEqual(pick.id, suppressed.id)

    def test_avoidance_probe_can_bypass_runtime_family_skip(self) -> None:
        profile = _profile(
            "image_to_imagetops_feedback_semantic",
            "image_feedback_sweep",
            "imagetops_coverage_options",
        )
        state = DiscoveryState(runtime_skip_enabled=True, generalized_skip_enabled=True)
        family = case_family_key(profile)
        state.suppressed_case_families = {family: "SUMMARY: AddressSanitizer: SEGV example/image.c:75"}

        with patch.dict("os.environ", {"SMT_FUZZER_AVOIDANCE_SKIP_PROBE_RATE": "1.0"}, clear=False):
            reason = _combined_skip_reason(profile, 0, "coverage", state, skip_probe_rate=0.0)

        self.assertEqual(reason, "")

    def test_runtime_skip_probe_can_execute_suppressed_case(self) -> None:
        profile = _profile("image_to_imagetoraster_coverage", "image_coverage_sweep", "imagetoraster_coverage_options")
        state = DiscoveryState(runtime_skip_enabled=True, crash_skip_after=1)
        self.assertTrue(record_runtime_crash_suppression(state, profile, 1, "sig"))

        skipped = _combined_skip_reason(profile, 721, "coverage", state, skip_probe_rate=0.0)
        probed = _combined_skip_reason(profile, 721, "coverage", state, skip_probe_rate=1.0)

        self.assertTrue(skipped.startswith("runtime-known-crash-shape:"))
        self.assertEqual(probed, "")

    def test_coverage_stagnation_requires_completed_cases_and_timeout(self) -> None:
        state = DiscoveryState()

        self.assertFalse(_coverage_stagnated("coverage", 60, state, 0.0, 120.0))

        state.completed_cases = 100
        self.assertFalse(_coverage_stagnated("coverage", 60, state, 100.0, 120.0))
        self.assertTrue(_coverage_stagnated("coverage", 60, state, 0.0, 120.0))
        self.assertFalse(_coverage_stagnated("crash", 60, state, 0.0, 120.0))
        self.assertFalse(_coverage_stagnated("coverage", 0, state, 0.0, 120.0))

    def test_novel_discovery_recognizes_retention_and_new_crash(self) -> None:
        self.assertTrue(_is_novel_discovery({"retained_for_coverage": True}))
        self.assertTrue(_is_novel_discovery({"new_crash_signature": True}))
        self.assertFalse(_is_novel_discovery({"new_crash_signature": False}))
        self.assertFalse(_is_novel_discovery(None))

    def test_short_png_abort_skip_is_optional_and_format_aware(self) -> None:
        profile = _profile("image_to_imagetops_feedback", "image_feedback_sweep", "imagetops_coverage_options")

        with patch.dict(
            "os.environ",
            {
                "SMT_FUZZER_SKIP_SHORT_IMAGE_ABORTS": "1",
                "SMT_FUZZER_TEMPLATE_EXPANSION_LEVEL": "1",
            },
            clear=False,
        ):
            case_id = next(
                index
                for index in range(720)
                if image_feedback_instance(index).objective == "short_payload"
                and image_feedback_instance(index).image_format.startswith("png")
            )
            reason = coverage_skip_reason(profile, case_id)

        self.assertEqual(reason, "low-value-short-png-libpng-abort")

    def test_run_dir_size_counts_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a").write_bytes(b"1234")
            nested = root / "nested"
            nested.mkdir()
            (nested / "b").write_bytes(b"123456")

            self.assertEqual(_run_dir_size_bytes(root), 10)

    def test_local_filter_env_prefers_explicit_asan_library_paths(self) -> None:
        profile = _profile("image_to_imagetops_coverage", "image_coverage_sweep", "imagetops_coverage_options")
        profile = TargetProfile(
            id=profile.id,
            description=profile.description,
            ppd_kind=profile.ppd_kind,
            document_kind=profile.document_kind,
            executor=profile.executor,
            input_mime=profile.input_mime,
            output_mime=profile.output_mime,
            expected_filters=profile.expected_filters,
            cases=profile.cases,
            oracle=profile.oracle,
            filter_binary="/data/pre-gsoc/cups-filters/imagetops",
        )
        env = {
            "SMT_FUZZER_LIBPPD_ASAN": "/tmp/libppd-asan",
            "SMT_FUZZER_LIBCUPSFILTERS_ASAN": "/tmp/libcupsfilters-asan",
            "SMT_FUZZER_PDFIO_LIB": "/tmp/pdfio-lib",
            "LD_LIBRARY_PATH": "/tmp/inherited",
        }

        with patch.dict("os.environ", env, clear=False):
            overrides = build_env_overrides(profile, Path("candidate.ppd"))

        self.assertEqual(overrides["PPD"], "candidate.ppd")
        self.assertEqual(
            overrides["LD_LIBRARY_PATH"].split(":")[:4],
            ["/tmp/libppd-asan", "/tmp/libcupsfilters-asan", "/tmp/pdfio-lib", "/tmp/inherited"],
        )

    def test_direct_filter_job_options_are_populated_and_passed_as_argv5(self) -> None:
        profile = _profile("image_to_imagetopdf_coverage", "image_feedback_sweep", "imagetopdf_coverage_options")

        options = build_job_options(profile, 17)
        command = build_command(profile, Path("candidate.ppd"), Path("document.png"), job_options=options)

        self.assertIn("PageSize=", options)
        self.assertIn("ColorModel=", options)
        self.assertIn("scaling=", options)
        self.assertEqual(command[5], options)
        self.assertEqual(command[6], "document.png")


def _profile(target_id: str, document_kind: str, ppd_kind: str) -> TargetProfile:
    return TargetProfile(
        id=target_id,
        description="test",
        ppd_kind=ppd_kind,
        document_kind=document_kind,
        executor="direct_filter",
        input_mime="application/test",
        output_mime="",
        expected_filters=[],
        cases=1,
        oracle="crash_or_signal",
        filter_binary="/bin/true",
    )


if __name__ == "__main__":
    unittest.main()
