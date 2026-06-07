#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class Family:
    family_id: str
    title: str
    needles: tuple[str, ...]
    required_harness: str
    notes: str


FAMILIES = (
    Family(
        "libppd_ppd_cupsfilter",
        "libppd / PPD / cupsFilter",
        ("libppd", "ppd", "cupsfilter", "cupsfilter:", "cluster-00"),
        "PPD-aware harness or PPD+document bundle",
        "Needs PPD as a first-class input; document-only fuzzing will miss several paths.",
    ),
    Family(
        "pwg_pwgtopdf",
        "PWG Raster -> pwgtopdf",
        ("pwg_to_pdf", "pwgtopdf", "pwg-bundle", "cfimagergbtowhite", "cluster-03"),
        "PWG document plus PPD/job options, standard AFL++ seedable",
        "Good fit for template-generated PWG seeds and AFL++ CmpLog/dictionary.",
    ),
    Family(
        "pwg_pwgtopclm",
        "PWG Raster -> pwgtopclm",
        ("pwg_to_pclm", "pwgtopclm", "pclm"),
        "PWG document plus PPD/job options, standard AFL++ seedable",
        "Sibling path to pwgtopdf; useful for format-depth comparison.",
    ),
    Family(
        "image_imagetoraster",
        "Image -> imagetoraster",
        ("imagetoraster", "image_to_imagetoraster"),
        "Image document plus PPD/job options",
        "Needs image templates, dimensions, color models, and valid/near-valid headers.",
    ),
    Family(
        "image_imagetops",
        "Image -> imagetops",
        ("imagetops", "image_to_imagetops"),
        "Image document plus PPD/job options",
        "Historically produced several shallow and mid-depth image conversion crashes.",
    ),
    Family(
        "image_imagetopdf",
        "Image -> imagetopdf",
        ("imagetopdf", "image_to_imagetopdf"),
        "Image document plus PPD/job options",
        "Useful as a control target for image parsing without PostScript output paths.",
    ),
    Family(
        "cups_raster_escpx",
        "CUPS Raster -> rastertoescpx/commandtoescpx",
        ("rastertoescpx", "commandtoescpx", "escpx", "cups_raster_to_rastertoescpx"),
        "CUPS raster/command document plus PPD/job options",
        "Requires raster-specific structural templates; generic image seeds are not enough.",
    ),
    Family(
        "cups_raster_pclx",
        "CUPS Raster -> rastertopclx/commandtopclx",
        ("rastertopclx", "commandtopclx", "pclx", "cups_raster_to_rastertopclx"),
        "CUPS raster/command document plus PPD/job options",
        "Requires row/plane/header consistency to get past early parser checks.",
    ),
    Family(
        "pdf_filters",
        "PDF filters",
        ("pdftopdf", "pdftops", "pdftoraster", "mupdftopwg", "qpdf", ".pdf"),
        "PDF document plus PPD/job options",
        "Coverage can be lower unless seeds contain enough valid PDF structure.",
    ),
    Family(
        "postscript_gs",
        "PostScript / Ghostscript wrappers",
        ("postscript", "gstoraster", "gstopdf", "gstopxl"),
        "PostScript document plus wrapper environment",
        "Often depends on external Ghostscript behavior and wrapper argument shape.",
    ),
    Family(
        "text_filters",
        "Text filters",
        ("texttopdf", "texttotext", "text_to_"),
        "Text document plus PPD/job options",
        "Good low-cost parser lane; lower historical crash density so far.",
    ),
)


def main() -> int:
    parser = argparse.ArgumentParser(description="build a heuristic historical crash reachability matrix")
    parser.add_argument("--project-root", default=".")
    parser.add_argument("--archive", default="", help="historical crash archive tar.gz; latest archive is used when omitted")
    parser.add_argument("--configs", default="configs")
    parser.add_argument("--output-json", required=True)
    parser.add_argument("--output-md", required=True)
    args = parser.parse_args()

    root = Path(args.project_root).resolve()
    archive = Path(args.archive).resolve() if args.archive else _latest_archive(root / "findings")
    if not archive or not archive.exists():
        raise SystemExit("historical crash archive not found")

    evidence_paths = _archive_names(archive)
    targets = _load_targets(root / args.configs)
    rows = [_family_row(root, family, evidence_paths, targets) for family in FAMILIES]
    payload = {
        "project_root": str(root),
        "archive": str(archive),
        "evidence_path_count": len(evidence_paths),
        "rows": rows,
    }

    Path(args.output_json).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output_json).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    Path(args.output_md).write_text(_render_md(payload), encoding="utf-8")
    print(json.dumps({"archive": str(archive), "rows": len(rows), "output_json": args.output_json, "output_md": args.output_md}, indent=2))
    return 0


def _latest_archive(findings: Path) -> Path | None:
    archives = sorted(findings.glob("2026-06-06-historical-crash-archive-*.tar.gz"), key=lambda path: path.stat().st_mtime)
    return archives[-1] if archives else None


def _archive_names(archive: Path) -> list[str]:
    with tarfile.open(archive, "r:gz") as tar:
        return [member.name for member in tar.getmembers()]


def _load_targets(configs: Path) -> list[dict[str, Any]]:
    targets: list[dict[str, Any]] = []
    for path in sorted(configs.glob("parser_targets*.yaml")) + sorted(configs.glob("targets.yaml")):
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except Exception:
            continue
        for item in data.get("targets", []) or []:
            record = dict(item)
            record["config_path"] = str(path)
            targets.append(record)
    return targets


def _family_row(root: Path, family: Family, evidence_paths: list[str], targets: list[dict[str, Any]]) -> dict[str, Any]:
    needles = tuple(needle.lower() for needle in family.needles)
    matches = [path for path in evidence_paths if any(needle in path.lower() for needle in needles)]
    target_matches = [
        target for target in targets if _target_matches(target, needles)
    ]
    afl_binaries = sorted(_afl_binaries_for(root, target_matches))
    reachability = "low"
    if target_matches and afl_binaries:
        reachability = "high"
    elif target_matches:
        reachability = "medium"
    elif matches:
        reachability = "needs-harness"
    return {
        "family_id": family.family_id,
        "title": family.title,
        "historical_evidence_count": len(matches),
        "historical_evidence_examples": matches[:8],
        "configured_targets": [
            {
                "id": target.get("id", ""),
                "config_path": target.get("config_path", ""),
                "filter_binary": target.get("filter_binary", ""),
                "document_kind": target.get("document_kind", ""),
                "ppd_kind": target.get("ppd_kind", ""),
            }
            for target in target_matches[:12]
        ],
        "afl_binaries": afl_binaries,
        "reachability": reachability,
        "required_harness": family.required_harness,
        "notes": family.notes,
    }


def _target_matches(target: dict[str, Any], needles: tuple[str, ...]) -> bool:
    text = " ".join(
        str(target.get(key, ""))
        for key in ("id", "description", "filter_binary", "document_kind", "ppd_kind", "input_mime")
    ).lower()
    return any(needle in text for needle in needles)


def _afl_binaries_for(root: Path, targets: list[dict[str, Any]]) -> set[str]:
    binaries: set[str] = set()
    filter_root = root / "work" / "afl-builds" / "cups-filters"
    for target in targets:
        binary = str(target.get("filter_binary", ""))
        name = Path(binary).name
        if name and (filter_root / name).exists():
            binaries.add(str(filter_root / name))
    if (root / "work" / "afl" / "bin" / "pwg_bundle_harness").exists():
        for target in targets:
            if "pwg" in str(target.get("id", "")):
                binaries.add(str(root / "work" / "afl" / "bin" / "pwg_bundle_harness"))
    return binaries


def _render_md(payload: dict[str, Any]) -> str:
    lines = [
        "# Historical Crash Reachability Matrix",
        "",
        f"- Archive: `{payload['archive']}`",
        f"- Evidence paths scanned: `{payload['evidence_path_count']}`",
        "",
        "| Family | Evidence | Configured Targets | AFL++ Binaries | Reachability | Harness |",
        "|---|---:|---:|---:|---|---|",
    ]
    for row in payload["rows"]:
        lines.append(
            "| {title} | {evidence} | {targets} | {binaries} | {reachability} | {harness} |".format(
                title=row["title"],
                evidence=row["historical_evidence_count"],
                targets=len(row["configured_targets"]),
                binaries=len(row["afl_binaries"]),
                reachability=row["reachability"],
                harness=row["required_harness"],
            )
        )
    lines.extend(["", "## Notes", ""])
    for row in payload["rows"]:
        lines.append(f"### {row['title']}")
        lines.append("")
        lines.append(f"- Reachability: `{row['reachability']}`")
        lines.append(f"- Notes: {row['notes']}")
        if row["historical_evidence_examples"]:
            lines.append("- Evidence examples:")
            for example in row["historical_evidence_examples"][:5]:
                lines.append(f"  - `{example}`")
        if row["configured_targets"]:
            lines.append("- Target examples:")
            for target in row["configured_targets"][:5]:
                lines.append(f"  - `{target['id']}` via `{target['filter_binary']}`")
        lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
