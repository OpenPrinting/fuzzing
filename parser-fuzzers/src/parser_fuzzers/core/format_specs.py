from __future__ import annotations

from dataclasses import dataclass


IMAGE_FORMATS = ("png_gray", "png_rgb", "png_rgba", "ppm", "pgm", "pbm")


@dataclass(frozen=True)
class ImageGoal:
    name: str
    target_family: str
    output_format: str
    allowed_formats: tuple[str, ...]
    min_width: int = 1
    min_height: int = 1
    min_area: int = 1
    max_width: int = 1024
    max_height: int = 256
    aspect: str = "any"
    payload_policy: str = "exact"
    maxval_class: str = "byte"
    png_interlace: int = 0
    comment_style: int | None = None


IMAGE_GOALS: tuple[ImageGoal, ...] = (
    ImageGoal(
        name="pdf-single-image",
        target_family="imagetopdf",
        output_format="pdf",
        allowed_formats=("png_rgb", "png_rgba", "ppm"),
        min_width=96,
        min_height=16,
        min_area=3072,
    ),
    ImageGoal(
        name="pdf-wide-image",
        target_family="imagetopdf",
        output_format="pdf",
        allowed_formats=("png_rgb", "ppm"),
        min_width=256,
        min_height=8,
        aspect="wide",
    ),
    ImageGoal(
        name="pdf-tall-image",
        target_family="imagetopdf",
        output_format="pdf",
        allowed_formats=("png_gray", "pgm"),
        min_width=32,
        min_height=96,
        aspect="tall",
    ),
    ImageGoal(
        name="pdf-alpha-image",
        target_family="imagetopdf",
        output_format="pdf",
        allowed_formats=("png_rgba",),
        min_width=64,
        min_height=32,
    ),
    ImageGoal(
        name="pdf-gray-image",
        target_family="imagetopdf",
        output_format="pdf",
        allowed_formats=("png_gray", "pgm"),
        min_width=128,
        min_height=16,
    ),
    ImageGoal(
        name="pdf-bitmap-image",
        target_family="imagetopdf",
        output_format="pdf",
        allowed_formats=("pbm",),
        min_width=63,
        min_height=31,
        comment_style=1,
    ),
    ImageGoal(
        name="pdf-interlaced-png",
        target_family="imagetopdf",
        output_format="pdf",
        allowed_formats=("png_rgb", "png_rgba"),
        min_width=96,
        min_height=32,
        png_interlace=1,
    ),
    ImageGoal(
        name="pdf-wide-maxval",
        target_family="imagetopdf",
        output_format="pdf",
        allowed_formats=("ppm", "pgm"),
        min_width=96,
        min_height=16,
        maxval_class="wide",
    ),
    ImageGoal(
        name="pdf-low-maxval",
        target_family="imagetopdf",
        output_format="pdf",
        allowed_formats=("ppm", "pgm"),
        min_width=127,
        min_height=17,
        maxval_class="low",
    ),
    ImageGoal(
        name="pdf-large-rgb",
        target_family="imagetopdf",
        output_format="pdf",
        allowed_formats=("png_rgb", "ppm"),
        min_width=512,
        min_height=64,
        min_area=32768,
    ),
    ImageGoal(
        name="ps-showpage-image",
        target_family="imagetops",
        output_format="postscript",
        allowed_formats=("png_rgb", "png_rgba", "ppm"),
        min_width=96,
        min_height=16,
        min_area=3072,
    ),
    ImageGoal(
        name="ps-wide-image",
        target_family="imagetops",
        output_format="postscript",
        allowed_formats=("png_rgb", "ppm"),
        min_width=256,
        min_height=8,
        aspect="wide",
    ),
    ImageGoal(
        name="ps-tall-image",
        target_family="imagetops",
        output_format="postscript",
        allowed_formats=("png_gray", "pgm"),
        min_width=32,
        min_height=96,
        aspect="tall",
    ),
    ImageGoal(
        name="ps-commented-pnm",
        target_family="imagetops",
        output_format="postscript",
        allowed_formats=("ppm", "pgm", "pbm"),
        min_width=64,
        min_height=32,
        comment_style=1,
    ),
    ImageGoal(
        name="ps-alpha-image",
        target_family="imagetops",
        output_format="postscript",
        allowed_formats=("png_rgba",),
        min_width=64,
        min_height=32,
    ),
    ImageGoal(
        name="ps-gray-image",
        target_family="imagetops",
        output_format="postscript",
        allowed_formats=("png_gray", "pgm"),
        min_width=128,
        min_height=16,
    ),
    ImageGoal(
        name="ps-bitmap-image",
        target_family="imagetops",
        output_format="postscript",
        allowed_formats=("pbm",),
        min_width=63,
        min_height=31,
        comment_style=1,
    ),
    ImageGoal(
        name="ps-interlaced-png",
        target_family="imagetops",
        output_format="postscript",
        allowed_formats=("png_rgb", "png_rgba"),
        min_width=96,
        min_height=32,
        png_interlace=1,
    ),
    ImageGoal(
        name="ps-wide-maxval",
        target_family="imagetops",
        output_format="postscript",
        allowed_formats=("ppm", "pgm"),
        min_width=127,
        min_height=17,
        maxval_class="wide",
    ),
    ImageGoal(
        name="ps-large-rgb",
        target_family="imagetops",
        output_format="postscript",
        allowed_formats=("png_rgb", "ppm"),
        min_width=512,
        min_height=64,
        min_area=32768,
    ),
    ImageGoal(
        name="raster-rgb24",
        target_family="imagetoraster",
        output_format="cups-raster",
        allowed_formats=("png_rgb", "ppm"),
        min_width=96,
        min_height=16,
        min_area=3072,
    ),
    ImageGoal(
        name="raster-alpha32",
        target_family="imagetoraster",
        output_format="cups-raster",
        allowed_formats=("png_rgba",),
        min_width=64,
        min_height=32,
    ),
    ImageGoal(
        name="raster-gray8",
        target_family="imagetoraster",
        output_format="cups-raster",
        allowed_formats=("png_gray", "pgm"),
        min_width=96,
        min_height=16,
    ),
    ImageGoal(
        name="raster-wide-rows",
        target_family="imagetoraster",
        output_format="cups-raster",
        allowed_formats=("png_rgb", "ppm"),
        min_width=256,
        min_height=8,
        aspect="wide",
    ),
    ImageGoal(
        name="raster-boundary-pnm",
        target_family="imagetoraster",
        output_format="cups-raster",
        allowed_formats=("ppm", "pgm", "pbm"),
        min_width=31,
        min_height=31,
        comment_style=1,
    ),
    ImageGoal(
        name="raster-bitmap-rows",
        target_family="imagetoraster",
        output_format="cups-raster",
        allowed_formats=("pbm",),
        min_width=63,
        min_height=31,
        comment_style=1,
    ),
    ImageGoal(
        name="raster-interlaced-png",
        target_family="imagetoraster",
        output_format="cups-raster",
        allowed_formats=("png_rgb", "png_rgba"),
        min_width=96,
        min_height=32,
        png_interlace=1,
    ),
    ImageGoal(
        name="raster-wide-maxval",
        target_family="imagetoraster",
        output_format="cups-raster",
        allowed_formats=("ppm", "pgm"),
        min_width=127,
        min_height=17,
        maxval_class="wide",
    ),
    ImageGoal(
        name="raster-low-maxval",
        target_family="imagetoraster",
        output_format="cups-raster",
        allowed_formats=("ppm", "pgm"),
        min_width=127,
        min_height=17,
        maxval_class="low",
    ),
    ImageGoal(
        name="raster-large-rgb",
        target_family="imagetoraster",
        output_format="cups-raster",
        allowed_formats=("png_rgb", "ppm"),
        min_width=512,
        min_height=64,
        min_area=32768,
    ),
)


def image_goals_for_target(target_id: str) -> tuple[ImageGoal, ...]:
    family = _target_family(target_id)
    goals = tuple(goal for goal in IMAGE_GOALS if goal.target_family == family)
    return goals or IMAGE_GOALS


def image_format_id(image_format: str) -> int:
    try:
        return IMAGE_FORMATS.index(image_format)
    except ValueError:
        return 0


def image_channels(image_format: str) -> int:
    if image_format in {"png_rgb", "ppm"}:
        return 3
    if image_format == "png_rgba":
        return 4
    return 1


def maxval_for_class(image_format: str, maxval_class: str, salt: int) -> int:
    if image_format == "pbm":
        return 1
    if maxval_class == "wide":
        return 65535
    if maxval_class == "low":
        return [1, 2, 15, 31][salt % 4]
    return [127, 255][salt % 2]


def _target_family(target_id: str) -> str:
    if "imagetopdf" in target_id:
        return "imagetopdf"
    if "imagetops" in target_id:
        return "imagetops"
    if "imagetoraster" in target_id:
        return "imagetoraster"
    for suffix in ("_coverage", "_general", "_explore", "_structural", "_feedback"):
        if target_id.endswith(suffix):
            return target_id.removesuffix(suffix)
    return target_id
