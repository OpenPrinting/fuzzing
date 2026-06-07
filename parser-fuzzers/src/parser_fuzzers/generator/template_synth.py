from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from parser_fuzzers.z3_guard import Z3_LOCK

try:
    import z3
except ImportError:  # pragma: no cover - exercised only in minimal environments
    z3 = None


PPD_SYNTH_PERIOD = 240
CUPS_RASTER_SYNTH_PERIOD = 192
PWG_RASTER_SYNTH_PERIOD = 160
IMAGE_SYNTH_PERIOD = 72

CUPS_WIDTHS = [1, 2, 3, 4, 7, 8, 9, 15, 16, 17, 31, 32, 33, 48, 63, 64, 65, 96, 127, 128, 129, 255]
CUPS_HEIGHTS = [1, 2, 3, 4, 5, 8]
CUPS_RESOLUTIONS = [72, 75, 100, 150, 203, 300, 360, 600, 720, 1200, 2400]
CUPS_COLOR_MODES = [
    (3, 1, 8),
    (18, 1, 8),
    (1, 3, 24),
    (6, 4, 32),
    (1, 3, 32),
    (18, 1, 16),
]

PWG_WIDTHS = [1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64, 65, 127, 128, 129, 255]
PWG_HEIGHTS = [1, 2, 3, 4, 8]
PWG_BPP = [1, 8, 16, 24, 32]
PWG_RESOLUTIONS = [72, 150, 203, 300, 360, 600, 720, 1200, 2400, 32768, 65535, 2147483647]

IMAGE_FORMATS = ["png_rgb", "png_gray", "ppm", "pgm", "pbm"]
IMAGE_WIDTHS = [1, 2, 3, 4, 7, 8, 9, 15, 16, 17, 31, 32, 63, 64]
IMAGE_HEIGHTS = [1, 2, 3, 4, 5, 8]

PAGE_SIZE_COUNT = 4
COLOR_MODEL_COUNT = 4
QUALITY_COUNT = 4
MEDIA_COUNT = 4
DUPLEX_COUNT = 3
PPD_RESOLUTIONS = [72, 75, 100, 150, 203, 300, 360, 600, 720, 1200, 2400, 65535]


@dataclass(frozen=True)
class CUPSRasterSlots:
    width: int
    height: int
    compression: int
    num_colors: int
    color_space: int
    color_order: int
    bits_per_pixel: int
    pages: int
    x_res: int
    y_res: int


@dataclass(frozen=True)
class PWGRasterSlots:
    width: int
    height: int
    bits_per_pixel: int
    x_res: int
    y_res: int
    pages: int


@dataclass(frozen=True)
class ImageSlots:
    image_format: str
    width: int
    height: int
    channels: int


@dataclass(frozen=True)
class PPDSlots:
    page_size_index: int
    color_model_index: int
    quality_index: int
    media_index: int
    duplex_index: int
    resolution: int


def synthesize_cups_raster_slots(case_index: int) -> CUPSRasterSlots:
    with Z3_LOCK:
        return _synthesize_cups_raster_slot(case_index % CUPS_RASTER_SYNTH_PERIOD)


@lru_cache(maxsize=None)
def _synthesize_cups_raster_slot(slot: int) -> CUPSRasterSlots:
    fallback = _fallback_cups(slot)
    if z3 is None:
        return fallback
    width = z3.Int("width")
    height = z3.Int("height")
    compression = z3.Int("compression")
    color_space = z3.Int("color_space")
    num_colors = z3.Int("num_colors")
    bits_per_pixel = z3.Int("bits_per_pixel")
    color_order = z3.Int("color_order")
    pages = z3.Int("pages")
    x_res = z3.Int("x_res")
    y_res = z3.Int("y_res")
    bytes_per_line = z3.Int("bytes_per_line")
    raw_bpl = (width * bits_per_pixel + 7) / 8

    solver = z3.Solver()
    _domain(solver, width, CUPS_WIDTHS)
    _domain(solver, height, CUPS_HEIGHTS)
    _domain(solver, compression, [0, 0, 0, 1, 10])
    _domain(solver, color_order, [0, 0, 1])
    _domain(solver, pages, [1, 1, 2, 3])
    _domain(solver, x_res, CUPS_RESOLUTIONS)
    _domain(solver, y_res, CUPS_RESOLUTIONS)
    solver.add(
        z3.Or(
            *[
                z3.And(color_space == cs, num_colors == colors, bits_per_pixel == bpp)
                for cs, colors, bpp in CUPS_COLOR_MODES
            ]
        )
    )
    solver.add(bytes_per_line >= raw_bpl)
    solver.add(bytes_per_line <= raw_bpl + 7)
    solver.add(bytes_per_line % 8 == 0)
    solver.add(width == CUPS_WIDTHS[(slot * 7 + slot // 5) % len(CUPS_WIDTHS)])
    solver.add(height == CUPS_HEIGHTS[(slot * 5 + slot // 11) % len(CUPS_HEIGHTS)])
    cs, colors, bpp = CUPS_COLOR_MODES[(slot * 3 + slot // 7) % len(CUPS_COLOR_MODES)]
    solver.add(color_space == cs, num_colors == colors, bits_per_pixel == bpp)
    solver.add(x_res == CUPS_RESOLUTIONS[(slot * 3 + 1) % len(CUPS_RESOLUTIONS)])
    solver.add(y_res == CUPS_RESOLUTIONS[(slot * 5 + 2) % len(CUPS_RESOLUTIONS)])
    solver.add(compression == [0, 0, 0, 1, 10][slot % 5])
    solver.add(pages == [1, 2, 1, 3][slot % 4])
    solver.add(color_order == [0, 0, 1][slot % 3])
    if solver.check() != z3.sat:
        return fallback
    model = solver.model()
    return CUPSRasterSlots(
        width=_model_int(model, width),
        height=_model_int(model, height),
        compression=_model_int(model, compression),
        num_colors=_model_int(model, num_colors),
        color_space=_model_int(model, color_space),
        color_order=_model_int(model, color_order),
        bits_per_pixel=_model_int(model, bits_per_pixel),
        pages=_model_int(model, pages),
        x_res=_model_int(model, x_res),
        y_res=_model_int(model, y_res),
    )


def synthesize_pwg_raster_slots(case_index: int) -> PWGRasterSlots:
    with Z3_LOCK:
        return _synthesize_pwg_raster_slot(case_index % PWG_RASTER_SYNTH_PERIOD)


@lru_cache(maxsize=None)
def _synthesize_pwg_raster_slot(slot: int) -> PWGRasterSlots:
    fallback = _fallback_pwg(slot)
    if z3 is None:
        return fallback
    width = z3.Int("width")
    height = z3.Int("height")
    bits_per_pixel = z3.Int("bits_per_pixel")
    x_res = z3.Int("x_res")
    y_res = z3.Int("y_res")
    pages = z3.Int("pages")
    row_bytes = z3.Int("row_bytes")

    solver = z3.Solver()
    _domain(solver, width, PWG_WIDTHS)
    _domain(solver, height, PWG_HEIGHTS)
    _domain(solver, bits_per_pixel, PWG_BPP)
    _domain(solver, x_res, PWG_RESOLUTIONS)
    _domain(solver, y_res, PWG_RESOLUTIONS)
    _domain(solver, pages, [1, 1, 2, 3])
    solver.add(row_bytes == (width * bits_per_pixel + 7) / 8)
    solver.add(row_bytes >= 1)
    solver.add(width == PWG_WIDTHS[(slot * 5 + slot // 3) % len(PWG_WIDTHS)])
    solver.add(height == PWG_HEIGHTS[(slot * 7 + slot // 13) % len(PWG_HEIGHTS)])
    solver.add(bits_per_pixel == PWG_BPP[(slot * 3 + slot // 17) % len(PWG_BPP)])
    solver.add(x_res == PWG_RESOLUTIONS[(slot * 2 + 3) % len(PWG_RESOLUTIONS)])
    solver.add(y_res == PWG_RESOLUTIONS[(slot * 5 + 1) % len(PWG_RESOLUTIONS)])
    solver.add(pages == [1, 2, 1, 3][slot % 4])
    if solver.check() != z3.sat:
        return fallback
    model = solver.model()
    return PWGRasterSlots(
        width=_model_int(model, width),
        height=_model_int(model, height),
        bits_per_pixel=_model_int(model, bits_per_pixel),
        x_res=_model_int(model, x_res),
        y_res=_model_int(model, y_res),
        pages=_model_int(model, pages),
    )


def synthesize_image_slots(case_index: int) -> ImageSlots:
    with Z3_LOCK:
        return _synthesize_image_slot(case_index % IMAGE_SYNTH_PERIOD)


@lru_cache(maxsize=None)
def _synthesize_image_slot(slot: int) -> ImageSlots:
    fallback = _fallback_image(slot)
    if z3 is None:
        return fallback
    format_index = z3.Int("format_index")
    width = z3.Int("width")
    height = z3.Int("height")
    channels = z3.Int("channels")
    solver = z3.Solver()
    _domain(solver, format_index, list(range(len(IMAGE_FORMATS))))
    _domain(solver, width, IMAGE_WIDTHS)
    _domain(solver, height, IMAGE_HEIGHTS)
    solver.add(format_index == slot % len(IMAGE_FORMATS))
    solver.add(width == IMAGE_WIDTHS[(slot * 7 + 3) % len(IMAGE_WIDTHS)])
    solver.add(height == IMAGE_HEIGHTS[(slot * 5 + 1) % len(IMAGE_HEIGHTS)])
    solver.add(
        z3.Or(
            z3.And(format_index == 0, channels == 3),
            z3.And(format_index == 1, channels == 1),
            z3.And(format_index == 2, channels == 3),
            z3.And(format_index == 3, channels == 1),
            z3.And(format_index == 4, channels == 1),
        )
    )
    if solver.check() != z3.sat:
        return fallback
    model = solver.model()
    fmt_index = _model_int(model, format_index)
    return ImageSlots(
        image_format=IMAGE_FORMATS[fmt_index],
        width=_model_int(model, width),
        height=_model_int(model, height),
        channels=_model_int(model, channels),
    )


def synthesize_ppd_slots(case_index: int) -> PPDSlots:
    with Z3_LOCK:
        return _synthesize_ppd_slot(case_index % PPD_SYNTH_PERIOD)


@lru_cache(maxsize=None)
def _synthesize_ppd_slot(slot: int) -> PPDSlots:
    fallback = _fallback_ppd(slot)
    if z3 is None:
        return fallback
    page_size_index = z3.Int("page_size_index")
    color_model_index = z3.Int("color_model_index")
    quality_index = z3.Int("quality_index")
    media_index = z3.Int("media_index")
    duplex_index = z3.Int("duplex_index")
    resolution = z3.Int("resolution")
    solver = z3.Solver()
    _domain(solver, page_size_index, list(range(PAGE_SIZE_COUNT)))
    _domain(solver, color_model_index, list(range(COLOR_MODEL_COUNT)))
    _domain(solver, quality_index, list(range(QUALITY_COUNT)))
    _domain(solver, media_index, list(range(MEDIA_COUNT)))
    _domain(solver, duplex_index, list(range(DUPLEX_COUNT)))
    _domain(solver, resolution, PPD_RESOLUTIONS)
    solver.add(page_size_index == (slot * 5 + slot // 13) % PAGE_SIZE_COUNT)
    solver.add(color_model_index == (slot * 3 + slot // 7) % COLOR_MODEL_COUNT)
    solver.add(quality_index == (slot * 5 + 1) % QUALITY_COUNT)
    solver.add(media_index == (slot * 7 + 2) % MEDIA_COUNT)
    solver.add(duplex_index == (slot * 11 + slot // 17) % DUPLEX_COUNT)
    solver.add(resolution == PPD_RESOLUTIONS[(slot * 7 + 3) % len(PPD_RESOLUTIONS)])
    if solver.check() != z3.sat:
        return fallback
    model = solver.model()
    return PPDSlots(
        page_size_index=_model_int(model, page_size_index),
        color_model_index=_model_int(model, color_model_index),
        quality_index=_model_int(model, quality_index),
        media_index=_model_int(model, media_index),
        duplex_index=_model_int(model, duplex_index),
        resolution=_model_int(model, resolution),
    )


def _domain(solver: Any, variable: Any, values: list[int]) -> None:
    solver.add(z3.Or(*[variable == value for value in sorted(set(values))]))


def _model_int(model: Any, variable: Any) -> int:
    return int(model.evaluate(variable, model_completion=True).as_long())


def _fallback_cups(slot: int) -> CUPSRasterSlots:
    color_space, num_colors, bits_per_pixel = CUPS_COLOR_MODES[(slot * 3 + slot // 7) % len(CUPS_COLOR_MODES)]
    return CUPSRasterSlots(
        width=CUPS_WIDTHS[(slot * 7 + slot // 5) % len(CUPS_WIDTHS)],
        height=CUPS_HEIGHTS[(slot * 5 + slot // 11) % len(CUPS_HEIGHTS)],
        compression=[0, 0, 0, 1, 10][slot % 5],
        num_colors=num_colors,
        color_space=color_space,
        color_order=[0, 0, 1][slot % 3],
        bits_per_pixel=bits_per_pixel,
        pages=[1, 2, 1, 3][slot % 4],
        x_res=CUPS_RESOLUTIONS[(slot * 3 + 1) % len(CUPS_RESOLUTIONS)],
        y_res=CUPS_RESOLUTIONS[(slot * 5 + 2) % len(CUPS_RESOLUTIONS)],
    )


def _fallback_pwg(slot: int) -> PWGRasterSlots:
    return PWGRasterSlots(
        width=PWG_WIDTHS[(slot * 5 + slot // 3) % len(PWG_WIDTHS)],
        height=PWG_HEIGHTS[(slot * 7 + slot // 13) % len(PWG_HEIGHTS)],
        bits_per_pixel=PWG_BPP[(slot * 3 + slot // 17) % len(PWG_BPP)],
        x_res=PWG_RESOLUTIONS[(slot * 2 + 3) % len(PWG_RESOLUTIONS)],
        y_res=PWG_RESOLUTIONS[(slot * 5 + 1) % len(PWG_RESOLUTIONS)],
        pages=[1, 2, 1, 3][slot % 4],
    )


def _fallback_image(slot: int) -> ImageSlots:
    fmt_index = slot % len(IMAGE_FORMATS)
    image_format = IMAGE_FORMATS[fmt_index]
    channels = 3 if image_format in {"png_rgb", "ppm"} else 1
    return ImageSlots(
        image_format=image_format,
        width=IMAGE_WIDTHS[(slot * 7 + 3) % len(IMAGE_WIDTHS)],
        height=IMAGE_HEIGHTS[(slot * 5 + 1) % len(IMAGE_HEIGHTS)],
        channels=channels,
    )


def _fallback_ppd(slot: int) -> PPDSlots:
    return PPDSlots(
        page_size_index=(slot * 5 + slot // 13) % PAGE_SIZE_COUNT,
        color_model_index=(slot * 3 + slot // 7) % COLOR_MODEL_COUNT,
        quality_index=(slot * 5 + 1) % QUALITY_COUNT,
        media_index=(slot * 7 + 2) % MEDIA_COUNT,
        duplex_index=(slot * 11 + slot // 17) % DUPLEX_COUNT,
        resolution=PPD_RESOLUTIONS[(slot * 7 + 3) % len(PPD_RESOLUTIONS)],
    )
