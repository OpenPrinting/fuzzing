from __future__ import annotations

import zlib
import struct
from dataclasses import dataclass


HEADER_SIZE = 1796
SYNC_CUPS_RASTER_V3 = b"3SaR"
SYNC_PWG_RASTER = b"2SaR"

OFF_MEDIA_CLASS = 0
OFF_MEDIA_TYPE = 128
OFF_OUTPUT_TYPE = 192
OFF_HW_RESOLUTION = 276
OFF_IMAGING_BBOX = 284
OFF_MARGINS = 312
OFF_PAGE_SIZE = 352
OFF_CUPS_WIDTH = 372
OFF_CUPS_HEIGHT = 376
OFF_CUPS_BITS_PER_COLOR = 384
OFF_CUPS_BITS_PER_PIXEL = 388
OFF_CUPS_BYTES_PER_LINE = 392
OFF_CUPS_COLOR_ORDER = 396
OFF_CUPS_COLOR_SPACE = 400
OFF_CUPS_COMPRESSION = 404
OFF_CUPS_ROW_COUNT = 408
OFF_CUPS_NUM_COLORS = 420
OFF_CUPS_PAGE_SIZE = 428
OFF_CUPS_IMAGING_BBOX = 436
OFF_CUPS_PAGE_SIZE_NAME = 1732

CUPS_CSPACE_RGB = 1
CUPS_CSPACE_K = 3
CUPS_CSPACE_CMYK = 6
CUPS_CSPACE_SW = 18

RASTER_BOUNDARY_CASES = [
    (8, 1, 0, 1),
    (16, 1, 0, 3),
    (9, 1, 1, 3),
    (11, 1, 10, 3),
    (14, 1, 10, 3),
    (5, 6, 10, 3),
    (31, 1, 0, 1),
    (64, 2, 0, 3),
]

RASTER_GENERAL_CASES = [
    (1, 1, 0, 1),
    (8, 1, 0, 1),
    (16, 1, 0, 1),
    (32, 2, 0, 1),
    (64, 4, 0, 1),
    (127, 1, 0, 1),
    (255, 2, 0, 1),
    (8, 1, 0, 3),
    (16, 2, 0, 3),
    (31, 3, 0, 3),
    (64, 1, 0, 3),
    (128, 4, 0, 3),
]

RASTER_COVERAGE_CASES = [
    # width, height, compression, num_colors, color_space, color_order, bits_per_pixel, pages, x_res, y_res
    (1, 1, 0, 1, CUPS_CSPACE_K, 0, 8, 1, 300, 300),
    (8, 1, 0, 1, CUPS_CSPACE_SW, 0, 8, 2, 300, 300),
    (16, 2, 0, 1, CUPS_CSPACE_K, 0, 8, 1, 600, 300),
    (32, 1, 0, 3, CUPS_CSPACE_RGB, 0, 24, 1, 300, 600),
    (48, 3, 0, 3, CUPS_CSPACE_RGB, 0, 24, 2, 203, 203),
    (63, 1, 0, 4, CUPS_CSPACE_CMYK, 0, 32, 1, 360, 360),
    (65, 2, 0, 1, CUPS_CSPACE_SW, 0, 8, 3, 720, 360),
    (127, 1, 0, 3, CUPS_CSPACE_RGB, 0, 24, 1, 1200, 600),
    (255, 2, 0, 1, CUPS_CSPACE_K, 0, 8, 1, 75, 75),
    (17, 4, 0, 3, CUPS_CSPACE_RGB, 0, 24, 2, 100, 100),
    (33, 1, 0, 1, CUPS_CSPACE_SW, 0, 8, 1, 150, 300),
    (96, 2, 0, 4, CUPS_CSPACE_CMYK, 0, 32, 1, 600, 1200),
    (12, 1, 1, 3, CUPS_CSPACE_RGB, 0, 24, 1, 300, 300),
    (24, 2, 10, 3, CUPS_CSPACE_RGB, 0, 24, 1, 300, 300),
]

PWG_BOUNDARY_CASES = [
    (8, 1, 8, 300),
    (16, 1, 1, 600),
    (3, 2, 8, 1200),
    (11, 1, 24, 65535),
    (4, 4, 16, 65536),
    (7, 2, 16, 2147483647),
    (13, 1, 8, 4294967295),
    (5, 6, 16, 2147483648),
]

PWG_GENERAL_CASES = [
    (1, 1, 8, 72),
    (8, 1, 8, 150),
    (16, 2, 8, 203),
    (32, 4, 8, 300),
    (64, 1, 8, 600),
    (127, 2, 8, 1200),
    (255, 1, 8, 2400),
    (8, 1, 16, 300),
    (16, 2, 16, 600),
    (31, 3, 16, 1200),
    (64, 1, 16, 65535),
    (128, 2, 16, 65536),
    (8, 1, 24, 300),
    (16, 2, 24, 600),
    (31, 1, 32, 1200),
]

PWG_COVERAGE_CASES = [
    # width, height, bits_per_pixel, y_res, pages
    (1, 1, 8, 72, 1),
    (8, 2, 8, 150, 2),
    (16, 1, 16, 203, 1),
    (32, 3, 8, 300, 2),
    (64, 1, 16, 600, 1),
    (127, 2, 8, 1200, 1),
    (255, 1, 24, 2400, 1),
    (31, 3, 32, 1200, 2),
    (65, 4, 16, 65535, 1),
    (129, 1, 8, 32768, 1),
]

PDF_COVERAGE_CASES = [
    # media box, body text
    ((0, 0, 200, 200), "SMT PDF smoke"),
    ((0, 0, 612, 792), "Letter page"),
    ((0, 0, 144, 144), "Small page"),
    ((0, 0, 1008, 612), "Wide page"),
]

IMAGE_COVERAGE_CASES = [
    # format, width, height, channels
    ("png_rgb", 4, 4, 3),
    ("png_gray", 9, 2, 1),
    ("ppm", 1, 1, 3),
    ("ppm", 8, 2, 3),
    ("pgm", 16, 1, 1),
    ("pbm", 17, 3, 1),
]

TEXT_COVERAGE_CASES = [
    b"SMT text parser smoke\n",
    b"Header: value\n\nBody line 1\nBody line 2\n",
    b"\tIndented\tcolumns\t12345\n",
    b"A" * 256 + b"\n",
    b"%%Title: looks-like-postscript-but-text\nplain\n",
]

POSTSCRIPT_COVERAGE_CASES = [
    b"%!PS-Adobe-3.0\n%%Pages: 1\nshowpage\n",
    b"%!PS-Adobe-3.0\n%%BoundingBox: 0 0 144 144\n/newpath { } def\nshowpage\n",
    b"%!PS\n72 72 moveto (SMT PostScript) show\nshowpage\n",
    b"%!PS-Adobe-3.0\n%%Pages: 2\n%%Page: 1 1\nshowpage\n%%Page: 2 2\nshowpage\n",
]

COMMAND_COVERAGE_CASES = [
    b"#CUPS-COMMAND\nReportLevels\n",
    b"#CUPS-COMMAND\nClean\n",
    b"#CUPS-COMMAND\nPrintSelfTestPage\n",
    b"#CUPS-COMMAND\nPrintAlignmentPage 1\n",
    b"#CUPS-COMMAND\nSetAlignment 0 0\nUnknownCommand\n",
]


@dataclass(frozen=True)
class DocumentCase:
    kind: str
    data: bytes
    mime: str
    description: str
    extension: str = ".bin"


def make_document(kind: str, case_index: int) -> DocumentCase:
    if kind == "text":
        return DocumentCase(
            kind=kind,
            data=b"SMT multi-target text job\n",
            mime="text/plain",
            description="minimal text job",
            extension=".txt",
        )
    if kind == "text_coverage_sweep":
        data = TEXT_COVERAGE_CASES[case_index % len(TEXT_COVERAGE_CASES)]
        return DocumentCase(
            kind=kind,
            data=data,
            mime="text/plain",
            description="coverage-oriented text input",
            extension=".txt",
        )
    if kind == "postscript":
        return DocumentCase(
            kind=kind,
            data=b"%!PS-Adobe-3.0\n%%Pages: 1\nshowpage\n",
            mime="application/postscript",
            description="minimal PostScript job",
            extension=".ps",
        )
    if kind == "postscript_coverage_sweep":
        data = POSTSCRIPT_COVERAGE_CASES[case_index % len(POSTSCRIPT_COVERAGE_CASES)]
        return DocumentCase(
            kind=kind,
            data=data,
            mime="application/postscript",
            description="coverage-oriented PostScript input",
            extension=".ps",
        )
    if kind == "pdf_coverage_sweep":
        media_box, text = PDF_COVERAGE_CASES[case_index % len(PDF_COVERAGE_CASES)]
        return DocumentCase(
            kind=kind,
            data=make_pdf(media_box=media_box, text=text),
            mime="application/pdf",
            description="coverage-oriented PDF input",
            extension=".pdf",
        )
    if kind == "image_coverage_sweep":
        image_format, width, height, channels = IMAGE_COVERAGE_CASES[case_index % len(IMAGE_COVERAGE_CASES)]
        extension = ".png" if image_format.startswith("png") else {
            "ppm": ".ppm",
            "pgm": ".pgm",
            "pbm": ".pbm",
        }[image_format]
        return DocumentCase(
            kind=kind,
            data=make_image(image_format=image_format, width=width, height=height, channels=channels),
            mime="image/png" if image_format.startswith("png") else "image/x-portable-anymap",
            description=f"coverage-oriented {image_format} image",
            extension=extension,
        )
    if kind == "command_coverage_sweep":
        data = COMMAND_COVERAGE_CASES[case_index % len(COMMAND_COVERAGE_CASES)]
        return DocumentCase(
            kind=kind,
            data=data,
            mime="application/vnd.cups-command",
            description="coverage-oriented CUPS command input",
            extension=".cmd",
        )
    if kind == "cups_raster_basic":
        return DocumentCase(
            kind=kind,
            data=make_cups_raster(width=16, height=1, compression=0, num_colors=1),
            mime="application/vnd.cups-raster",
            description="minimal CUPS Raster page",
            extension=".ras",
        )
    if kind == "cups_raster_mode10":
        return DocumentCase(
            kind=kind,
            data=make_cups_raster(width=11 + case_index, height=1, compression=10, num_colors=3),
            mime="application/vnd.cups-raster",
            description="Mode 10 RGB CUPS Raster page",
            extension=".ras",
        )
    if kind == "cups_raster_boundary_sweep":
        width, height, compression, num_colors = RASTER_BOUNDARY_CASES[case_index % len(RASTER_BOUNDARY_CASES)]
        return DocumentCase(
            kind=kind,
            data=make_cups_raster(width=width, height=height, compression=compression, num_colors=num_colors),
            mime="application/vnd.cups-raster",
            description="generic CUPS Raster boundary sweep",
            extension=".ras",
        )
    if kind == "cups_raster_general_sweep":
        width, height, compression, num_colors = RASTER_GENERAL_CASES[case_index % len(RASTER_GENERAL_CASES)]
        return DocumentCase(
            kind=kind,
            data=make_cups_raster(width=width, height=height, compression=compression, num_colors=num_colors),
            mime="application/vnd.cups-raster",
            description="general valid CUPS Raster sweep",
            extension=".ras",
        )
    if kind == "cups_raster_coverage_sweep":
        width, height, compression, num_colors, color_space, color_order, bits_per_pixel, pages, x_res, y_res = (
            RASTER_COVERAGE_CASES[case_index % len(RASTER_COVERAGE_CASES)]
        )
        return DocumentCase(
            kind=kind,
            data=make_cups_raster(
                width=width,
                height=height,
                compression=compression,
                num_colors=num_colors,
                color_space=color_space,
                color_order=color_order,
                bits_per_pixel=bits_per_pixel,
                pages=pages,
                x_res=x_res,
                y_res=y_res,
            ),
            mime="application/vnd.cups-raster",
            description="coverage-oriented CUPS Raster sweep",
            extension=".ras",
        )
    if kind == "pwg_raster_boundary_sweep":
        width, height, bits_per_pixel, y_res = PWG_BOUNDARY_CASES[case_index % len(PWG_BOUNDARY_CASES)]
        return DocumentCase(
            kind=kind,
            data=make_pwg_raster(width=width, height=height, bits_per_pixel=bits_per_pixel, y_res=y_res),
            mime="application/vnd.cups-pwg",
            description="generic PWG Raster boundary sweep",
            extension=".pwg",
        )
    if kind == "pwg_raster_general_sweep":
        width, height, bits_per_pixel, y_res = PWG_GENERAL_CASES[case_index % len(PWG_GENERAL_CASES)]
        return DocumentCase(
            kind=kind,
            data=make_pwg_raster(width=width, height=height, bits_per_pixel=bits_per_pixel, x_res=y_res, y_res=y_res),
            mime="application/vnd.cups-pwg",
            description="general valid PWG Raster sweep",
            extension=".pwg",
        )
    if kind == "pwg_raster_coverage_sweep":
        width, height, bits_per_pixel, y_res, pages = PWG_COVERAGE_CASES[case_index % len(PWG_COVERAGE_CASES)]
        return DocumentCase(
            kind=kind,
            data=make_pwg_raster(
                width=width,
                height=height,
                bits_per_pixel=bits_per_pixel,
                x_res=y_res,
                y_res=y_res,
                pages=pages,
            ),
            mime="application/vnd.cups-pwg",
            description="coverage-oriented PWG Raster sweep",
            extension=".pwg",
        )
    raise ValueError(f"unknown document kind: {kind}")


def make_pdf(*, media_box: tuple[int, int, int, int], text: str) -> bytes:
    escaped = text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    x0, y0, x1, y1 = media_box
    stream = f"BT /F1 12 Tf 24 24 Td ({escaped}) Tj ET\n".encode("ascii")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        (
            f"<< /Type /Page /Parent 2 0 R /MediaBox [{x0} {y0} {x1} {y1}] "
            "/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>"
        ).encode("ascii"),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length " + str(len(stream)).encode("ascii") + b" >>\nstream\n" + stream + b"endstream",
    ]
    output = bytearray(b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n")
    offsets = [0]
    for index, obj in enumerate(objects, start=1):
        offsets.append(len(output))
        output.extend(f"{index} 0 obj\n".encode("ascii"))
        output.extend(obj)
        output.extend(b"\nendobj\n")
    xref_offset = len(output)
    output.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    output.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    output.extend(
        (
            f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
            f"startxref\n{xref_offset}\n%%EOF\n"
        ).encode("ascii")
    )
    return bytes(output)


def make_image(*, image_format: str, width: int, height: int, channels: int) -> bytes:
    if image_format == "ppm":
        header = f"P6\n{width} {height}\n255\n".encode("ascii")
        pixels = bytes((index * 17) & 0xFF for index in range(width * height * 3))
        return header + pixels
    if image_format == "pgm":
        header = f"P5\n{width} {height}\n255\n".encode("ascii")
        pixels = bytes((index * 31) & 0xFF for index in range(width * height))
        return header + pixels
    if image_format == "pbm":
        row_bytes = (width + 7) // 8
        header = f"P4\n{width} {height}\n".encode("ascii")
        pixels = bytes((0xAA ^ row) & 0xFF for row in range(height) for _ in range(row_bytes))
        return header + pixels
    if image_format == "png_rgb":
        return make_png(width=width, height=height, color_type=2, channels=channels)
    if image_format == "png_gray":
        return make_png(width=width, height=height, color_type=0, channels=channels)
    raise ValueError(f"unknown image format: {image_format}")


def make_png(*, width: int, height: int, color_type: int, channels: int) -> bytes:
    bit_depth = 8
    raw = bytearray()
    for y in range(height):
        raw.append(0)  # filter type: None
        for x in range(width):
            if channels == 1:
                raw.append((x * 23 + y * 17) & 0xFF)
            else:
                raw.extend(((x * 31) & 0xFF, (y * 47) & 0xFF, ((x + y) * 19) & 0xFF))
    ihdr = struct.pack(">IIBBBBB", width, height, bit_depth, color_type, 0, 0, 0)
    compressed = zlib.compress(bytes(raw))
    return (
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"IHDR", ihdr)
        + _png_chunk(b"IDAT", compressed)
        + _png_chunk(b"IEND", b"")
    )


def _png_chunk(chunk_type: bytes, payload: bytes) -> bytes:
    crc = zlib.crc32(chunk_type + payload) & 0xFFFFFFFF
    return struct.pack(">I", len(payload)) + chunk_type + payload + struct.pack(">I", crc)


def make_cups_raster(
    *,
    width: int,
    height: int,
    compression: int,
    num_colors: int,
    color_space: int | None = None,
    color_order: int = 0,
    bits_per_pixel: int | None = None,
    pages: int = 1,
    x_res: int = 300,
    y_res: int = 300,
) -> bytes:
    bits_per_color = 8
    bits_per_pixel = bits_per_pixel or max(1, bits_per_color * num_colors)
    raw_bpl = (width * bits_per_pixel + 7) // 8
    cups_bytes_per_line = ((raw_bpl + 7) // 8) * 8
    header = bytearray(HEADER_SIZE)
    _write_cstr(header, OFF_MEDIA_CLASS, "PwgRaster", 64)
    _write_cstr(header, OFF_CUPS_PAGE_SIZE_NAME, "Letter", 64)
    _pack_u32(header, OFF_HW_RESOLUTION, x_res)
    _pack_u32(header, OFF_HW_RESOLUTION + 4, y_res)
    _pack_page_geometry(header)
    _pack_u32(header, OFF_CUPS_WIDTH, width)
    _pack_u32(header, OFF_CUPS_HEIGHT, height)
    _pack_u32(header, OFF_CUPS_BITS_PER_COLOR, bits_per_color)
    _pack_u32(header, OFF_CUPS_BITS_PER_PIXEL, bits_per_pixel)
    _pack_u32(header, OFF_CUPS_BYTES_PER_LINE, cups_bytes_per_line)
    _pack_u32(header, OFF_CUPS_COLOR_ORDER, color_order)
    _pack_u32(header, OFF_CUPS_COLOR_SPACE, color_space if color_space is not None else (CUPS_CSPACE_RGB if num_colors == 3 else CUPS_CSPACE_K))
    _pack_u32(header, OFF_CUPS_COMPRESSION, compression)
    _pack_u32(header, OFF_CUPS_ROW_COUNT, height)
    _pack_u32(header, OFF_CUPS_NUM_COLORS, num_colors)
    pixel = bytes((i & 0xFF) or 1 for i in range(cups_bytes_per_line))
    page = bytes(header) + pixel * height
    return SYNC_CUPS_RASTER_V3 + page * max(1, pages)


def make_pwg_raster(*, width: int, height: int, bits_per_pixel: int, x_res: int = 300, y_res: int, pages: int = 1) -> bytes:
    cups_bytes_per_line = max(1, (width * bits_per_pixel + 7) // 8)
    header = bytearray(HEADER_SIZE)
    _write_cstr(header, OFF_MEDIA_CLASS, "PwgRaster", 64)
    _write_cstr(header, OFF_MEDIA_TYPE, "PLAIN", 64)
    _write_cstr(header, OFF_OUTPUT_TYPE, "Automatic", 64)
    _write_cstr(header, OFF_CUPS_PAGE_SIZE_NAME, "Letter", 64)
    _pack_u32(header, OFF_HW_RESOLUTION, x_res)
    _pack_u32(header, OFF_HW_RESOLUTION + 4, y_res)
    _pack_page_geometry(header)
    _pack_u32(header, OFF_CUPS_WIDTH, width)
    _pack_u32(header, OFF_CUPS_HEIGHT, height)
    _pack_u32(header, OFF_CUPS_BITS_PER_COLOR, 8)
    _pack_u32(header, OFF_CUPS_BITS_PER_PIXEL, bits_per_pixel)
    _pack_u32(header, OFF_CUPS_BYTES_PER_LINE, cups_bytes_per_line)
    _pack_u32(header, OFF_CUPS_COLOR_ORDER, 0)
    _pack_u32(header, OFF_CUPS_COLOR_SPACE, CUPS_CSPACE_SW)
    _pack_u32(header, OFF_CUPS_COMPRESSION, 0)
    _pack_u32(header, OFF_CUPS_ROW_COUNT, height)
    _pack_u32(header, OFF_CUPS_NUM_COLORS, 1)
    row = bytes([0xFF if y_res >= 2147483648 else 0x80]) * cups_bytes_per_line
    page = bytes(header) + row * height
    return SYNC_PWG_RASTER + page * max(1, pages)


def _pack_page_geometry(buffer: bytearray) -> None:
    _pack_u32(buffer, OFF_IMAGING_BBOX, 18)
    _pack_u32(buffer, OFF_IMAGING_BBOX + 4, 36)
    _pack_u32(buffer, OFF_IMAGING_BBOX + 8, 594)
    _pack_u32(buffer, OFF_IMAGING_BBOX + 12, 756)
    _pack_u32(buffer, OFF_MARGINS, 18)
    _pack_u32(buffer, OFF_MARGINS + 4, 36)
    _pack_u32(buffer, OFF_PAGE_SIZE, 612)
    _pack_u32(buffer, OFF_PAGE_SIZE + 4, 792)
    _pack_float(buffer, OFF_CUPS_PAGE_SIZE, 612.0)
    _pack_float(buffer, OFF_CUPS_PAGE_SIZE + 4, 792.0)
    _pack_float(buffer, OFF_CUPS_IMAGING_BBOX, 18.0)
    _pack_float(buffer, OFF_CUPS_IMAGING_BBOX + 4, 36.0)
    _pack_float(buffer, OFF_CUPS_IMAGING_BBOX + 8, 594.0)
    _pack_float(buffer, OFF_CUPS_IMAGING_BBOX + 12, 756.0)


def _pack_u32(buffer: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<I", buffer, offset, value & 0xFFFFFFFF)


def _pack_float(buffer: bytearray, offset: int, value: float) -> None:
    struct.pack_into("<f", buffer, offset, value)


def _write_cstr(buffer: bytearray, offset: int, value: str, size: int) -> None:
    encoded = value.encode("ascii")[: size - 1]
    buffer[offset : offset + len(encoded)] = encoded
