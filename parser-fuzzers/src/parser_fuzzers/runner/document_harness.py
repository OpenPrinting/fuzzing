from __future__ import annotations

import zlib
import struct
from dataclasses import dataclass

from parser_fuzzers.image_templates import image_feedback_instance
from parser_fuzzers.structured_templates import (
    cups_feedback_instance,
    cups_structural_instance,
    pwg_feedback_instance,
    pwg_structural_instance,
)
from parser_fuzzers.template_synth import (
    synthesize_cups_raster_slots,
    synthesize_image_slots,
    synthesize_pwg_raster_slots,
)


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
PDF_SEMANTIC_PERIOD = 32

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

TEXT_SEMANTIC_CASES = [
    b"\xef\xbb\xbfTitle\tColumn\tValue\r\nOne\tTwo\tThree\r\n",
    b"Line 001\r\nLine 002\r\n\fLine after form feed\r\n",
    b"Header: value\nContinuation: " + b"x" * 96 + b"\n\nBody\n",
    b"\x1b%-12345X@PJL INFO STATUS\r\nPlain text after printer control\r\n",
    b"Column A     Column B     Column C\n" + b"1234567890 " * 24 + b"\n",
    b"Backspace demo: ABC\b\bXY\nOverprint-like line\r\n",
    b"\tIndented\tcolumns\twith\ttabs\n" + b" " * 64 + b"right edge\n",
    b"%%BeginFeature: *InputSlot Tray1\nplain text payload\n%%EndFeature\n",
    b"Page 1\n\fPage 2\n\fPage 3 with trailing bytes\0\0\n",
    b"UTF8-ish bytes: \xc2\xa9 \xe2\x82\xac \xf0\x9f\x98\x80\n",
]

POSTSCRIPT_SEMANTIC_CASES = [
    (
        b"%!PS-Adobe-3.0\n%%Pages: 1\n"
        b"<< /PageSize [144 144] /ImagingBBox null >> setpagedevice\n"
        b"/Courier findfont 10 scalefont setfont\n24 72 moveto (setpagedevice path) show\nshowpage\n"
    ),
    (
        b"%!PS-Adobe-3.0\n%%BoundingBox: 0 0 64 64\n"
        b"gsave 32 32 translate 30 rotate 1 0 0 setrgbcolor\n"
        b"0 0 moveto 24 0 lineto 12 24 lineto closepath fill\ngrestore\nshowpage\n"
    ),
    (
        b"%!PS-Adobe-3.0\n%%Pages: 2\n%%Page: 1 1\n"
        b"/F /Helvetica findfont 12 scalefont def F setfont\n24 24 moveto (page one) show\nshowpage\n"
        b"%%Page: 2 2\n90 rotate 24 -96 moveto (rotated page two) show\nshowpage\n"
    ),
    (
        b"%!PS-Adobe-3.0\n%%BoundingBox: 0 0 16 16\n/picstr 2 string def\n"
        b"2 2 1 [2 0 0 -2 0 2] {<80C04020>} image\nshowpage\n"
    ),
    (
        b"%!PS\n/userdict 12 dict dup begin /x 42 def /paint { x 2 mul 24 moveto (dict) show } bind def end def\n"
        b"userdict begin /Helvetica findfont 9 scalefont setfont paint end showpage\n"
    ),
    (
        b"%!PS-Adobe-3.0\n%%BeginResource: procset smt 1 0\n"
        b"/box { newpath 0 0 moveto 50 0 lineto 50 50 lineto 0 50 lineto closepath stroke } bind def\n"
        b"%%EndResource\n10 10 translate box showpage\n"
    ),
    (
        b"%!PS-Adobe-3.0\n%%LanguageLevel: 2\n"
        b"<< /Policies << /PageSize 3 >> /PageSize [612 792] >> setpagedevice\n"
        b"/Times-Roman findfont 14 scalefont setfont 72 720 moveto (policy page) show showpage\n"
    ),
    (
        b"%!PS-Adobe-3.0\n%%BoundingBox: 0 0 128 128\n"
        b"/DeviceGray setcolorspace 0.5 setgray 16 16 96 64 rectfill\n"
        b"/DeviceRGB setcolorspace 1 0 0 setrgbcolor 24 24 32 32 rectstroke\nshowpage\n"
    ),
]

COMMAND_SEMANTIC_CASES = [
    b"#CUPS-COMMAND\nReportLevels\nReportStatus\n",
    b"#CUPS-COMMAND\nClean all\nClean print-heads\n",
    b"#CUPS-COMMAND\nPrintSelfTestPage\nPrintAlignmentPage 1\n",
    b"#CUPS-COMMAND\nSetAlignment 0 0\nSetAlignment 1 -1\n",
    b"#CUPS-COMMAND\nAutoConfigure\nReportConfig\nReportLevels\n",
    b"#CUPS-COMMAND\nReportStatus\nUnknownCommand key=value count=3\n",
    b"#CUPS-COMMAND\r\nClean\r\nPrintSelfTestPage\r\n",
    b"#CUPS-COMMAND\nSetAlignment 2147483647 -2147483648\nReportStatus\n",
    b"#CUPS-COMMAND\n# comment line\nReportLevels\n\nReportConfig\n",
    b"#CUPS-COMMAND\nNoOp\nClean\nReportStatus\nPrintAlignmentPage 99\n",
]


@dataclass(frozen=True)
class DocumentCase:
    kind: str
    data: bytes
    mime: str
    description: str
    extension: str = ".bin"


def make_document(kind: str, case_index: int, target_id: str = "") -> DocumentCase:
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
    if kind == "text_semantic_sweep":
        data = TEXT_SEMANTIC_CASES[case_index % len(TEXT_SEMANTIC_CASES)]
        return DocumentCase(
            kind=kind,
            data=data,
            mime="text/plain",
            description="semantic text input",
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
    if kind == "postscript_semantic_sweep":
        data = POSTSCRIPT_SEMANTIC_CASES[case_index % len(POSTSCRIPT_SEMANTIC_CASES)]
        return DocumentCase(
            kind=kind,
            data=data,
            mime="application/postscript",
            description="semantic PostScript input",
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
    if kind == "pdf_semantic_sweep":
        return DocumentCase(
            kind=kind,
            data=make_pdf_semantic(case_index),
            mime="application/pdf",
            description="semantic PDF input",
            extension=".pdf",
        )
    if kind == "image_coverage_sweep":
        slots = synthesize_image_slots(case_index)
        extension = ".png" if slots.image_format.startswith("png") else {
            "ppm": ".ppm",
            "pgm": ".pgm",
            "pbm": ".pbm",
        }[slots.image_format]
        return DocumentCase(
            kind=kind,
            data=make_image(
                image_format=slots.image_format,
                width=slots.width,
                height=slots.height,
                channels=slots.channels,
            ),
            mime="image/png" if slots.image_format.startswith("png") else "image/x-portable-anymap",
            description=f"SMT-filled coverage {slots.image_format} image",
            extension=extension,
        )
    if kind == "image_feedback_sweep":
        instance = image_feedback_instance(case_index, target_id=target_id)
        extension = ".png" if instance.image_format.startswith("png") else {
            "ppm": ".ppm",
            "pgm": ".pgm",
            "pbm": ".pbm",
        }[instance.image_format]
        return DocumentCase(
            kind=kind,
            data=make_image(
                image_format=instance.image_format,
                width=instance.width,
                height=instance.height,
                channels=instance.channels,
                maxval=instance.maxval,
                payload_delta=instance.payload_delta,
                comment_style=instance.comment_style,
                png_interlace=instance.png_interlace,
            ),
            mime="image/png" if instance.image_format.startswith("png") else "image/x-portable-anymap",
            description=f"feedback-driven image sweep via {instance.objective}/{instance.solved_by}",
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
    if kind == "command_semantic_sweep":
        data = COMMAND_SEMANTIC_CASES[case_index % len(COMMAND_SEMANTIC_CASES)]
        return DocumentCase(
            kind=kind,
            data=data,
            mime="application/vnd.cups-command",
            description="semantic CUPS command input",
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
        slots = synthesize_cups_raster_slots(case_index)
        return DocumentCase(
            kind=kind,
            data=make_cups_raster(
                width=slots.width,
                height=slots.height,
                compression=slots.compression,
                num_colors=slots.num_colors,
                color_space=slots.color_space,
                color_order=slots.color_order,
                bits_per_pixel=slots.bits_per_pixel,
                pages=slots.pages,
                x_res=slots.x_res,
                y_res=slots.y_res,
            ),
            mime="application/vnd.cups-raster",
            description="SMT-filled coverage CUPS Raster sweep",
            extension=".ras",
        )
    if kind == "cups_raster_structural_sweep":
        instance = cups_structural_instance(case_index)
        return DocumentCase(
            kind=kind,
            data=make_cups_raster(
                width=instance.get("width"),
                height=instance.get("height"),
                compression=instance.get("compression"),
                num_colors=instance.get("num_colors"),
                color_space=instance.get("color_space"),
                color_order=instance.get("color_order"),
                bits_per_pixel=instance.get("bits_per_pixel"),
                pages=instance.get("pages"),
                x_res=instance.get("x_res"),
                y_res=instance.get("y_res"),
                bytes_per_line=instance.get("bytes_per_line"),
                row_count=instance.get("row_count"),
                payload_rows=instance.get("payload_rows"),
            ),
            mime="application/vnd.cups-raster",
            description=f"structural CUPS Raster sweep via {instance.objective}",
            extension=".ras",
        )
    if kind == "cups_raster_feedback_sweep":
        instance = cups_feedback_instance(case_index)
        return DocumentCase(
            kind=kind,
            data=make_cups_raster(
                width=instance.get("width"),
                height=instance.get("height"),
                compression=instance.get("compression"),
                num_colors=instance.get("num_colors"),
                color_space=instance.get("color_space"),
                color_order=instance.get("color_order"),
                bits_per_pixel=instance.get("bits_per_pixel"),
                pages=instance.get("pages"),
                x_res=instance.get("x_res"),
                y_res=instance.get("y_res"),
                bytes_per_line=instance.get("bytes_per_line"),
                row_count=instance.get("row_count"),
                payload_rows=instance.get("payload_rows"),
            ),
            mime="application/vnd.cups-raster",
            description=f"feedback-driven CUPS Raster sweep via {instance.objective}",
            extension=".ras",
        )
    if kind == "pwg_raster_resolution_stress":
        stress = case_index > 0
        return DocumentCase(
            kind=kind,
            data=make_pwg_raster_resolution_stress(stress=stress),
            mime="application/vnd.cups-pwg",
            description="resolution stress PWG Raster" if stress else "benign small PWG Raster",
            extension=".pwg",
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
        slots = synthesize_pwg_raster_slots(case_index)
        return DocumentCase(
            kind=kind,
            data=make_pwg_raster(
                width=slots.width,
                height=slots.height,
                bits_per_pixel=slots.bits_per_pixel,
                x_res=slots.x_res,
                y_res=slots.y_res,
                pages=slots.pages,
            ),
            mime="application/vnd.cups-pwg",
            description="SMT-filled coverage PWG Raster sweep",
            extension=".pwg",
        )
    if kind == "pwg_raster_structural_sweep":
        instance = pwg_structural_instance(case_index)
        return DocumentCase(
            kind=kind,
            data=make_pwg_raster(
                width=instance.get("width"),
                height=instance.get("height"),
                bits_per_pixel=instance.get("bits_per_pixel"),
                x_res=instance.get("x_res"),
                y_res=instance.get("y_res"),
                pages=instance.get("pages"),
                bytes_per_line=instance.get("bytes_per_line"),
                row_count=instance.get("row_count"),
                payload_rows=instance.get("payload_rows"),
            ),
            mime="application/vnd.cups-pwg",
            description=f"structural PWG Raster sweep via {instance.objective}",
            extension=".pwg",
        )
    if kind == "pwg_raster_feedback_sweep":
        instance = pwg_feedback_instance(case_index)
        return DocumentCase(
            kind=kind,
            data=make_pwg_raster(
                width=instance.get("width"),
                height=instance.get("height"),
                bits_per_pixel=instance.get("bits_per_pixel"),
                x_res=instance.get("x_res"),
                y_res=instance.get("y_res"),
                pages=instance.get("pages"),
                bytes_per_line=instance.get("bytes_per_line"),
                row_count=instance.get("row_count"),
                payload_rows=instance.get("payload_rows"),
            ),
            mime="application/vnd.cups-pwg",
            description=f"feedback-driven PWG Raster sweep via {instance.objective}",
            extension=".pwg",
        )
    raise ValueError(f"unknown document kind: {kind}")


def make_pdf(*, media_box: tuple[int, int, int, int], text: str) -> bytes:
    escaped = _escape_pdf_text(text)
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


def make_pdf_semantic(case_index: int) -> bytes:
    media_boxes = [
        (0, 0, 200, 200),
        (0, 0, 612, 792),
        (0, 0, 144, 144),
        (0, 0, 1008, 612),
    ]
    media_box = media_boxes[(case_index // 8) % len(media_boxes)]
    variant = case_index % 8
    text = f"semantic pdf case {case_index}"
    x0, y0, x1, y1 = media_box

    if variant == 0:
        return make_pdf(media_box=media_box, text=text)

    if variant == 1:
        page_one = _pdf_text_stream(f"{text} page one", x=24, y=48, size=12)
        page_two = _pdf_text_stream(f"{text} rotated page two", x=24, y=48, size=10)
        objects = [
            b"<< /Type /Catalog /Pages 2 0 R /PageMode /UseNone >>",
            b"<< /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 >>",
            (
                f"<< /Type /Page /Parent 2 0 R /MediaBox [{x0} {y0} {x1} {y1}] "
                "/Resources << /Font << /F1 5 0 R >> >> /Contents 6 0 R >>"
            ).encode("ascii"),
            (
                f"<< /Type /Page /Parent 2 0 R /Rotate 90 /MediaBox [{x0} {y0} {x1} {y1}] "
                "/Resources << /Font << /F1 5 0 R >> >> /Contents 7 0 R >>"
            ).encode("ascii"),
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>",
            _pdf_stream(page_one),
            _pdf_stream(page_two),
        ]
        return _build_pdf(objects)

    if variant == 2:
        stream = (
            b"q 0.8 0.8 0.8 rg 18 18 96 48 re f Q\n"
            + _pdf_text_stream(f"{text} flate stream", x=24, y=34, size=9)
        )
        compressed = zlib.compress(stream)
        objects = [
            b"<< /Type /Catalog /Pages 2 0 R >>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            (
                f"<< /Type /Page /Parent 2 0 R /MediaBox [{x0} {y0} {x1} {y1}] "
                "/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>"
            ).encode("ascii"),
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
            _pdf_stream(compressed, extra=b"/Filter /FlateDecode"),
        ]
        return _build_pdf(objects)

    if variant == 3:
        image_pixels = bytes([255, 0, 0, 0, 255, 0, 0, 0, 255, 255, 255, 0])
        content = b"q 32 0 0 32 24 24 cm /Im1 Do Q\n"
        objects = [
            b"<< /Type /Catalog /Pages 2 0 R >>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            (
                f"<< /Type /Page /Parent 2 0 R /MediaBox [{x0} {y0} {x1} {y1}] "
                "/Resources << /XObject << /Im1 5 0 R >> >> /Contents 4 0 R >>"
            ).encode("ascii"),
            _pdf_stream(content),
            (
                b"<< /Type /XObject /Subtype /Image /Width 2 /Height 2 "
                b"/ColorSpace /DeviceRGB /BitsPerComponent 8 /Length "
                + str(len(image_pixels)).encode("ascii")
                + b" >>\nstream\n"
                + image_pixels
                + b"\nendstream"
            ),
        ]
        return _build_pdf(objects)

    if variant == 4:
        content = _pdf_text_stream(f"{text} annotation page", x=24, y=48, size=11)
        objects = [
            b"<< /Type /Catalog /Pages 2 0 R /OpenAction [3 0 R /Fit] >>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            (
                f"<< /Type /Page /Parent 2 0 R /MediaBox [{x0} {y0} {x1} {y1}] "
                "/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R /Annots [6 0 R] >>"
            ).encode("ascii"),
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Oblique >>",
            _pdf_stream(content),
            b"<< /Type /Annot /Subtype /Link /Rect [20 20 100 60] /Border [0 0 0] /Dest [3 0 R /Fit] >>",
        ]
        return _build_pdf(objects)

    if variant == 5:
        form_stream = (
            b"q 1 0 0 rg 0 0 36 18 re f Q\n"
            b"BT /F1 8 Tf 2 6 Td (form) Tj ET\n"
        )
        content = b"q 1 0 0 1 24 24 cm /Fm1 Do Q\n"
        objects = [
            b"<< /Type /Catalog /Pages 2 0 R >>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            (
                f"<< /Type /Page /Parent 2 0 R /MediaBox [{x0} {y0} {x1} {y1}] "
                "/Resources << /Font << /F1 4 0 R >> /XObject << /Fm1 6 0 R >> >> /Contents 5 0 R >>"
            ).encode("ascii"),
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
            _pdf_stream(content),
            (
                b"<< /Type /XObject /Subtype /Form /BBox [0 0 40 20] "
                b"/Resources << /Font << /F1 4 0 R >> >> /Length "
                + str(len(form_stream)).encode("ascii")
                + b" >>\nstream\n"
                + form_stream
                + b"endstream"
            ),
        ]
        return _build_pdf(objects)

    if variant == 6:
        path_stream = (
            b"q 0 0 1 RG 2 w 20 20 m 60 20 l 60 60 l 20 60 l h S Q\n"
            b"q 0.2 0.6 0.1 rg 72 24 36 18 re f Q\n"
            + _pdf_text_stream(f"{text} paths", x=20, y=90, size=8)
        )
        objects = [
            b"<< /Type /Catalog /Pages 2 0 R >>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            (
                f"<< /Type /Page /Parent 2 0 R /MediaBox [{x0} {y0} {x1} {y1}] "
                "/Resources << /Font << /F1 4 0 R >> /ProcSet [/PDF /Text] >> /Contents 5 0 R >>"
            ).encode("ascii"),
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Times-Roman >>",
            _pdf_stream(path_stream),
        ]
        return _build_pdf(objects)

    metadata = (
        f"<< /Title ({_escape_pdf_text(text)}) /Producer (parser-fuzzers) "
        "/Creator (semantic sweep) >>"
    ).encode("ascii")
    content = _pdf_text_stream(f"{text} info object", x=24, y=48, size=12)
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R /ViewerPreferences << /FitWindow true >> >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        (
            f"<< /Type /Page /Parent 2 0 R /MediaBox [{x0} {y0} {x1} {y1}] "
            "/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>"
        ).encode("ascii"),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>",
        _pdf_stream(content),
        metadata,
    ]
    return _build_pdf(objects, info_obj=6)


def _escape_pdf_text(text: str) -> str:
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _pdf_text_stream(text: str, *, x: int, y: int, size: int) -> bytes:
    escaped = _escape_pdf_text(text)
    return f"BT /F1 {size} Tf {x} {y} Td ({escaped}) Tj ET\n".encode("ascii")


def _pdf_stream(data: bytes, *, extra: bytes = b"") -> bytes:
    if extra:
        return b"<< /Length " + str(len(data)).encode("ascii") + b" " + extra + b" >>\nstream\n" + data + b"endstream"
    return b"<< /Length " + str(len(data)).encode("ascii") + b" >>\nstream\n" + data + b"endstream"


def _build_pdf(objects: list[bytes], *, info_obj: int | None = None) -> bytes:
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
    trailer = f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R"
    if info_obj is not None:
        trailer += f" /Info {info_obj} 0 R"
    trailer += f" >>\nstartxref\n{xref_offset}\n%%EOF\n"
    output.extend(trailer.encode("ascii"))
    return bytes(output)


def make_image(
    *,
    image_format: str,
    width: int,
    height: int,
    channels: int,
    maxval: int = 255,
    payload_delta: int = 0,
    comment_style: int = 0,
    png_interlace: int = 0,
) -> bytes:
    if image_format == "ppm":
        header = _pnm_header("P6", width, height, maxval, comment_style)
        pixels = _sized_payload(width * height * 3 * _sample_bytes(maxval), payload_delta, 17)
        return header + pixels
    if image_format == "pgm":
        header = _pnm_header("P5", width, height, maxval, comment_style)
        pixels = _sized_payload(width * height * _sample_bytes(maxval), payload_delta, 31)
        return header + pixels
    if image_format == "pbm":
        row_bytes = (width + 7) // 8
        header = _pnm_header("P4", width, height, 1, comment_style)
        pixels = _sized_payload(row_bytes * height, payload_delta, 0x5A)
        return header + pixels
    if image_format == "png_rgb":
        return make_png(
            width=width,
            height=height,
            color_type=2,
            channels=channels,
            payload_delta=payload_delta,
            interlace=png_interlace,
        )
    if image_format == "png_gray":
        return make_png(
            width=width,
            height=height,
            color_type=0,
            channels=channels,
            payload_delta=payload_delta,
            interlace=png_interlace,
        )
    if image_format == "png_rgba":
        return make_png(
            width=width,
            height=height,
            color_type=6,
            channels=channels,
            payload_delta=payload_delta,
            interlace=png_interlace,
        )
    raise ValueError(f"unknown image format: {image_format}")


def make_png(
    *,
    width: int,
    height: int,
    color_type: int,
    channels: int,
    payload_delta: int = 0,
    interlace: int = 0,
) -> bytes:
    bit_depth = 8
    raw = bytearray()
    for y in range(height):
        raw.append(0)  # filter type: None
        for x in range(width):
            if channels == 1:
                raw.append((x * 23 + y * 17) & 0xFF)
            else:
                raw.extend(((x * 31) & 0xFF, (y * 47) & 0xFF, ((x + y) * 19) & 0xFF))
                if channels == 4:
                    raw.append(((x * 11 + y * 13) & 0xFF) or 1)
    raw = bytearray(_sized_payload(len(raw), payload_delta, 23, seed=bytes(raw)))
    ihdr = struct.pack(">IIBBBBB", width, height, bit_depth, color_type, 0, 0, 1 if interlace else 0)
    compressed = zlib.compress(bytes(raw))
    return (
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"IHDR", ihdr)
        + _png_chunk(b"IDAT", compressed)
        + _png_chunk(b"IEND", b"")
    )


def _pnm_header(magic: str, width: int, height: int, maxval: int, comment_style: int) -> bytes:
    if magic == "P4":
        if comment_style == 1:
            return f"{magic}\n# smt image feedback\n{width} {height}\n".encode("ascii")
        if comment_style == 2:
            return f"{magic}\r\n{width}\t{height}\r\n".encode("ascii")
        if comment_style == 3:
            return f"{magic} # inline\n{width} {height}\n".encode("ascii")
        return f"{magic}\n{width} {height}\n".encode("ascii")
    bounded_maxval = max(1, min(65535, maxval))
    if comment_style == 1:
        return f"{magic}\n# smt image feedback\n{width} {height}\n{bounded_maxval}\n".encode("ascii")
    if comment_style == 2:
        return f"{magic}\r\n{width}\t{height}\r\n{bounded_maxval}\r\n".encode("ascii")
    if comment_style == 3:
        return f"{magic} # inline\n{width} {height}\n{bounded_maxval}\n".encode("ascii")
    return f"{magic}\n{width} {height}\n{bounded_maxval}\n".encode("ascii")


def _sample_bytes(maxval: int) -> int:
    return 2 if maxval > 255 else 1


def _sized_payload(size: int, delta: int, salt: int, seed: bytes | None = None) -> bytes:
    target_size = max(0, size + delta)
    if seed is not None:
        if target_size <= len(seed):
            return seed[:target_size]
        extra = bytes(((index * salt + 3) & 0xFF) for index in range(target_size - len(seed)))
        return seed + extra
    return bytes(((index * salt + 1) & 0xFF) for index in range(target_size))


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
    bytes_per_line: int | None = None,
    row_count: int | None = None,
    payload_rows: int | None = None,
) -> bytes:
    bits_per_color = 8
    bits_per_pixel = bits_per_pixel or max(1, bits_per_color * num_colors)
    raw_bpl = (width * bits_per_pixel + 7) // 8
    cups_bytes_per_line = max(1, bytes_per_line if bytes_per_line is not None else ((raw_bpl + 7) // 8) * 8)
    raster_rows = max(1, payload_rows if payload_rows is not None else height)
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
    _pack_u32(header, OFF_CUPS_ROW_COUNT, row_count if row_count is not None else height)
    _pack_u32(header, OFF_CUPS_NUM_COLORS, num_colors)
    pixel = bytes((i & 0xFF) or 1 for i in range(cups_bytes_per_line))
    page = bytes(header) + pixel * raster_rows
    return SYNC_CUPS_RASTER_V3 + page * max(1, pages)


def make_pwg_raster_resolution_stress(*, stress: bool) -> bytes:
    width = 5 if stress else 8
    height = 6 if stress else 1
    bits_per_pixel = 16
    y_res = 2147483648 if stress else 300
    return make_pwg_raster(width=width, height=height, bits_per_pixel=bits_per_pixel, x_res=300, y_res=y_res)


def make_pwg_raster(
    *,
    width: int,
    height: int,
    bits_per_pixel: int,
    x_res: int = 300,
    y_res: int,
    pages: int = 1,
    bytes_per_line: int | None = None,
    row_count: int | None = None,
    payload_rows: int | None = None,
) -> bytes:
    cups_bytes_per_line = max(1, bytes_per_line if bytes_per_line is not None else (width * bits_per_pixel + 7) // 8)
    raster_rows = max(1, payload_rows if payload_rows is not None else height)
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
    _pack_u32(header, OFF_CUPS_ROW_COUNT, row_count if row_count is not None else height)
    _pack_u32(header, OFF_CUPS_NUM_COLORS, 1)
    row = bytes([0xFF if y_res >= 2147483648 else 0x80]) * cups_bytes_per_line
    page = bytes(header) + row * raster_rows
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
