from __future__ import annotations

from parser_fuzzers.template_synth import synthesize_ppd_slots


GENERIC_STRING_VALUES = ["normal", "0", "", "A", "END", "reset", "job", "literal text"]
GENERAL_STRING_VALUES = [
    "normal",
    "",
    "A",
    "END",
    "reset",
    "job-end",
    "literal text",
    "x" * 64,
    "\\033E",
    "0 1 2 3",
    "printer-ready",
    "SMT-Fuzzer-General",
    "quotes-\"-escaped",
    "backslash-\\-escaped",
]
GENERIC_RESOLUTIONS = [300, 600, 150, 72, 1200, 2, 75, 1]
GENERAL_RESOLUTIONS = [300, 600, 150, 72, 203, 200, 360, 720, 1200, 2400, 75, 100, 1, 2, 10, 65535, 65536]
COVERAGE_RESOLUTIONS = [300, 600, 150, 72, 203, 200, 360, 720, 1200, 2400, 75, 100, 1, 2, 10, 65535]
PAGE_SIZES = [
    ("Letter", "612 792", "18 36 594 756"),
    ("A4", "595 842", "12 12 583 830"),
    ("Small", "144 144", "0 0 144 144"),
    ("Wide", "1008 612", "18 18 990 594"),
]
FILTER_COVERAGE_PPDS = {
    "pdftopdf_coverage_options": ("PDFToPDF Coverage Options", "application/pdf", "pdftopdf"),
    "pdftops_coverage_options": ("PDFToPS Coverage Options", "application/pdf", "pdftops"),
    "pdftoraster_coverage_options": ("PDFToRaster Coverage Options", "application/pdf", "pdftoraster"),
    "mupdftopwg_coverage_options": ("MuPDFToPWG Coverage Options", "application/pdf", "mupdftopwg"),
    "imagetoraster_coverage_options": ("ImageToRaster Coverage Options", "image/x-portable-anymap", "imagetoraster"),
    "imagetopdf_coverage_options": ("ImageToPDF Coverage Options", "image/x-portable-anymap", "imagetopdf"),
    "imagetops_coverage_options": ("ImageToPS Coverage Options", "image/x-portable-anymap", "imagetops"),
    "texttopdf_coverage_options": ("TextToPDF Coverage Options", "text/plain", "texttopdf"),
    "texttotext_coverage_options": ("TextToText Coverage Options", "text/plain", "texttotext"),
    "gstoraster_coverage_options": ("GSToRaster Coverage Options", "application/postscript", "gstoraster"),
    "gstopdf_coverage_options": ("GSToPDF Coverage Options", "application/postscript", "gstopdf"),
    "gstopxl_coverage_options": ("GSToPXL Coverage Options", "application/postscript", "gstopxl"),
    "pwgtopclm_coverage_options": ("PWGToPCLm Coverage Options", "application/vnd.cups-pwg", "pwgtopclm"),
    "commandtoescpx_coverage_options": ("CommandToESCPX Coverage Options", "application/vnd.cups-command", "commandtoescpx"),
    "commandtopclx_coverage_options": ("CommandToPCLX Coverage Options", "application/vnd.cups-command", "commandtopclx"),
}


def make_ppd(kind: str, case_index: int) -> str:
    if kind in FILTER_COVERAGE_PPDS:
        model, input_mime, filter_name = FILTER_COVERAGE_PPDS[kind]
        slots = synthesize_ppd_slots(case_index)
        return _base_ppd(
            model=model,
            filter_line=f'*cupsFilter: "{input_mime} 0 {filter_name}"',
            extra=_coverage_options(case_index),
            page_size=PAGE_SIZES[slots.page_size_index],
        )
    if kind == "rastertopclx":
        payload = GENERAL_STRING_VALUES[case_index % len(GENERAL_STRING_VALUES)]
        return _base_ppd(
            model="Rastertopclx Template",
            filter_line='*cupsFilter: "application/vnd.cups-raster 0 rastertopclx"',
            extra=f'*cupsPCL EndJob: "{_escape(payload)}"\n',
        )
    if kind == "rastertopclx_string_sweep":
        value = GENERIC_STRING_VALUES[case_index % len(GENERIC_STRING_VALUES)]
        return _base_ppd(
            model="Rastertopclx String Sweep",
            filter_line='*cupsFilter: "application/vnd.cups-raster 0 rastertopclx"',
            extra=f'*cupsPCL EndJob: "{_escape(value)}"\n',
        )
    if kind == "rastertopclx_general_strings":
        value = GENERAL_STRING_VALUES[case_index % len(GENERAL_STRING_VALUES)]
        return _base_ppd(
            model="Rastertopclx General Strings",
            filter_line='*cupsFilter: "application/vnd.cups-raster 0 rastertopclx"',
            extra=f'*cupsPCL EndJob: "{_escape(value)}"\n',
        )
    if kind == "rastertopclx_plain":
        return _base_ppd(
            model="Rastertopclx Plain Template",
            filter_line='*cupsFilter: "application/vnd.cups-raster 0 rastertopclx"',
            extra="",
        )
    if kind == "rastertoescpx_single_pagesize":
        return _base_ppd(
            model="Rastertoescpx Single PageSize",
            filter_line='*cupsFilter: "application/vnd.cups-raster 0 rastertoescpx"',
            extra="",
        )
    if kind == "rastertoescpx_size_sweep":
        return _base_ppd(
            model="Rastertoescpx Size Sweep",
            filter_line='*cupsFilter: "application/vnd.cups-raster 0 rastertoescpx"',
            extra="",
        )
    if kind == "raster_coverage_options":
        slots = synthesize_ppd_slots(case_index)
        return _base_ppd(
            model="Raster Coverage Options",
            filter_line='*cupsFilter: "application/vnd.cups-raster 0 rastertopclx"',
            extra=_coverage_options(case_index),
            page_size=PAGE_SIZES[slots.page_size_index],
        )
    if kind == "rastertops_plain":
        return _base_ppd(
            model="Rastertops Plain Template",
            filter_line='*cupsFilter: "application/vnd.cups-raster 0 rastertops"',
            extra="",
        )
    if kind == "rastertopwg_plain":
        return _base_ppd(
            model="Rastertopwg Plain Template",
            filter_line='*cupsFilter: "application/vnd.cups-raster 0 rastertopwg"',
            extra="",
        )
    if kind == "pwgtopdf_plain":
        return _base_ppd(
            model="PWGToPDF Plain Template",
            filter_line='*cupsFilter: "application/vnd.cups-pwg 0 pwgtopdf"',
            extra="",
        )
    if kind == "pwgtopdf_coverage_options":
        slots = synthesize_ppd_slots(case_index)
        return _base_ppd(
            model="PWGToPDF Coverage Options",
            filter_line='*cupsFilter: "application/vnd.cups-pwg 0 pwgtopdf"',
            extra=_coverage_options(case_index),
            page_size=PAGE_SIZES[slots.page_size_index],
        )
    if kind == "pwgtoraster_1dpi":
        return _base_ppd(
            model="PWG 1dpi Template",
            filter_line='*cupsFilter: "application/vnd.cups-pwg 0 pwgtoraster"',
            extra=(
                '*OpenUI *Resolution: PickOne\n'
                '*DefaultResolution: 1x1dpi\n'
                '*Resolution 1x1dpi/1 dpi: "<</HWResolution[1 1]>>setpagedevice"\n'
                '*CloseUI: *Resolution\n'
            ),
        )
    if kind == "pwg_resolution_sweep":
        dpi = GENERIC_RESOLUTIONS[case_index % len(GENERIC_RESOLUTIONS)]
        return _base_ppd(
            model="PWG Resolution Sweep",
            filter_line='*cupsFilter: "application/vnd.cups-pwg 0 pwgtoraster"',
            extra=(
                '*OpenUI *Resolution: PickOne\n'
                f'*DefaultResolution: {dpi}x{dpi}dpi\n'
                f'*Resolution {dpi}x{dpi}dpi/{dpi} dpi: "<</HWResolution[{dpi} {dpi}]>>setpagedevice"\n'
                '*CloseUI: *Resolution\n'
            ),
        )
    if kind == "pwg_resolution_general":
        dpi = GENERAL_RESOLUTIONS[case_index % len(GENERAL_RESOLUTIONS)]
        return _base_ppd(
            model="PWG General Resolution",
            filter_line='*cupsFilter: "application/vnd.cups-pwg 0 pwgtoraster"',
            extra=(
                '*OpenUI *Resolution: PickOne\n'
                f'*DefaultResolution: {dpi}x{dpi}dpi\n'
                f'*Resolution {dpi}x{dpi}dpi/{dpi} dpi: "<</HWResolution[{dpi} {dpi}]>>setpagedevice"\n'
                '*CloseUI: *Resolution\n'
            ),
        )
    if kind == "pwg_resolution_coverage":
        slots = synthesize_ppd_slots(case_index)
        dpi = slots.resolution
        return _base_ppd(
            model="PWG Coverage Resolution",
            filter_line='*cupsFilter: "application/vnd.cups-pwg 0 pwgtoraster"',
            extra=(
                '*OpenUI *Resolution: PickOne\n'
                f'*DefaultResolution: {dpi}x{dpi}dpi\n'
                f'*Resolution {dpi}x{dpi}dpi/{dpi} dpi: "<</HWResolution[{dpi} {dpi}]>>setpagedevice"\n'
                '*CloseUI: *Resolution\n'
                + _coverage_options(case_index)
            ),
            page_size=PAGE_SIZES[slots.page_size_index],
        )
    raise ValueError(f"unknown PPD kind: {kind}")


def make_pwg_resolution_ppd(dpi: int) -> str:
    return _base_ppd(
        model="PWG Resolution Boundary",
        filter_line='*cupsFilter: "application/vnd.cups-pwg 0 pwgtoraster"',
        extra=(
            '*OpenUI *Resolution: PickOne\n'
            f'*DefaultResolution: {dpi}x{dpi}dpi\n'
            f'*Resolution {dpi}x{dpi}dpi/{dpi} dpi: "<</HWResolution[{dpi} {dpi}]>>setpagedevice"\n'
            '*CloseUI: *Resolution\n'
        ),
    )


def _base_ppd(
    *,
    model: str,
    filter_line: str,
    extra: str,
    single_pagesize: bool = False,
    page_size: tuple[str, str, str] = ("Letter", "612 792", "18 36 594 756"),
) -> str:
    page_name, page_dimension, imageable_area = page_size
    page_region = "" if single_pagesize else (
        '*OpenUI *PageRegion: PickOne\n'
        f'*DefaultPageRegion: {page_name}\n'
        f'*PageRegion {page_name}: "<</PageSize[{page_dimension}]/ImagingBBox null>>setpagedevice"\n'
        '*CloseUI: *PageRegion\n'
    )
    return f"""*PPD-Adobe: "4.3"
*FormatVersion: "4.3"
*FileVersion: "1.0"
*LanguageVersion: English
*LanguageEncoding: ISOLatin1
*Manufacturer: "SMT-Fuzzer"
*ModelName: "{_escape(model)}"
*ShortNickName: "SMTTemplate"
*NickName: "{_escape(model)}"
*PCFileName: "SMTPPD.PPD"
*Product: "(SMTTemplate)"
*PSVersion: "(3010) 0"
*cupsVersion: 1.0
*cupsModelNumber: 0
*cupsManualCopies: False
{filter_line}
{extra}*OpenUI *PageSize: PickOne
*DefaultPageSize: {page_name}
*PageSize {page_name}: "<</PageSize[{page_dimension}]/ImagingBBox null>>setpagedevice"
*CloseUI: *PageSize
{page_region}*DefaultImageableArea: {page_name}
*ImageableArea {page_name}: "{imageable_area}"
*DefaultPaperDimension: {page_name}
*PaperDimension {page_name}: "{page_dimension}"
"""


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _coverage_options(case_index: int) -> str:
    slots = synthesize_ppd_slots(case_index)
    color_model = ["Gray", "RGB", "CMYK", "Black"][slots.color_model_index]
    quality = ["Draft", "Normal", "High", "Photo"][slots.quality_index]
    media = ["Plain", "Glossy", "Transparency", "Envelope"][slots.media_index]
    duplex = ["None", "DuplexNoTumble", "DuplexTumble"][slots.duplex_index]
    return f"""*OpenUI *ColorModel: PickOne
*DefaultColorModel: {color_model}
*ColorModel Gray/Gray: "<</cupsColorSpace 18/cupsBitsPerColor 8/cupsBitsPerPixel 8>>setpagedevice"
*ColorModel RGB/RGB: "<</cupsColorSpace 1/cupsBitsPerColor 8/cupsBitsPerPixel 24>>setpagedevice"
*ColorModel CMYK/CMYK: "<</cupsColorSpace 6/cupsBitsPerColor 8/cupsBitsPerPixel 32>>setpagedevice"
*ColorModel Black/Black: "<</cupsColorSpace 3/cupsBitsPerColor 8/cupsBitsPerPixel 8>>setpagedevice"
*CloseUI: *ColorModel
*OpenUI *PrintQuality: PickOne
*DefaultPrintQuality: {quality}
*PrintQuality Draft/Draft: "<</cupsInteger0 3>>setpagedevice"
*PrintQuality Normal/Normal: "<</cupsInteger0 4>>setpagedevice"
*PrintQuality High/High: "<</cupsInteger0 5>>setpagedevice"
*PrintQuality Photo/Photo: "<</cupsInteger0 6>>setpagedevice"
*CloseUI: *PrintQuality
*OpenUI *MediaType: PickOne
*DefaultMediaType: {media}
*MediaType Plain/Plain: "<</MediaType(Plain)>>setpagedevice"
*MediaType Glossy/Glossy: "<</MediaType(Glossy)>>setpagedevice"
*MediaType Transparency/Transparency: "<</MediaType(Transparency)>>setpagedevice"
*MediaType Envelope/Envelope: "<</MediaType(Envelope)>>setpagedevice"
*CloseUI: *MediaType
*OpenUI *Duplex: PickOne
*DefaultDuplex: {duplex}
*Duplex None/Off: "<</Duplex false>>setpagedevice"
*Duplex DuplexNoTumble/Long edge: "<</Duplex true/Tumble false>>setpagedevice"
*Duplex DuplexTumble/Short edge: "<</Duplex true/Tumble true>>setpagedevice"
*CloseUI: *Duplex
"""
