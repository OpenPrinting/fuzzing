#!/usr/bin/python3
import sys
import atheris
import cups

def TestOneInput(data: bytes):
    fdp = atheris.FuzzedDataProvider(data)

    try:
        # generating fuzzed Unicode string
        fuzz_str = fdp.ConsumeUnicodeNoSurrogates(atheris.ALL_REMAINING)
    except Exception:
        return

    try:
        conn = cups.Connection()
        # string-to-UTF8 conversions
        conn.getPPD(fuzz_str)

        # UTF8-from-PyObj conversions
        utf8_bytes = fuzz_str.encode("utf-8", errors="ignore")
        conn.acceptJobs(fuzz_str)
        conn.getJobs(which_jobs=fuzz_str)
        conn.getJobAttributes(utf8_bytes.decode("utf-8", errors="ignore"))
    except Exception:
        pass

def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
