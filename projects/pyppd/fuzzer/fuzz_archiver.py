#!/usr/bin/python3

import atheris
import sys
import os
import tempfile
import pyppd.archiver as archiver

def TestOneInput(data):
    try:
        #write the fuzz input into a fake ppd file in a temp dir
        with tempfile.TemporaryDirectory() as tmpdir:
            fuzz_ppd = os.path.join(tmpdir, "fuzz.ppd")
            with open(fuzz_ppd, "wb") as f:
                f.write(data)

            # call the archive with that directory
            archiver.archive(tmpdir)
    except Exception:
        pass

def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
