#!/usr/bin/python3

import atheris
import sys
import tempfile
import shutil
import os
import gzip

import pyppd.archiver as archiver


def TestOneInput(data):
    tmpdir = tempfile.mkdtemp()
    try:
        parts = data.split(b"\n\n")
        if not parts:
            return

        for i, content in enumerate(parts):
            if i % 2 == 0:
                fname = os.path.join(tmpdir, f"fuzz_{i}.ppd")
                with open(fname, "wb") as f:
                    f.write(content)
            else:
                fname = os.path.join(tmpdir, f"fuzz_{i}.ppd.gz")
                with gzip.open(fname, "wb") as f:
                    f.write(content)

        # Call compress function
        try:
            _ = archiver.compress(tmpdir)
        except Exception:
            pass

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
