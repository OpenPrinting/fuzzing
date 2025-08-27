#!/usr/bin/python3

import atheris
import sys
import tempfile
import shutil
import os
import fnmatch
from pathlib import Path

import pyppd.archiver as archiver


def TestOneInput(data):
    #temp directory for fuzz input
    tmpdir = tempfile.mkdtemp()
    try:
        # to simulate multiple files -> split into chunks
        parts = data.split(b"\n")
        files = parts[:-1]
        patterns = [p.decode("utf-8", errors="ignore") for p in parts[-1:]] or ["*"]

        # write the fuzz-controlled files into temp dir
        for i, content in enumerate(files):
            # limiting filename length
            fname = f"file_{i}.ppd"
            fpath = os.path.join(tmpdir, fname)
            try:
                with open(fpath, "wb") as f:
                    f.write(content)
            except Exception:
                pass

        # find_files
        for _ in archiver.find_files(tmpdir, patterns):
            pass

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
