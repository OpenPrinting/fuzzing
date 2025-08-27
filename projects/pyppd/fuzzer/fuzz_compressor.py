#!/usr/bin/python3

import atheris
import sys
import pyppd.compressor as compressor

def TestOneInput(data):
    try:
        # fuzz the compress/decompress cycle
        compressed = compressor.compress(data)
        _ = compressor.decompress(compressed)

        # also try compress_file interface
        # (needs a temp file with fuzz data)
        import tempfile, os
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(data)
            f.flush()
            fpath = f.name

        try:
            _ = compressor.compress_file(fpath)
        finally:
            os.remove(fpath)

    except Exception:
        pass

def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
