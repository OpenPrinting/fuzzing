#!/usr/bin/python3

import atheris
import sys
import pyppd.archiver as archiver


def TestOneInput(data):
    try:
        filename = data.decode("utf-8", errors="ignore").strip()
        if not filename:
            return
        try:
            _ = archiver.read_file_in_syspath(filename)
        except FileNotFoundError:
            pass
        except Exception:
            pass
    except Exception:
        pass


def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
