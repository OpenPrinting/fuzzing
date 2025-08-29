#!/usr/bin/python3

import atheris
import sys
import os

import pyppd.runner as runner


def TestOneInput(data):
    try:
        args = data.decode("utf-8", errors="ignore").split()
        if not args:
            return
        # runner.parse_args expects scriptname + args
        sys.argv = ["fuzz_runner"] + args
        try:
            _ = runner.parse_args()
        except SystemExit:
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
