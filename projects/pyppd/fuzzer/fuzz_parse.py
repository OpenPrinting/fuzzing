#!/usr/bin/python3

import atheris
import sys
import pyppd.ppd as ppd

def TestOneInput(data):
    try:
        #fuzz.ppd is a fake file name
        ppd.parse(data, "fuzz.ppd")
    except (ValueError, KeyError, AttributeError, UnicodeDecodeError):
        #parsing errors are expected
        pass

def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
