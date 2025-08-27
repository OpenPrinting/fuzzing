#!/usr/bin/python3
import sys
import atheris
import cups


def TestOneInput(data: bytes):
    if len(data) < 4:
        return

    fdp = atheris.FuzzedDataProvider(data)

    try:
        conn = cups.Connection()

        # required argument
        name = fdp.ConsumeUnicodeNoSurrogates(32)
        kwargs = {}

        if fdp.ConsumeBool():
            kwargs["filename"] = fdp.ConsumeUnicodeNoSurrogates(32)
        if fdp.ConsumeBool():
            kwargs["ppdname"] = fdp.ConsumeUnicodeNoSurrogates(32)
        if fdp.ConsumeBool():
            kwargs["info"] = fdp.ConsumeUnicodeNoSurrogates(32)
        if fdp.ConsumeBool():
            kwargs["location"] = fdp.ConsumeUnicodeNoSurrogates(32)
        if fdp.ConsumeBool():
            kwargs["device"] = fdp.ConsumeUnicodeNoSurrogates(32)

        #sometimes fuzz with a PPD object if available
        if fdp.ConsumeBool():
            try:
                ppd = cups.PPD()  # minimal empty object
                kwargs["ppd"] = ppd
            except Exception:
                pass

        # calling the addPrinter with fuzzed args
        try:
            conn.addPrinter(name, **kwargs)
        except Exception:
            pass
    except Exception:
        pass


def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
