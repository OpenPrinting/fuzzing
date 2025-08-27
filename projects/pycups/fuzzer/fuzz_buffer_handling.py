#!/usr/bin/python3
import sys
import atheris
import cups

def TestOneInput(data: bytes):
    fdp = atheris.FuzzedDataProvider(data)

    buf_len = fdp.ConsumeIntInRange(0, 1024)
    buffer_obj = fdp.ConsumeBytes(buf_len)

    MAX_LEN = 8192
    if fdp.ConsumeBool():
        length = fdp.ConsumeIntInRange(0, len(buffer_obj)) if buffer_obj else 0
    else:
        length = fdp.ConsumeIntInRange(len(buffer_obj), MAX_LEN)

    try:
        conn = cups.Connection()
        choice = fdp.ConsumeIntInRange(0, 3)

        if choice == 0:
            # normal buffer+length
            conn.writeRequestData(buffer_obj, length)
        elif choice == 1:
            #empty buffer with non-zero length
            conn.writeRequestData(b"", length)
        elif choice == 2:
            # null/none input case
            try:
                conn.writeRequestData(None, length)
            except Exception:
                pass
        else:
            #negative length edge case
            negative_len = -fdp.ConsumeIntInRange(1, 100)
            conn.writeRequestData(buffer_obj, negative_len)

    except Exception:
        pass

def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
