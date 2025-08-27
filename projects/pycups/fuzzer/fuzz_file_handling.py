#!/usr/bin/python3
import sys
import atheris
import cups
import tempfile
import io
import os

def TestOneInput(data: bytes):
    # if len(data) < 4:
    #     return

    fdp = atheris.FuzzedDataProvider(data)

    resource = fdp.ConsumeUnicodeNoSurrogates(20)
    filename = fdp.ConsumeUnicodeNoSurrogates(20)
    dest_choice = fdp.ConsumeIntInRange(0, 2)

    try:
        conn = cups.Connection()

        if dest_choice == 0:
            # using file descriptor
            with tempfile.NamedTemporaryFile() as tmp:
                fd = tmp.fileno()
                if fdp.ConsumeBool():
                    conn.getFile(resource, fd=fd)
                else:
                    conn.putFile(resource, fd=fd)

        elif dest_choice == 1:
            # Using filename
            temp_path = os.path.join(tempfile.gettempdir(), filename)
            try:
                if fdp.ConsumeBool():
                    conn.getFile(resource, filename=temp_path)
                else:
                    conn.putFile(resource, filename=temp_path)
            finally:
                if os.path.exists(temp_path):
                    os.remove(temp_path)

        else:
            # using a file-like object
            content = fdp.ConsumeBytes(50)
            fileobj = io.BytesIO(content)
            if fdp.ConsumeBool():
                conn.getFile(resource, file=fileobj)
            else:
                fileobj.seek(0)  # reset the position before writing
                conn.putFile(resource, file=fileobj)

    except Exception:
        pass

def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
