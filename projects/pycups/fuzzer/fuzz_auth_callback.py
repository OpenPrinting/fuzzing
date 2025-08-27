#!/usr/bin/python3
import sys
import atheris
import cups

# callback that returns fuzzed password strings
class PasswordCallback:
    def __init__(self, fdp):
        self.fdp = fdp
        self.call_count = 0

    def __call__(self, prompt: str, conn, method: str, resource: str, context=None):
        self.call_count += 1
        #return the fuzzed UTF-8 password
        length = self.fdp.ConsumeIntInRange(0, 64)
        pw_bytes = self.fdp.ConsumeBytes(length)
        try:
            return pw_bytes.decode('utf-8', errors='ignore')
        except Exception:
            return ""

def TestOneInput(data: bytes):
    if len(data) < 4:
        return

    fdp = atheris.FuzzedDataProvider(data)

    try:
        #connection object
        conn = cups.Connection()

        # fuzzed prompt/method/resource strings
        prompt = fdp.ConsumeUnicodeNoSurrogates(20)
        method = fdp.ConsumeUnicodeNoSurrogates(20)
        resource = fdp.ConsumeUnicodeNoSurrogates(20)

        context_choice = fdp.ConsumeIntInRange(0, 1)
        context = {} if context_choice else None

        #assigning the fuzzed callback to simulate cups password callback
        conn.cb_password_callback = PasswordCallback(fdp)

        #simulate calling password_callback
        try:
            result = conn.password_callback(
                newstyle=fdp.ConsumeBool(),
                prompt=prompt,
                method=method,
                resource=resource,
                user_data=context
            )
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
