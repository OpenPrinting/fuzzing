#!/usr/bin/python3
import sys
import atheris
import cups

# callback to provide fuzzed data for readIO
class ReadCallback:
    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0
        
    def __call__(self, size: int):
        if self.offset >= len(self.data) or size <= 0:
            return b""
        chunk = self.data[self.offset:self.offset + size]
        self.offset += size
        return chunk

# callback to receive data from writeIO
class WriteCallback:
    def __init__(self):
        self.collected = b""
        self.call_count = 0
        
    def __call__(self, buf: bytes):
        self.call_count += 1
        if not buf:
            return 0
        self.collected += buf
        return len(buf)

# callback that raises errors
class ErrorCallback:
    def __init__(self, error_on_call: int = 1):
        self.call_count = 0
        self.error_on_call = error_on_call
        
    def __call__(self, *args):
        self.call_count += 1
        if self.call_count == self.error_on_call:
            raise RuntimeError("Callback error")
        return b"" if len(args) == 1 and isinstance(args[0], int) else len(args[0]) if args else 0

def TestOneInput(data: bytes):
    if len(data) < 4:
        return

    fdp = atheris.FuzzedDataProvider(data)
    
    try:
        req = cups.IPPRequest()  #create the IPP request object
        operation = fdp.ConsumeIntInRange(0, 3)

        #selecting fuzzing scenario
        if operation == 0:
            cb = ReadCallback(fdp.ConsumeBytes(1024))
            req.readIO(cb, blocking=fdp.ConsumeBool())
        elif operation == 1:
            cb = WriteCallback()
            req.writeIO(cb, blocking=fdp.ConsumeBool())
        elif operation == 2:
            cb = ErrorCallback(fdp.ConsumeIntInRange(1, 5))
            req.readIO(cb, blocking=fdp.ConsumeBool())
        else:
            cb = ErrorCallback(fdp.ConsumeIntInRange(1, 5))
            req.writeIO(cb, blocking=fdp.ConsumeBool())

        if fdp.remaining_bytes() > 0 and hasattr(req, 'setChunkSize'):
            req.setChunkSize(fdp.ConsumeIntInRange(1, 8192))

    except Exception:
        pass

def main():
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
