#!/usr/bin/python3
import sys
import atheris
import cups

def TestOneInput(data: bytes):
    if len(data) < 8:
        return
        
    fdp = atheris.FuzzedDataProvider(data)
    
    try:
        conn = cups.Connection()
        
        #generating the fuzzed parameters
        printer = fdp.ConsumeUnicodeNoSurrogates(64)
        filename = fdp.ConsumeUnicodeNoSurrogates(128)
        title = fdp.ConsumeUnicodeNoSurrogates(64)
        
        #building fuzzed options dict
        options = {}
        num_opts = fdp.ConsumeIntInRange(0, 5)
        for i in range(num_opts):
            if fdp.remaining_bytes() < 4:
                break
            key = fdp.ConsumeUnicodeNoSurrogates(32)
            val = fdp.ConsumeUnicodeNoSurrogates(64)
            if key:  #skip any empty keys
                options[key] = val
                
        #calling the target
        conn.printFile(printer, filename, title, options)
        
    except cups.IPPError:
        pass
    except RuntimeError:
        pass
    except Exception:
        pass

def main():
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()

if __name__ == "__main__":
    main()