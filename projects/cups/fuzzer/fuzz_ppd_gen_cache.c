#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include "ppd.h"
#include "ppd-private.h"
#include "cups.h"
#include "ipp.h"
#include "file-private.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1)
        return 0;

    char filename[256];
    snprintf(filename, sizeof(filename), "/tmp/fuzz_ppd_%d.ppd", getpid());

    // Write the input data to a temporary file
    FILE *file = fopen(filename, "wb");
    if (!file)
        return 0;
    fwrite(data, 1, size, file);
    fclose(file);

    // Open the PPD file
    ppd_file_t *ppd = ppdOpenFile(filename);
    if (ppd)
    {
        // Create a cache from the PPD file
        _ppd_cache_t *cache = _ppdCacheCreateWithPPD(NULL, ppd);
        if (cache)
        {
            // Use the cache
            _ppdCacheWriteFile(cache, filename, NULL);
            _ppdCacheGetBin(cache, "output-bin");
            int exact;
            _ppdCacheGetPageSize(cache, NULL, "keyword", &exact);

            // Destroy the cache
            _ppdCacheDestroy(cache);
        }

        // Close the PPD file
        ppdClose(ppd);
    }

    // Clean up the temporary file
    unlink(filename);

    return 0;
}
