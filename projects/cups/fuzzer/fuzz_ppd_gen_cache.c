#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ppd.h"
#include "cups.h"
#include "ipp.h"
#include "file-private.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    // Create a temporary file to simulate a PPD file
    char filename[256];
    snprintf(filename, sizeof(filename), "/tmp/fuzz_ppd_%d.ppd", getpid());
    FILE *file = fopen(filename, "wb");
    if (!file)
        return 0;
    fwrite(data, 1, size, file);
    fclose(file);

    // Open the PPD file
    ppd_file_t *ppd = ppdOpenFile(filename);
    if (!ppd)
    {
        remove(filename);
        return 0;
    }

    // Create a cache with the PPD
    ipp_t *attrs = ippNew(); // Create a new IPP attributes object
    _ppd_cache_t *cache = _ppdCacheCreateWithPPD(attrs, ppd);
    if (cache)
    {
        // Optionally write the cache to a file
        char cache_filename[256];
        snprintf(cache_filename, sizeof(cache_filename), "/tmp/fuzz_cache_%d.cache", getpid());
        _ppdCacheWriteFile(cache, cache_filename, attrs);

        // Retrieve data from the cache
        _ppdCacheGetBin(cache, "output-bin");
        int exact;
        _ppdCacheGetPageSize(cache, attrs, "page-size", &exact);

        // Destroy the cache
        _ppdCacheDestroy(cache);

        // Clean up the cache file
        remove(cache_filename);
    }

    // Clean up IPP attributes
    ippDelete(attrs);

    // Close the PPD file
    ppdClose(ppd);

    // Remove the temporary PPD file
    remove(filename);

    return 0;
}
