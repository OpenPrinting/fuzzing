#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "ppd.h"
#include "cups.h"
#include "file-private.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    // Create a temporary file to simulate a PPD file
    char filename[256];
    snprintf(filename, sizeof(filename), "/tmp/fuzz_ppd_%d.ppd", getpid());

    FILE *file = fopen(filename, "wb");
    if (!file)
    {
        return 0; // Could not create file, exit
    }

    fwrite(data, 1, size, file);
    fclose(file);

    // Open the PPD file
    ppd_file_t *ppd = ppdOpenFile(filename);
    if (!ppd)
    {
        unlink(filename);
        return 0; // Could not open PPD file, exit
    }

    // Mark default options
    ppdMarkDefaults(ppd);

    // Check for conflicts
    int conflicts = ppdConflicts(ppd);

    // Optionally mark options (using dummy options for demonstration)
    cups_option_t options[1];
    options[0].name = "OptionName";
    options[0].value = "OptionValue";
    cupsMarkOptions(ppd, 1, options);

    // Close the PPD file
    ppdClose(ppd);

    // Clean up the temporary file
    unlink(filename);

    return 0;
}
