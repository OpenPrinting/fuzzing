#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "ppd.h"
#include "cups.h"
#include "file-private.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return 0; // Ensure there is at least some data

    // Use process ID to create a unique temporary filename
    char filename[256];
    snprintf(filename, sizeof(filename), "/tmp/fuzz_ppd_%d.ppd", getpid());

    // Write the fuzz data to a temporary file
    FILE *file = fopen(filename, "wb");
    if (!file) return 0;
    fwrite(data, 1, size, file);
    fclose(file);

    // Attempt to open the PPD file
    ppd_file_t *ppd = ppdOpenFile(filename);
    if (ppd) {
        // Fuzz ppdMarkOption
        if (size > 2) {
            ppdMarkOption(ppd, (const char *)data, (const char *)(data + 1));
        }

        // Fuzz ppdFindMarkedChoice
        if (size > 3) {
            ppdFindMarkedChoice(ppd, (const char *)(data + 2));
        }

        // Fuzz ppdInstallableConflict
        if (size > 4) {
            ppdInstallableConflict(ppd, (const char *)(data + 3), (const char *)(data + 4));
        }

        // Close the PPD file
        ppdClose(ppd);
    }

    // Fuzz cupsGetOption
    if (size > 5) {
        cups_option_t options[1];
        options[0].name = (char *)data;
        options[0].value = (char *)(data + 1);
        cupsGetOption((const char *)(data + 5), 1, options);
    }

    // Clean up the temporary file
    unlink(filename);

    return 0;
}
