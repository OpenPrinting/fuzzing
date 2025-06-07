#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <cups/ipp.h>
#include "file.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Create a temporary file name using the process ID to avoid conflicts
    char filename[256];
    snprintf(filename, sizeof(filename), "/tmp/fuzz_input_%d.ipp", getpid());

    // Open the file for writing
    cups_file_t *file = cupsFileOpen(filename, "w");
    if (!file) {
        return 0; // Cannot open file, return
    }

    // Write the fuzzing data to the file
    if (cupsFileWrite(file, (const char *)data, size) != (ssize_t)size) {
        cupsFileClose(file);
        unlink(filename); // Clean up the file
        return 0; // Write error, return
    }

    // Close the file after writing
    cupsFileClose(file);

    // Reopen the file for reading
    file = cupsFileOpen(filename, "r");
    if (!file) {
        unlink(filename); // Clean up the file
        return 0; // Cannot reopen file, return
    }

    // Create a new IPP request and response objects
    ipp_t *request = ippNew();
    ipp_t *response = ippNew();

    // Use ippReadIO with cupsFileRead callback to process the input
    ipp_state_t state = ippReadIO(file, (ipp_io_cb_t)cupsFileRead, 1, request, response);

    // Cleanup
    ippDelete(request);
    ippDelete(response);
    cupsFileClose(file);
    unlink(filename); // Remove the temporary file

    return 0;
}
