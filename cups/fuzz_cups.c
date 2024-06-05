/*
 * Fuzztest for `_cupsRasterExecPS`.
 *
 * Copyright © 2024 by OpenPrinting.
 *
 * Licensed under Apache License v2.0.  See the file "LICENSE" for more
 * information.
 */

#undef _CUPS_NO_DEPRECATED
#include <cups-private.h>
#include <ppd-private.h>
#include <raster-private.h>

#define kMinInputLength 2
#define kMaxInputLength 2048

extern int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    int	                 p_bits;
    char                 *data_in;
    cups_page_header2_t	 header;

    if (size < kMinInputLength || size > kMaxInputLength) {
        return 0;
    }

    /* Add NUL byte. */
    data_in = calloc(size + 1, sizeof(char));
    if(data_in == NULL) {
        return 0;
    }

    memcpy(data_in, data, size);

    memset(&header, 0, sizeof(header));
    header.Collate = CUPS_TRUE;
    p_bits = 0;

    _cupsRasterExecPS(&header, &p_bits, data_in);

    free(data_in);
    return 0;
}
