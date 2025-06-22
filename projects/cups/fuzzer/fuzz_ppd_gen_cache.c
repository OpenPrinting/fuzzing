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

// Global variables for cleanup
static char *g_ppd_file = NULL;
static char *g_cache_file = NULL;

// Cleanup function
static void cleanup_files(void)
{
    if (g_ppd_file)
    {
        unlink(g_ppd_file);
        free(g_ppd_file);
        g_ppd_file = NULL;
    }
    if (g_cache_file)
    {
        unlink(g_cache_file);
        free(g_cache_file);
        g_cache_file = NULL;
    }
}

// Parse input data into segments
static int parse_input_segments(const uint8_t *data, size_t size,
                                const uint8_t **segments, size_t *seg_sizes, int max_segments)
{
    if (size < 4)
        return 0;

    uint32_t num_segments = *(uint32_t *)data;
    if (num_segments == 0 || num_segments > max_segments)
        return 0;

    const uint8_t *ptr = data + 4;
    size_t remaining = size - 4;

    for (uint32_t i = 0; i < num_segments && i < max_segments; i++)
    {
        if (remaining < 4)
            return i;

        uint32_t seg_len = *(uint32_t *)ptr;
        ptr += 4;
        remaining -= 4;

        if (seg_len > remaining)
            return i;

        segments[i] = ptr;
        seg_sizes[i] = seg_len;
        ptr += seg_len;
        remaining -= seg_len;
    }

    return num_segments;
}

// Create a simple IPP job for testing
static ipp_t *create_test_job(const uint8_t *data, size_t size)
{
    ipp_t *job = ippNew();
    if (!job)
        return NULL;

    // Add some basic attributes using fuzz data
    if (size > 10)
    {
        char media_name[64];
        snprintf(media_name, sizeof(media_name), "media-%02x%02x", data[0], data[1]);
        ippAddString(job, IPP_TAG_JOB, IPP_TAG_KEYWORD, "media", NULL, media_name);
    }

    if (size > 20)
    {
        char source_name[64];
        snprintf(source_name, sizeof(source_name), "source-%02x%02x", data[10], data[11]);
        ippAddString(job, IPP_TAG_JOB, IPP_TAG_KEYWORD, "media-source", NULL, source_name);
    }

    if (size > 30)
    {
        char type_name[64];
        snprintf(type_name, sizeof(type_name), "type-%02x%02x", data[20], data[21]);
        ippAddString(job, IPP_TAG_JOB, IPP_TAG_KEYWORD, "media-type", NULL, type_name);
    }

    return job;
}

// Test all cache GET functions
static void test_cache_functions(_ppd_cache_t *pc, ppd_file_t *ppd, const uint8_t **segments, size_t *seg_sizes, int num_segments)
{
    if (!pc)
        return;

    // Test _ppdCacheGetBin
    if (num_segments > 4 && seg_sizes[4] > 0)
    {
        char bin_name[256];
        size_t copy_len = seg_sizes[4] < sizeof(bin_name) - 1 ? seg_sizes[4] : sizeof(bin_name) - 1;
        memcpy(bin_name, segments[4], copy_len);
        bin_name[copy_len] = '\0';

        const char *result = _ppdCacheGetBin(pc, bin_name);
        (void)result; // Suppress unused variable warning
    }

    // Test _ppdCacheGetOutputBin
    if (num_segments > 4 && seg_sizes[4] > 0)
    {
        char output_bin[256];
        size_t copy_len = seg_sizes[4] < sizeof(output_bin) - 1 ? seg_sizes[4] : sizeof(output_bin) - 1;
        memcpy(output_bin, segments[4], copy_len);
        output_bin[copy_len] = '\0';

        const char *result = _ppdCacheGetOutputBin(pc, output_bin);
        (void)result;
    }

    // Test _ppdCacheGetSource
    if (num_segments > 3 && seg_sizes[3] > 0)
    {
        char input_slot[256];
        size_t copy_len = seg_sizes[3] < sizeof(input_slot) - 1 ? seg_sizes[3] : sizeof(input_slot) - 1;
        memcpy(input_slot, segments[3], copy_len);
        input_slot[copy_len] = '\0';

        const char *result = _ppdCacheGetSource(pc, input_slot);
        (void)result;
    }

    // Test _ppdCacheGetType
    if (num_segments > 2 && seg_sizes[2] > 0)
    {
        char media_type[256];
        size_t copy_len = seg_sizes[2] < sizeof(media_type) - 1 ? seg_sizes[2] : sizeof(media_type) - 1;
        memcpy(media_type, segments[2], copy_len);
        media_type[copy_len] = '\0';

        const char *result = _ppdCacheGetType(pc, media_type);
        (void)result;
    }

    // Test _ppdCacheGetPageSize with keyword
    if (num_segments > 1 && seg_sizes[1] > 0)
    {
        char page_size[256];
        size_t copy_len = seg_sizes[1] < sizeof(page_size) - 1 ? seg_sizes[1] : sizeof(page_size) - 1;
        memcpy(page_size, segments[1], copy_len);
        page_size[copy_len] = '\0';

        int exact = 0;
        const char *result = _ppdCacheGetPageSize(pc, NULL, page_size, &exact);
        (void)result;
    }

    // Test _ppdCacheGetPageSize with IPP job
    if (num_segments > 5 && seg_sizes[5] > 0)
    {
        ipp_t *job = create_test_job(segments[5], seg_sizes[5]);
        if (job)
        {
            int exact = 0;
            const char *result = _ppdCacheGetPageSize(pc, job, NULL, &exact);
            (void)result;
            ippDelete(job);
        }
    }

    // Test _ppdCacheGetInputSlot
    if (num_segments > 5 && seg_sizes[5] > 0)
    {
        ipp_t *job = create_test_job(segments[5], seg_sizes[5]);
        if (job)
        {
            const char *result = _ppdCacheGetInputSlot(pc, job, NULL);
            (void)result;
            ippDelete(job);
        }
    }

    // Test _ppdCacheGetMediaType
    if (num_segments > 5 && seg_sizes[5] > 0)
    {
        ipp_t *job = create_test_job(segments[5], seg_sizes[5]);
        if (job)
        {
            const char *result = _ppdCacheGetMediaType(pc, job, NULL);
            (void)result;
            ippDelete(job);
        }
    }

    // Test _ppdCacheGetSize
    if (num_segments > 1 && seg_sizes[1] > 0)
    {
        char page_size[256];
        size_t copy_len = seg_sizes[1] < sizeof(page_size) - 1 ? seg_sizes[1] : sizeof(page_size) - 1;
        memcpy(page_size, segments[1], copy_len);
        page_size[copy_len] = '\0';

        pwg_size_t *result = _ppdCacheGetSize(pc, page_size, NULL);
        (void)result;
    }

    // Test _ppdCacheGetFinishingValues
    if (ppd)
    {
        int finishings[20];
        int num_finishings = _ppdCacheGetFinishingValues(ppd, pc, 20, finishings);
        (void)num_finishings;
    }

    // Test _ppdCacheGetFinishingOptions
    if (num_segments > 5 && seg_sizes[5] > 0)
    {
        ipp_t *job = create_test_job(segments[5], seg_sizes[5]);
        if (job)
        {
            cups_option_t *options = NULL;
            int num_options = 0;
            num_options = _ppdCacheGetFinishingOptions(pc, job, IPP_FINISHINGS_NONE, num_options, &options);

            if (options)
            {
                cupsFreeOptions(num_options, options);
            }
            ippDelete(job);
        }
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    // Minimum size check
    if (size < 100)
    {
        return 0;
    }

    // Setup cleanup
    atexit(cleanup_files);

    // Create filenames with cursor_test_ prefix
    g_ppd_file = malloc(256);
    g_cache_file = malloc(256);
    if (!g_ppd_file || !g_cache_file)
    {
        cleanup_files();
        return 0;
    }

    snprintf(g_ppd_file, 256, "/tmp/cursor_test_ppd_%d.ppd", getpid());
    snprintf(g_cache_file, 256, "/tmp/cursor_test_cache_%d.cache", getpid());

    // Parse input segments
    const uint8_t *segments[10];
    size_t seg_sizes[10];
    int num_segments = parse_input_segments(data, size, segments, seg_sizes, 10);

    if (num_segments < 1)
    {
        cleanup_files();
        return 0;
    }

    // Write PPD file data
    FILE *file = fopen(g_ppd_file, "wb");
    if (!file)
    {
        cleanup_files();
        return 0;
    }

    fwrite(segments[0], 1, seg_sizes[0], file);
    fclose(file);

    // Open PPD file
    ppd_file_t *ppd = ppdOpenFile(g_ppd_file);
    if (!ppd)
    {
        cleanup_files();
        return 0;
    }

    // Create cache from PPD
    _ppd_cache_t *cache = _ppdCacheCreateWithPPD(NULL, ppd);
    if (!cache)
    {
        ppdClose(ppd);
        cleanup_files();
        return 0;
    }

    // Test all cache functions
    test_cache_functions(cache, ppd, segments, seg_sizes, num_segments);

    // Test cache file write/read cycle
    if (_ppdCacheWriteFile(cache, g_cache_file, NULL))
    {
        ipp_t *attrs = NULL;
        _ppd_cache_t *cache2 = _ppdCacheCreateWithFile(g_cache_file, &attrs);
        if (cache2)
        {
            // Test functions on loaded cache
            test_cache_functions(cache2, ppd, segments, seg_sizes, num_segments);
            _ppdCacheDestroy(cache2);
        }
        if (attrs)
        {
            ippDelete(attrs);
        }
    }

    // Test _cupsConvertOptions if we have enough segments
    if (num_segments > 6 && seg_sizes[6] > 0)
    {
        ipp_t *request = ippNewRequest(IPP_OP_PRINT_JOB);
        if (request)
        {
            cups_option_t *options = NULL;
            int num_options = 0;

            // Parse options from segment data
            char options_str[1024];
            size_t copy_len = seg_sizes[6] < sizeof(options_str) - 1 ? seg_sizes[6] : sizeof(options_str) - 1;
            memcpy(options_str, segments[6], copy_len);
            options_str[copy_len] = '\0';

            num_options = cupsParseOptions(options_str, num_options, &options);

            if (num_options > 0)
            {
                _cupsConvertOptions(request, ppd, cache, NULL, NULL, NULL,
                                    "testuser", "application/pdf", 1, num_options, options);
                cupsFreeOptions(num_options, options);
            }

            ippDelete(request);
        }
    }

    // Cleanup resources
    _ppdCacheDestroy(cache);
    ppdClose(ppd);
    cleanup_files();

    return 0;
}
