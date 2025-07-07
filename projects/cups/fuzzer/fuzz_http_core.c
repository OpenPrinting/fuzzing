/*
 * HTTP Core Functions Fuzzer for CUPS
 *
 * This fuzzer tests core HTTP functionality including connection management,
 * field parsing, URI handling, and data transfer functions.
 *
 * Licensed under Apache License v2.0.
 * See the file "LICENSE" for more information.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include "cups.h"
#include "http.h"
#include "cups-private.h"

// Global variables for cleanup
static char *g_temp_file = NULL;

// Cleanup function
static void cleanup_files(void)
{
    if (g_temp_file)
    {
        unlink(g_temp_file);
        free(g_temp_file);
        g_temp_file = NULL;
    }
}

// Parse input data into segments
static int parse_http_segments(const uint8_t *data, size_t size,
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

// Test HTTP URI functions
static void test_http_uri_functions(const uint8_t **segments, size_t *seg_sizes, int num_segments)
{
    if (num_segments < 1)
        return;

    // Test httpAssembleURI
    char uri_buffer[2048];
    char scheme[64] = "http";
    char hostname[256] = "localhost";
    char resource[1024] = "/";
    char username[128] = "";
    int port = 80;

    if (seg_sizes[0] > 0)
    {
        size_t copy_len = seg_sizes[0] < sizeof(hostname) - 1 ? seg_sizes[0] : sizeof(hostname) - 1;
        memcpy(hostname, segments[0], copy_len);
        hostname[copy_len] = '\0';

        // Ensure null termination and basic cleanup
        for (size_t i = 0; i < copy_len; i++)
        {
            if (hostname[i] == 0 || hostname[i] < 32 || hostname[i] > 126)
            {
                hostname[i] = 'a';
            }
        }
    }

    httpAssembleURI(HTTP_URI_CODING_ALL, uri_buffer, sizeof(uri_buffer),
                    scheme, username, hostname, port, resource);

    // Test httpSeparateURI
    if (num_segments > 1 && seg_sizes[1] > 0)
    {
        char test_uri[1024];
        size_t copy_len = seg_sizes[1] < sizeof(test_uri) - 1 ? seg_sizes[1] : sizeof(test_uri) - 1;
        memcpy(test_uri, segments[1], copy_len);
        test_uri[copy_len] = '\0';

        char sep_scheme[64], sep_username[128], sep_hostname[256], sep_resource[512];
        int sep_port;

        httpSeparateURI(HTTP_URI_CODING_ALL, test_uri,
                        sep_scheme, sizeof(sep_scheme),
                        sep_username, sizeof(sep_username),
                        sep_hostname, sizeof(sep_hostname),
                        &sep_port,
                        sep_resource, sizeof(sep_resource));
    }
}

// Test HTTP field functions
static void test_http_field_functions(const uint8_t **segments, size_t *seg_sizes, int num_segments)
{
    // Test httpFieldValue
    if (num_segments > 2 && seg_sizes[2] > 0)
    {
        char field_name[128];
        size_t copy_len = seg_sizes[2] < sizeof(field_name) - 1 ? seg_sizes[2] : sizeof(field_name) - 1;
        memcpy(field_name, segments[2], copy_len);
        field_name[copy_len] = '\0';

        // Ensure printable characters
        for (size_t i = 0; i < copy_len; i++)
        {
            if (field_name[i] < 32 || field_name[i] > 126)
            {
                field_name[i] = 'A';
            }
        }

        http_field_t field = httpFieldValue(field_name);
        (void)field; // Suppress unused variable warning
    }

    // Test httpGetDateString
    time_t test_time = time(NULL);
    const char *date_str = httpGetDateString(test_time);
    (void)date_str;

    // Test httpGetDateTime
    if (num_segments > 3 && seg_sizes[3] > 0)
    {
        char date_string[128];
        size_t copy_len = seg_sizes[3] < sizeof(date_string) - 1 ? seg_sizes[3] : sizeof(date_string) - 1;
        memcpy(date_string, segments[3], copy_len);
        date_string[copy_len] = '\0';

        time_t parsed_time = httpGetDateTime(date_string);
        (void)parsed_time;
    }
}

// Test HTTP encoding functions
static void test_http_encoding_functions(const uint8_t **segments, size_t *seg_sizes, int num_segments)
{
    if (num_segments > 4 && seg_sizes[4] > 0)
    {
        // Test httpEncode64_2
        char input_data[512];
        char encoded_buffer[1024];
        char decoded_buffer[512];

        size_t copy_len = seg_sizes[4] < sizeof(input_data) - 1 ? seg_sizes[4] : sizeof(input_data) - 1;
        memcpy(input_data, segments[4], copy_len);

        httpEncode64_2(encoded_buffer, sizeof(encoded_buffer), input_data, copy_len);

        // Test httpDecode64_3
        size_t decoded_len = sizeof(decoded_buffer);
        const char *end_ptr = NULL;
        httpDecode64_3(decoded_buffer, &decoded_len, encoded_buffer, &end_ptr);
    }

    if (num_segments > 5 && seg_sizes[5] > 0)
    {
        // Test httpEncode64_3 with URL encoding
        char url_input[256];
        char url_encoded[512];

        size_t copy_len = seg_sizes[5] < sizeof(url_input) - 1 ? seg_sizes[5] : sizeof(url_input) - 1;
        memcpy(url_input, segments[5], copy_len);

        httpEncode64_3(url_encoded, sizeof(url_encoded), url_input, copy_len, true);
    }
}

// Test HTTP address functions
static void test_http_address_functions(const uint8_t **segments, size_t *seg_sizes, int num_segments)
{
    if (num_segments > 6 && seg_sizes[6] > 0)
    {
        char hostname[256];
        size_t copy_len = seg_sizes[6] < sizeof(hostname) - 1 ? seg_sizes[6] : sizeof(hostname) - 1;
        memcpy(hostname, segments[6], copy_len);
        hostname[copy_len] = '\0';

        // Clean hostname
        for (size_t i = 0; i < copy_len; i++)
        {
            if (hostname[i] < 32 || hostname[i] > 126)
            {
                hostname[i] = 'a';
            }
        }

        // Test httpAddrGetList
        http_addrlist_t *addrlist = httpAddrGetList(hostname, AF_UNSPEC, "80");
        if (addrlist)
        {
            // Test httpAddrGetString
            char addr_string[256];
            httpAddrGetString(&addrlist->addr, addr_string, sizeof(addr_string));

            // Test httpAddrGetPort and httpAddrGetFamily
            int port = httpAddrGetPort(&addrlist->addr);
            int family = httpAddrGetFamily(&addrlist->addr);
            (void)port;
            (void)family;

            // Test httpAddrIsLocalhost and httpAddrIsAny
            bool is_localhost = httpAddrIsLocalhost(&addrlist->addr);
            bool is_any = httpAddrIsAny(&addrlist->addr);
            (void)is_localhost;
            (void)is_any;

            httpAddrFreeList(addrlist);
        }
    }
}

// Test HTTP connection simulation
static void test_http_connection_simulation(const uint8_t **segments, size_t *seg_sizes, int num_segments)
{
    if (num_segments > 7 && seg_sizes[7] > 0)
    {
        // Create a simple mock HTTP server data
        char mock_response[1024];
        size_t copy_len = seg_sizes[7] < sizeof(mock_response) - 1 ? seg_sizes[7] : sizeof(mock_response) - 1;
        memcpy(mock_response, segments[7], copy_len);
        mock_response[copy_len] = '\0';

        // Write mock data to temp file for testing
        g_temp_file = malloc(256);
        if (g_temp_file)
        {
            snprintf(g_temp_file, 256, "/tmp/cursor_test_http_%d.txt", getpid());

            FILE *fp = fopen(g_temp_file, "w");
            if (fp)
            {
                fwrite(mock_response, 1, copy_len, fp);
                fclose(fp);
            }
        }
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    // Minimum size check
    if (size < 50)
    {
        return 0;
    }

    // Setup cleanup
    atexit(cleanup_files);

    // Parse input segments
    const uint8_t *segments[10];
    size_t seg_sizes[10];
    int num_segments = parse_http_segments(data, size, segments, seg_sizes, 10);

    if (num_segments < 1)
    {
        return 0;
    }

    // Initialize HTTP subsystem
    httpInitialize();

    // Test various HTTP functionality groups
    test_http_uri_functions(segments, seg_sizes, num_segments);
    test_http_field_functions(segments, seg_sizes, num_segments);
    test_http_encoding_functions(segments, seg_sizes, num_segments);
    test_http_address_functions(segments, seg_sizes, num_segments);
    test_http_connection_simulation(segments, seg_sizes, num_segments);

    // Cleanup
    cleanup_files();

    return 0;
}