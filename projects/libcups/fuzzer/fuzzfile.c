/*
 * File I/O Fuzzer for libcups
 *
 * This fuzzer tests file operations including opening, reading, writing,
 * seeking, and file manipulation functionality in the libcups library.
 *
 * Licensed under Apache License v2.0.
 * See the file "LICENSE" for more information.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include "cups.h"
#include "file.h"
#include "dir.h"

// Global variables for cleanup
static char *g_temp_files[16];
static int g_temp_file_count = 0;

// Cleanup function
static void cleanup_files(void)
{
    for (int i = 0; i < g_temp_file_count; i++)
    {
        if (g_temp_files[i])
        {
            unlink(g_temp_files[i]);
            free(g_temp_files[i]);
            g_temp_files[i] = NULL;
        }
    }
    g_temp_file_count = 0;
}

// Add temp file to cleanup list
static void add_temp_file(const char *filename)
{
    if (g_temp_file_count < 16)
    {
        g_temp_files[g_temp_file_count] = strdup(filename);
        g_temp_file_count++;
    }
}

// Parse input data into segments
static int parse_file_segments(const uint8_t *data, size_t size,
                               const uint8_t **segments, size_t *seg_sizes, int max_segments)
{
    if (size < 4)
        return 0;

    uint32_t num_segments = *(uint32_t *)data % max_segments + 1;
    data += 4;
    size -= 4;

    size_t pos = 0;
    int count = 0;

    for (uint32_t i = 0; i < num_segments && count < max_segments && pos < size; i++)
    {
        if (pos + 2 >= size)
            break;

        uint16_t seg_len = *(uint16_t *)(data + pos) % (size - pos - 2) + 1;
        pos += 2;

        if (pos + seg_len <= size)
        {
            segments[count] = data + pos;
            seg_sizes[count] = seg_len;
            count++;
            pos += seg_len;
        }
    }

    return count;
}

// Test basic file operations
static void test_file_basic_operations(const uint8_t *data, size_t size)
{
    if (size == 0)
        return;

    char filename[256];
    snprintf(filename, sizeof(filename), "/tmp/fuzz_file_%d_%zu.test", getpid(), size);
    add_temp_file(filename);

    cups_file_t *fp = NULL;

    // Test cupsFileOpen for writing
    fp = cupsFileOpen(filename, "w");
    if (fp)
    {
        // Test cupsFileWrite
        size_t written = cupsFileWrite(fp, (char *)data, size);
        (void)written;

        // Test cupsFilePrintf
        cupsFilePrintf(fp, "\nTest line %zu\n", size);

        // Test cupsFilePuts
        cupsFilePuts(fp, "Test string\n");

        // Test cupsFilePutChar
        cupsFilePutChar(fp, 'X');

        // Test cupsFileFlush
        cupsFileFlush(fp);

        // Test cupsFileClose
        cupsFileClose(fp);
    }

    // Test cupsFileOpen for reading
    fp = cupsFileOpen(filename, "r");
    if (fp)
    {
        // Test cupsFileRead
        char buffer[1024];
        size_t bytes_read = cupsFileRead(fp, buffer, sizeof(buffer) - 1);
        if (bytes_read > 0)
        {
            buffer[bytes_read] = '\0';
        }

        // Test cupsFileRewind
        cupsFileRewind(fp);

        // Test cupsFileGets
        char line_buffer[256];
        while (cupsFileGets(fp, line_buffer, sizeof(line_buffer)))
        {
            // Process line
        }

        // Test cupsFileRewind again
        cupsFileRewind(fp);

        // Test cupsFileGetChar
        int ch;
        while ((ch = cupsFileGetChar(fp)) != EOF)
        {
            // Process character
        }

        // Test cupsFileTell and cupsFileSeek
        off_t pos = cupsFileTell(fp);
        cupsFileSeek(fp, 0);
        cupsFileSeek(fp, pos);

        // Test cupsFileNumber
        int fd = cupsFileNumber(fp);
        (void)fd;

        // Test cupsFileIsCompressed
        bool compressed = cupsFileIsCompressed(fp);
        (void)compressed;

        cupsFileClose(fp);
    }
}

// Test compressed file operations
static void test_file_compression(const uint8_t *data, size_t size)
{
    if (size == 0)
        return;

    char filename[256];
    snprintf(filename, sizeof(filename), "/tmp/fuzz_compressed_%d_%zu.gz", getpid(), size);
    add_temp_file(filename);

    cups_file_t *fp = NULL;

    // Test writing compressed file
    fp = cupsFileOpen(filename, "w9"); // 9 = maximum compression
    if (fp)
    {
        cupsFileWrite(fp, (char *)data, size);
        cupsFilePrintf(fp, "\nCompressed data test\n");
        cupsFileClose(fp);

        // Test reading compressed file
        fp = cupsFileOpen(filename, "r");
        if (fp)
        {
            char buffer[2048];
            size_t read_size = cupsFileRead(fp, buffer, sizeof(buffer) - 1);
            (void)read_size;

            // Test compressed file properties
            bool is_compressed = cupsFileIsCompressed(fp);
            (void)is_compressed;

            cupsFileClose(fp);
        }
    }
}

// Test file finding and path operations
static void test_file_path_operations(const uint8_t *data, size_t size)
{
    if (size < 16)
        return;

    // Create test file in current directory
    char test_filename[64];
    snprintf(test_filename, sizeof(test_filename), "test_find_%d.tmp", data[0] | (data[1] << 8));
    add_temp_file(test_filename);

    cups_file_t *fp = cupsFileOpen(test_filename, "w");
    if (fp)
    {
        cupsFileWrite(fp, "test content", 12);
        cupsFileClose(fp);

        // Test cupsFileFind
        char found_path[1024];
        if (cupsFileFind(test_filename, ".", 1, found_path, sizeof(found_path)))
        {
            // File found
        }

        // Test with multiple search paths
        if (cupsFileFind(test_filename, ".:/tmp", 1, found_path, sizeof(found_path)))
        {
            // File found in search path
        }
    }
}

// Test directory operations
static void test_directory_operations(const uint8_t *data, size_t size)
{
    if (size < 4)
        return;

    char dirname[256];
    snprintf(dirname, sizeof(dirname), "/tmp/fuzz_dir_%d_%zu", getpid(), size);

    // Create test directory
    if (mkdir(dirname, 0755) == 0)
    {
        // Create some test files in the directory
        for (int i = 0; i < 3 && i < size; i++)
        {
            char filepath[512];
            snprintf(filepath, sizeof(filepath), "%s/file_%d.txt", dirname, i);

            cups_file_t *fp = cupsFileOpen(filepath, "w");
            if (fp)
            {
                cupsFilePrintf(fp, "File %d content: %d\n", i, data[i]);
                cupsFileClose(fp);
            }
        }

        // Test cupsDirOpen
        cups_dir_t *dir = cupsDirOpen(dirname);
        if (dir)
        {
            // Test cupsDirRead
            cups_dentry_t *entry;
            while ((entry = cupsDirRead(dir)) != NULL)
            {
                // Process directory entry
                const char *filename = entry->filename;
                (void)filename;
            }

            // Test cupsDirRewind
            cupsDirRewind(dir);

            // Read again after rewind
            entry = cupsDirRead(dir);
            (void)entry;

            cupsDirClose(dir);
        }

        // Cleanup directory and files
        for (int i = 0; i < 3 && i < size; i++)
        {
            char filepath[512];
            snprintf(filepath, sizeof(filepath), "%s/file_%d.txt", dirname, i);
            unlink(filepath);
        }
        rmdir(dirname);
    }
}

// Test file locking operations
static void test_file_locking(const uint8_t *data, size_t size)
{
    if (size < 8)
        return;

    char filename[256];
    snprintf(filename, sizeof(filename), "/tmp/fuzz_lock_%d_%zu.test", getpid(), size);
    add_temp_file(filename);

    cups_file_t *fp = cupsFileOpen(filename, "w+");
    if (fp)
    {
        // Write some data
        cupsFileWrite(fp, (char *)data, size);

        // Test cupsFileLock
        int lock_result = cupsFileLock(fp, 1); // blocking lock
        (void)lock_result;

        // Test cupsFileUnlock
        int unlock_result = cupsFileUnlock(fp);
        (void)unlock_result;

        // Test non-blocking lock
        lock_result = cupsFileLock(fp, 0); // non-blocking
        if (lock_result == 0)
        {
            cupsFileUnlock(fp);
        }

        cupsFileClose(fp);
    }
}

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0 || size > 65536)
    {
        return 0;
    }

    // Setup cleanup handler
    atexit(cleanup_files);

    const uint8_t *segments[8];
    size_t seg_sizes[8];
    int num_segments = parse_file_segments(data, size, segments, seg_sizes, 8);

    // Test 1: Basic file operations
    for (int i = 0; i < num_segments; i++)
    {
        test_file_basic_operations(segments[i], seg_sizes[i]);
    }

    // Test 2: Compressed file operations
    if (size >= 16)
    {
        test_file_compression(data, size);
    }

    // Test 3: File path and finding operations
    test_file_path_operations(data, size);

    // Test 4: Directory operations
    test_directory_operations(data, size);

    // Test 5: File locking operations
    if (size >= 8)
    {
        test_file_locking(data, size);
    }

    // Cleanup
    cleanup_files();

    return 0;
}