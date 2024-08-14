//
// Dither test program for libcupsfilters.
//
// Try the following:
//
//       testdither 0 255 > filename.ppm
//       testdither 0 127 255 > filename.ppm
//       testdither 0 85 170 255 > filename.ppm
//       testdither 0 63 127 170 198 227 255 > filename.ppm
//       testdither 0 210 383 > filename.ppm
//       testdither 0 82 255 > filename.ppm
//
// Copyright 2007-2011 by Apple Inc.
// Copyright 1993-2005 by Easy Software Products.
//
// Licensed under Apache License v2.0.  See the file "LICENSE" for more
// information.
//
// Contents:
//
//   main()  - Test dithering and output a PPM file.
//

//
// Include necessary headers.
//

#include "driver.h"
#include "filter.h"
#include <config.h>
#include <string.h>
#include <ctype.h>

#define MAX_INT 2147483647

cf_logfunc_t logfunc = cfCUPSLogFunc;    // Log function
void         *ld = NULL;                 // Log function data

//
// Local functions...
//

// fuzz entry point
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {

  if (Size < 4) {
    return 0;
  }

  // redirect_stdout_stderr();

  int		x, y;		// Current coordinate in image
  short		line[512];	// Line to dither
  unsigned char	pixels[512],	// Dither pixels
		*pixptr;	// Pointer in line
  int		output;		// Output pixel
  cf_lut_t	*lut;		// Dither lookup table
  cf_dither_t	*dither;	// Dither state
  int		nlutvals;	// Number of lookup values
  float		lutvals[16];	// Lookup values
  int		pixvals[16];	// Pixel values

  // Export to Static Location
  freopen("/tmp/test", "w", stdout);

  // Static Input Param
  // int argc = 4;
  // char *argv[4];  
  // argv[0] = "2";
  // argv[1] = "4";
  // argv[2] = "6";
  // argv[3] = "8";

  int argc = (Data[0] % 15) + 2;

  if (Size < (size_t)(argc + 1)) {
        return 0;
    }

  char **argv = (char **)malloc(argc * sizeof(char *));
    if (!argv) {
        free(argv);
        return 0;
    }
  
  for (int i = 0; i < argc; i++) {
    if (Size < (i + 1) * sizeof(int)) {
        break;
    }

    int num = abs((int)Data[i % Size]); 
    argv[i] = (char *)malloc(12);
    if (!argv[i]) {
      for (int j = 0; j < i; j++) {
        free(argv[j]);
      }
      free(argv);
      return 0;
    }
    snprintf(argv[i], 12, "%d", num);
  }

  //
  // See if we have lookup table values on the command-line...
  //

  if (argc > 1)
  {
    //
    // Yes, collect them...
    //

    nlutvals = 0;

    for (x = 1; x < argc; x ++)
      if (isdigit(argv[x][0]) && nlutvals < 16)
      {
        pixvals[nlutvals] = atoi(argv[x]);
        lutvals[nlutvals] = atof(argv[x]) / 255.0;
	nlutvals ++;
      }
      else
        free(argv);
        return 0;

    //
    // See if we have at least 2 values...
    //

    if (nlutvals < 2)
      free(argv);
      return 0;
  }
  else
  {
    //
    // Otherwise use the default 2-entry LUT with values of 0 and 255...
    //

    nlutvals   = 2;
    lutvals[0] = 0.0;
    lutvals[1] = 1.0;
    pixvals[0] = 0;
    pixvals[1] = 255;
  }

  //
  // Create the lookup table and dither state...
  //

  lut    = cfLutNew(nlutvals, lutvals, logfunc, ld);
  dither = cfDitherNew(512);

  //
  // Put out the PGM header for a raw 256x256x8-bit grayscale file...
  //

  puts("P5\n512\n512\n255");

  //
  // Dither 512 lines, which are written out in 256 image lines...
  //

  for (y = 0; y < 512; y ++)
  {
    //
    // Create the grayscale data for the current line...
    //

    for (x = 0; x < 512; x ++)
      line[x] = 4095 * ((y / 32) * 16 + x / 32) / 255;

    //
    // Dither the line...
    //

    cfDitherLine(dither, lut, line, 1, pixels);

    if (y == 0)
    {
      fputs("DEBUG: pixels =", stderr);
      for (x = 0; x < 512; x ++)
        fprintf(stderr, " %d", pixels[x]);
      fputs("\n", stderr);
    }

    //
    // Add or set the output pixel values...
    //

    for (x = 0, pixptr = pixels; x < 512; x ++, pixptr ++)
    {
      output = 255 - pixvals[*pixptr];

      if (output < 0)
	putchar(0);
      else
	putchar(output);
    }
  }

  //
  // Free the dither state and lookup table...
  //

  cfDitherDelete(dither);
  cfLutDelete(lut);

  //
  // Return with no errors...
  //

  fclose(stdout);
  free(argv);
  return (0);
}