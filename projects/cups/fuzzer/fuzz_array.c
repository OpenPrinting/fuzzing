//
// Array fuzz program for CUPS.
//
// Copyright © 2020-2024 by OpenPrinting.
// Copyright © 2007-2014 by Apple Inc.
// Copyright © 1997-2006 by Easy Software Products.
//
// Licensed under Apache License v2.0.  See the file "LICENSE" for more
// information.
//

#include "string-private.h"
#include "debug-private.h"
#include "cups.h"
#include "dir.h"
#include "test-internal.h"

//
// Local functions...
//

// static double	get_seconds(void);
// static int	load_words(const char *filename, cups_array_t *array);

typedef struct {
    char* str1;
    char* str2;
} FuzzArray;

extern void generate_fuzz_array_data(const unsigned char *data, size_t size, FuzzArray *outData);
extern void free_fuzz_array_data(FuzzArray *data);

// fuzz entry point
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  int		i;			// Looping var
  cups_array_t	*array,			// Test array
	  *dup_array;		// Duplicate array
  int		status;			// Exit status
  char		*text;			// Text from array
  // int string_size;
  char		*saved[32];		// Saved entries

  // No errors so far...
  status = 0;

  if (Size < 4) {
    return 0; 
  }

  FuzzArray fuzzInput;
  generate_fuzz_array_data(Data, Size, &fuzzInput);
  char* first_string = fuzzInput.str1;
  char* second_string = fuzzInput.str2;

  // cupsArrayNew()
  array = cupsArrayNew3((cups_array_func_t)_cupsArrayStrcmp, (void *)first_string, NULL, 0, (cups_acopy_cb_t)_cupsArrayStrdup, (cups_afree_cb_t)_cupsArrayFree);

  if (!array)
  {
    printf("returned NULL, expected pointer");
    abort();
  }

  // cupsArrayGetUserData()
  if (cupsArrayGetUserData(array) != first_string)
  {
    printf("returned %p instead of %p", cupsArrayGetUserData(array), first_string);
    abort();
  }

  // cupsArrayAdd()
  if (!cupsArrayAdd(array, second_string))
  {
    printf("Add String Error");
    abort();
  }

  // cupsArrayGetCount()
  cupsArrayGetCount(array);

  // cupsArrayGetFirst()
  text = (char *)cupsArrayGetFirst(array);
  if (text == NULL)
  {
    printf("Error Reading");
  }

  // cupsArrayGetNext()
  text = (char *)cupsArrayGetNext(array);
  if (text == NULL)
  {
    printf("Error Reading");
  }

  // cupsArrayGetLast()
  text = (char *)cupsArrayGetLast(array);
  if (text == NULL)
  {
    printf("Error Reading");
  }

  // cupsArrayGetPrev()
  text = (char *)cupsArrayGetPrev(array);
  if (text == NULL)
  {
    printf("Error Reading");
  }

  // cupsArrayFind()
  text = (char *)cupsArrayFind(array, second_string);
  if (text == NULL)
  {
    printf("Error Finding");
  }

  // cupsArrayGetCurrent()
  text = (char *)cupsArrayGetCurrent(array);
  if (text == NULL)
  {
    printf("Error Finding");
  }

  // cupsArrayDup()
  dup_array = cupsArrayDup(array);

  // cupsArrayRemove()
  if (!cupsArrayRemove(array, first_string))
  {
    printf("Error Finding");
  }

  // cupsArrayClear()
  cupsArrayClear(array);
  if (cupsArrayGetCount(array) != 0)
    {
        printf("Error Clearing");
  }

  // Test save/restore...
  for (i = 0, text = (char *)cupsArrayGetFirst(array); i < 32; i ++, text = (char *)cupsArrayGetNext(array))
  {
    saved[i] = text;

    if (!cupsArraySave(array))
      break;
  }

  while (i > 0)
  {
    i --;

    text = cupsArrayRestore(array);
    if (text != saved[i])
      break;
  }

  // Delete the arrays...
  cupsArrayDelete(array);
  cupsArrayDelete(dup_array);

  free(first_string);
  free(second_string);

  if (status != 0) {
    abort();
  }

  return 0;
}
