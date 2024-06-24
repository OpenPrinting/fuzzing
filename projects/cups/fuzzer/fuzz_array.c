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

// fuzz entry point
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  int		i;			// Looping var
  cups_array_t	*array,			// Test array
		*dup_array;		// Duplicate array
  int		status;			// Exit status
  char		*text;			// Text from array
  char		*saved[32];		// Saved entries

  // No errors so far...
  status = 0;

  if (Size < 4) {
    return 0; 
  }

  size_t halfSize = Size / 2;
  char *firstStr = (char *)malloc(halfSize + 1);
    if (!firstStr) {
        return 0;
    }
  memcpy(firstStr, Data, halfSize);
  firstStr[halfSize] = '\0';

  char *secondStr = (char *)malloc(Size - halfSize + 1);
  if (!secondStr) {
    free(firstStr);
    return 0;
  }
  memcpy(secondStr, Data + halfSize, Size - halfSize);
  secondStr[halfSize] = '\0';

  // cupsArrayNew()
  array = cupsArrayNew3((cups_array_func_t)_cupsArrayStrcmp, (void *)firstStr, NULL, 0, (cups_acopy_cb_t)_cupsArrayStrdup, (cups_afree_cb_t)_cupsArrayFree);

  if (!array)
  {
    printf("returned NULL, expected pointer");
    abort();
  }

  // cupsArrayGetUserData()
  if (cupsArrayGetUserData(array) != firstStr)
  {
    printf("returned %p instead of %p", cupsArrayGetUserData(array), firstStr);
    abort();
  }

  // cupsArrayAdd()
  if (!cupsArrayAdd(array, secondStr))
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
  text = (char *)cupsArrayFind(array, secondStr);
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
  if (!cupsArrayRemove(array, firstStr))
  {
    printf("Error Finding");
  }

  // cupsArrayClear()
  cupsArrayClear(array);
  if (cupsArrayGetCount(array) != 0)
    {
        printf("Error Clearing");
  }

  // Now load this source file and grab all of the unique words...
  // TODO: do the file readings fuzzing

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

  free(firstStr);
  free(secondStr);

  return (status);
}