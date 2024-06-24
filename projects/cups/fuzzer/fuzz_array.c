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
//   char		word[256];		// Word from file
//   double	start,			// Start time
		// end;			// End time
//   cups_dir_t	*dir;			// Current directory
//   cups_dentry_t	*dent;			// Directory entry
  char		*saved[32];		// Saved entries
  // void		*data;			// User data for arrays


  // No errors so far...
  status = 0;

  if (Size < 2) {
    return 0; 
  }

  size_t halfSize = Size / 2;
  void *firstStr = malloc(halfSize + 1);
    if (!firstStr) {
        return 0;
    }
  memcpy(firstStr, Data, halfSize);
  void *secondStr = malloc(Size - halfSize + 1);
  if (!secondStr) {
    free(firstStr);
    return 0;
  }
  memcpy(secondStr, Data + halfSize, Size - halfSize);

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
  if (cupsArrayGetCount(array) != halfSize)
  {
    printf("String Size Error");
    abort();
  }

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

//   start = get_seconds();

//   if ((dir = cupsDirOpen(".")) == NULL)
//   {
//     testEndMessage(false, "cupsDirOpen failed");
//     status ++;
//   }
//   else
//   {
//     bool load_status = true;		// Load status

//     while ((dent = cupsDirRead(dir)) != NULL)
//     {
//       i = (int)strlen(dent->filename) - 2;

//       if (i > 0 && dent->filename[i] == '.' && (dent->filename[i + 1] == 'c' || dent->filename[i + 1] == 'h'))
//       {
// 	if (!load_words(dent->filename, array))
// 	{
// 	  load_status = false;
// 	  break;
// 	}
//       }
//     }

//     cupsDirClose(dir);

//     if (load_status)
//     {
//       end = get_seconds();

//       for (text = (char *)cupsArrayGetFirst(array); text;)
//       {
//         // Copy this word to the word buffer (safe because we strdup'd from
// 	// the same buffer in the first place... :)
// 	cupsCopyString(word, text, sizeof(word));

//         // Grab the next word and compare...
// 	if ((text = (char *)cupsArrayGetNext(array)) == NULL)
// 	  break;

// 	if (strcmp(word, text) >= 0)
// 	  break;
//       }

//       if (text)
//       {
// 	testEndMessage(false, "\"%s\" >= \"%s\"", word, text);
// 	status ++;
//       }
//       else
//       {
// 	testEndMessage(true, "%d words in %.3f seconds - %.0f words/sec", cupsArrayGetCount(array), end - start, cupsArrayGetCount(array) / (end - start));
//       }
//     }
//   }

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


//
// 'get_seconds()' - Get the current time in seconds...
//

// #ifdef _WIN32
// #  include <windows.h>


// static double
// get_seconds(void)
// {
// }
// #else
// #  include <sys/time.h>


// static double
// get_seconds(void)
// {
//   struct timeval	curtime;	// Current time


//   gettimeofday(&curtime, NULL);
//   return (curtime.tv_sec + 0.000001 * curtime.tv_usec);
// }
// #endif // _WIN32


//
// 'load_words()' - Load words from a file.
//

// static int				// O - 1 on success, 0 on failure
// load_words(const char   *filename,	// I - File to load
//            cups_array_t *array)		// I - Array to add to
// {
//   FILE		*fp;			// Test file
//   char		word[256];		// Word from file


//   testProgress();

//   if ((fp = fopen(filename, "r")) == NULL)
//   {
//     testEndMessage(false, "%s: %s", filename, strerror(errno));
//     return (0);
//   }

//   while (fscanf(fp, "%255s", word) == 1)
//   {
//     if (!cupsArrayFind(array, word))
//       cupsArrayAdd(array, word);
//   }

//   fclose(fp);

//   return (1);
// }
