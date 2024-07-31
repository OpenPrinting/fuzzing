//
// Legacy CUPS filter wrapper for cfFilterTextToPDF() for cups-filters.
//
// Copyright © 2020-2022 by OpenPrinting.
//
// Licensed under Apache License v2.0.  See the file "LICENSE" for more
// information.
//

//
// Include necessary headers...
//

#include <cupsfilters/filter.h>
#include <ppd/ppd-filter.h>
#include <signal.h>
#include <config.h>

//
// Local globals...
//

static int	JobCanceled = 0; // Set to 1 on SIGTERM

//
// Local functions...
//

static void		cancel_job(int sig);

static void redirect_stdout_stderr();
// fuzz entry point
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {

  if (Size < 4) {
    return 0;
  }

  redirect_stdout_stderr();
  
  FILE *fp;
  char temp_filename[] = "/tmp/fuzz-input";

  fp = fopen(temp_filename, "wb");
    if (!fp) {
        perror("Failed to open file");
        return 1;
    }
  
  ssize_t bytes_written = fwrite(Data, 1, Size, fp);
  if (bytes_written < Size) {
      perror("Failed to write to temp file");
      fclose(fp);
      remove(temp_filename);
      return 0;
  }
  fclose(fp);

  int argc = 7;
  char *argv[7];
  argv[0] = "texttopdf";
  argv[1] = "1";
  argv[2] = "hi_user";
  argv[3] = "there_title";
  argv[4] = "1";
  argv[5] = "random_string";
  argv[6] = temp_filename;
  // argv[7] = NULL; // seems useless

  int           ret;
#if defined(HAVE_SIGACTION) && !defined(HAVE_SIGSET)
  struct sigaction action;		// Actions for POSIX signals
#endif // HAVE_SIGACTION && !HAVE_SIGSET

  //
  // Register a signal handler to cleanly cancel a job.
  // 

#ifdef HAVE_SIGSET // Use System V signals over POSIX to avoid bugs
  sigset(SIGTERM, cancel_job);
#elif defined(HAVE_SIGACTION)
  memset(&action, 0, sizeof(action));

  sigemptyset(&action.sa_mask);
  action.sa_handler = cancel_job;
  sigaction(SIGTERM, &action, NULL);
#else
  signal(SIGTERM, cancel_job);
#endif // HAVE_SIGSET

  //
  // Fire up the cfFilterTextToPDF() filter function
  //

  cf_filter_texttopdf_parameter_t parameters;
  char *p;

  if ((p = getenv("CUPS_DATADIR")) != NULL)
    parameters.data_dir = p;
  else
    parameters.data_dir = CUPS_DATADIR;
  if ((p = getenv("CHARSET")) != NULL)
    parameters.char_set = p;
  else
    parameters.char_set = NULL;
  if ((p = getenv("CONTENT_TYPE")) != NULL)
    parameters.content_type = p;
  else
    parameters.content_type = NULL;
  if ((p = getenv("CLASSIFICATION")) != NULL)
    parameters.classification = p;
  else
    parameters.classification = NULL;

  ret = ppdFilterCUPSWrapper(argc, argv, cfFilterTextToPDF, &parameters,
			     &JobCanceled);

  if (ret)
    fprintf(stderr, "ERROR: texttopdf filter function failed.\n");
  
  // clean tmp file
  remove(temp_filename);
  return (ret);
}


//
// 'cancel_job()' - Flag the job as canceled.
//

static void
cancel_job(int sig)			// I - Signal number (unused)
{
  (void)sig;

  JobCanceled = 1;
}

void redirect_stdout_stderr() {
    int dev_null = open("/dev/null", O_WRONLY);
    if (dev_null < 0) {
        perror("Failed to open /dev/null");
        return;
    }
    dup2(dev_null, STDOUT_FILENO);
    dup2(dev_null, STDERR_FILENO);
    close(dev_null);
}