/*
   Copyright The libcups Developers.
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at
       http://www.apache.org/licenses/LICENSE-2.0
   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "ipp.h"

#define MAX_IPP_SIZE (256 * 1024)

typedef struct _fuzz_buffer_s
{
  const ipp_uchar_t *input;
  size_t input_length;
  size_t input_offset;
  ipp_uchar_t *output;
  size_t output_length;
  size_t output_offset;
} fuzz_buffer_t;

static ssize_t
read_cb(fuzz_buffer_t *buffer, ipp_uchar_t *data, size_t length)
{
  size_t bytes;

  bytes = buffer->input_length - buffer->input_offset;
  if (bytes > length)
    bytes = length;

  if (bytes > 0)
  {
    memcpy(data, buffer->input + buffer->input_offset, bytes);
    buffer->input_offset += bytes;
  }

  return (ssize_t)bytes;
}

static ssize_t
write_cb(fuzz_buffer_t *buffer, ipp_uchar_t *data, size_t length)
{
  size_t bytes;

  bytes = buffer->output_length - buffer->output_offset;
  if (bytes > length)
    bytes = length;

  if (bytes < length)
    return (-1);

  if (bytes > 0)
  {
    memcpy(buffer->output + buffer->output_offset, data, bytes);
    buffer->output_offset += bytes;
  }

  return (ssize_t)bytes;
}

static ipp_state_t
read_ipp(fuzz_buffer_t *buffer, ipp_t *ipp)
{
  ipp_state_t state = IPP_STATE_ERROR;
  size_t iterations;

  for (iterations = 0; iterations <= buffer->input_length; iterations ++)
  {
    size_t old_offset = buffer->input_offset;

    state = ippReadIO(buffer, (ipp_io_cb_t)read_cb, true, NULL, ipp);
    if (state != IPP_STATE_ATTRIBUTE)
      break;

    if (buffer->input_offset == old_offset)
      break;
  }

  return (state);
}

static ipp_state_t
write_ipp(fuzz_buffer_t *buffer, ipp_t *ipp)
{
  ipp_state_t state = IPP_STATE_ERROR;
  size_t iterations;

  for (iterations = 0; iterations < buffer->output_length; iterations ++)
  {
    size_t old_offset = buffer->output_offset;

    state = ippWriteIO(buffer, (ipp_io_cb_t)write_cb, true, NULL, ipp);
    if (state != IPP_STATE_ATTRIBUTE)
      break;

    if (buffer->output_offset == old_offset)
      break;
  }

  return (state);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  fuzz_buffer_t input = { 0 }, output = { 0 }, roundtrip = { 0 };
  ipp_t *request = NULL, *parsed = NULL;
  ipp_attribute_t *attr;
  ipp_state_t state;

  if (size < 8 || size > MAX_IPP_SIZE)
    return (0);

  input.input = data;
  input.input_length = size;

  if ((request = ippNew()) == NULL)
    return (0);

  state = read_ipp(&input, request);
  if (state != IPP_STATE_DATA)
    goto done;

  for (attr = ippGetFirstAttribute(request); attr; attr = ippGetNextAttribute(request))
    (void)ippValidateAttribute(attr);
  (void)ippValidateAttributes(request);
  ippSetState(request, IPP_STATE_IDLE);

  output.output_length = MAX_IPP_SIZE;
  if ((output.output = malloc(output.output_length)) == NULL)
    goto done;

  state = write_ipp(&output, request);
  if (state != IPP_STATE_DATA || output.output_offset == 0)
    goto done;

  roundtrip.input = output.output;
  roundtrip.input_length = output.output_offset;
  roundtrip.input_offset = 0;
  if ((parsed = ippNew()) == NULL)
    goto done;

  state = read_ipp(&roundtrip, parsed);
  if (state == IPP_STATE_DATA)
  {
    for (attr = ippGetFirstAttribute(parsed); attr; attr = ippGetNextAttribute(parsed))
      (void)ippValidateAttribute(attr);
    (void)ippValidateAttributes(parsed);
  }

 done:
  ippDelete(parsed);
  ippDelete(request);
  free(output.output);
  return (0);
}
