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
#include "cups.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  if (size == 0 || size > 65536)
    return 0;

  // NUL-terminate the input so it can be used as a C string.
  char *str = (char *)malloc(size + 1);
  if (!str)
    return 0;
  memcpy(str, data, size);
  str[size] = '\0';

  // 1. URI parser: scheme://user@host:port/resource splitter.
  char scheme[256], username[256], host[256], resource[1024];
  int port = 0;
  http_uri_status_t st = httpSeparateURI(HTTP_URI_CODING_ALL, str,
                                         scheme, sizeof(scheme),
                                         username, sizeof(username),
                                         host, sizeof(host),
                                         &port,
                                         resource, sizeof(resource));

  // Round-trip the separated components back into a URI.
  if (st == HTTP_URI_STATUS_OK)
  {
    char rebuilt[2048];
    httpAssembleURI(HTTP_URI_CODING_ALL, rebuilt, sizeof(rebuilt),
                    scheme, username, host, port, resource);
  }

  // 2. base64 decoder (output is at most ~3/4 of the input).
  {
    size_t outlen = size;
    char *out = (char *)malloc(outlen + 1);
    if (out)
    {
      const char *end = NULL;
      httpDecode64(out, &outlen, str, &end);
      free(out);
    }
  }

  // 3. HTTP date-string parser.
  httpGetDateTime(str);

  free(str);
  return 0;
}
