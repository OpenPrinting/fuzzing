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

// Fuzzes the HTTP/1.x connection state machine in http.c over a local socket.
//
// Input layout: byte 0 selects the mode, the rest is the raw peer byte stream.
//   bit 0 clear: server mode - input is one or more client requests.
//   bit 0 set:   client mode - input is the server response to a GET request
//                (POST with a small chunked body if bit 1 is also set).

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <zlib.h>
#include "cups.h"
#include "http-private.h"

#define MAX_INPUT	65536
#define MAX_REQUESTS	8
#define MAX_UPDATES	64
#define MAX_BODY	(1024 * 1024)

static int		listen_fd = -1;
static char		sock_path[sizeof(((struct sockaddr_un *)0)->sun_path)];
static const char	resource[] = "/ipp/print";


static const char *
password_cb(const char *prompt, http_t *http, const char *method, const char *res, void *cb_data)
{
  (void)prompt; (void)http; (void)method; (void)res; (void)cb_data;

  return ("fuzz-password");
}


static const char *
oauth_cb(http_t *http, const char *realm, const char *scope, const char *res, void *cb_data)
{
  (void)http; (void)realm; (void)res; (void)cb_data;

  // Decline when no scope so Basic/Digest after a Bearer challenge stay reachable.
  return (scope ? "fuzz-token" : NULL);
}


static void
remove_socket(void)
{
  if (sock_path[0])
    unlink(sock_path);
}


static void
make_addr(struct sockaddr_un *addr)
{
  memset(addr, 0, sizeof(*addr));
  addr->sun_family = AF_LOCAL;
  memcpy(addr->sun_path, sock_path, sizeof(addr->sun_path));
}


static bool
init_once(void)
{
  struct sockaddr_un addr;

  if (listen_fd >= 0)
    return (true);

  // Library writes to a peer that may already be gone.
  signal(SIGPIPE, SIG_IGN);

  cupsSetPasswordCB(password_cb, NULL);
  cupsSetOAuthCB(oauth_cb, NULL);

  snprintf(sock_path, sizeof(sock_path), "/tmp/fuzzhttpconn-%d.sock", (int)getpid());
  unlink(sock_path);

  if ((listen_fd = socket(AF_LOCAL, SOCK_STREAM, 0)) < 0)
    return (false);

  make_addr(&addr);

  if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) || listen(listen_fd, 16))
  {
    close(listen_fd);
    listen_fd = -1;
    return (false);
  }

  atexit(remove_socket);

  return (true);
}


// Queue the whole input on the peer socket, then half-close so reads hit EOF instead of blocking.
static bool
feed(int fd, const uint8_t *data, size_t size)
{
  while (size > 0)
  {
    ssize_t bytes = send(fd, data, size, MSG_NOSIGNAL);

    if (bytes < 0)
    {
      if (errno == EINTR)
        continue;

      return (false);
    }

    data += bytes;
    size -= (size_t)bytes;
  }

  return (shutdown(fd, SHUT_WR) == 0);
}


static void
check_fields(http_t *http)
{
  char value[256];

  httpGetSubField(http, HTTP_FIELD_AUTHORIZATION, "username", value, sizeof(value));
  httpGetSubField(http, HTTP_FIELD_CONTENT_TYPE, "charset", value, sizeof(value));
  httpGetSubField(http, HTTP_FIELD_KEEP_ALIVE, "timeout", value, sizeof(value));
  httpGetSubField(http, HTTP_FIELD_WWW_AUTHENTICATE, "realm", value, sizeof(value));
  httpGetCookieValue(http, "_TOKEN", value, sizeof(value));
  httpGetCookieValue(http, "_DEVGRANT", value, sizeof(value));
}


static void
drain_body(http_t *http)
{
  char		buffer[8192];
  ssize_t	bytes;
  size_t	total = 0;
  int		i;

  (void)httpPeek(http, buffer, sizeof(buffer));

  for (i = 0; i < 1024 && total < MAX_BODY; i ++)
  {
    if ((bytes = httpRead(http, buffer, sizeof(buffer))) <= 0)
      break;

    total += (size_t)bytes;
  }
}


// httpClose() does not free an unfinished (de)compression stream, so release it first.
static void
close_http(http_t *http)
{
  if (http && http->stream)
  {
    if (http->coding == _HTTP_CODING_GZIP || http->coding == _HTTP_CODING_DEFLATE)
      deflateEnd((z_stream *)http->stream);
    else
      inflateEnd((z_stream *)http->stream);

    free(http->stream);
    free(http->sbuffer);

    http->stream  = NULL;
    http->sbuffer = NULL;
    http->coding  = _HTTP_CODING_IDENTITY;
  }

  httpClose(http);
}


static bool
is_recv_state(http_state_t state)
{
  return (state == HTTP_STATE_POST_RECV || state == HTTP_STATE_PUT_RECV || state == HTTP_STATE_LOCK_RECV || state == HTTP_STATE_PROPFIND_RECV || state == HTTP_STATE_PROPPATCH_RECV);
}


// Mirrors respond_http() in tools/ippeveprinter.c.
static bool
server_respond(http_t *http, http_status_t code, const char *coding)
{
  static const char body[] = "fuzz response\n";

  httpClearFields(http);
  httpSetField(http, HTTP_FIELD_CONTENT_TYPE, "text/plain");
  if (coding)
    httpSetField(http, HTTP_FIELD_CONTENT_ENCODING, coding);
  httpSetLength(http, 0);

  if (!httpWriteResponse(http, code))
    return (false);

  if (httpGetState(http) == HTTP_STATE_WAITING)
    return (true);

  if (httpWrite(http, body, sizeof(body) - 1) < 0)
    return (false);

  return (httpWrite(http, "", 0) >= 0);
}


static void
fuzz_server(const uint8_t *data, size_t size)
{
  struct sockaddr_un	addr;
  http_t		*http = NULL;
  int			cfd, i;

  if ((cfd = socket(AF_LOCAL, SOCK_STREAM, 0)) < 0)
    return;

  make_addr(&addr);

  if (connect(cfd, (struct sockaddr *)&addr, sizeof(addr)))
    goto done;

  if ((http = httpAcceptConnection(listen_fd, true)) == NULL)
    goto done;

  if (!feed(cfd, data, size))
    goto done;

  for (i = 0; i < MAX_REQUESTS; i ++)
  {
    char		uri[1024];
    http_state_t	state;
    http_status_t	status;
    const char		*coding;
    int			tries = 0;

    httpClearFields(http);
    httpClearCookie(http);

    while ((state = httpReadRequest(http, uri, sizeof(uri))) == HTTP_STATE_WAITING && ++ tries < 16);

    if (state == HTTP_STATE_WAITING || state == HTTP_STATE_ERROR)
      break;

    if (state == HTTP_STATE_UNKNOWN_METHOD || state == HTTP_STATE_UNKNOWN_VERSION)
    {
      server_respond(http, HTTP_STATUS_BAD_REQUEST, NULL);
      break;
    }

    tries = 0;
    do
    {
      status = httpUpdate(http);
    }
    while (status == HTTP_STATUS_CONTINUE && ++ tries < MAX_UPDATES);

    if (status != HTTP_STATUS_OK)
    {
      server_respond(http, HTTP_STATUS_BAD_REQUEST, NULL);
      break;
    }

    check_fields(http);

    if (is_recv_state(httpGetState(http)))
    {
      if (httpGetExpect(http) == HTTP_STATUS_CONTINUE && !httpWriteResponse(http, HTTP_STATUS_CONTINUE))
        break;

      drain_body(http);
    }

    coding = httpGetContentEncoding(http);

    if (!server_respond(http, HTTP_STATUS_OK, coding) || httpGetState(http) != HTTP_STATE_WAITING)
      break;
  }

  done:

  close_http(http);
  close(cfd);
}


static void
fuzz_client(const uint8_t *data, size_t size, bool post)
{
  http_t	*http;
  http_status_t	status;
  const char	*method = post ? "POST" : "GET";
  int		sfd = -1, tries = 0;

  if ((http = httpConnect(sock_path, 0, NULL, AF_LOCAL, HTTP_ENCRYPTION_IF_REQUESTED, true, 1000, NULL)) == NULL)
    return;

  if ((sfd = accept(listen_fd, NULL, NULL)) < 0)
    goto done;

  if (!feed(sfd, data, size))
    goto done;

  if (post)
  {
    httpSetField(http, HTTP_FIELD_CONTENT_TYPE, "application/ipp");
    httpSetLength(http, 0);
  }

  if (!httpWriteRequest(http, method, resource))
    goto done;

  if (post && (httpWrite(http, "fuzz", 4) < 0 || httpWrite(http, "", 0) < 0))
    goto done;

  do
  {
    status = httpUpdate(http);
  }
  while (status == HTTP_STATUS_CONTINUE && ++ tries < MAX_UPDATES);

  check_fields(http);

  // Never resend: http_send() would reconnect to a listener nobody accepts on and block.
  if (status == HTTP_STATUS_UNAUTHORIZED)
    cupsDoAuthentication(http, method, resource);

  drain_body(http);

  done:

  close_http(http);
  if (sfd >= 0)
    close(sfd);

  // WWW-Authenticate "username" parameters change the per-thread user name.
  cupsSetUser(NULL);
}


int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  if (size < 1 || size > MAX_INPUT + 1 || !init_once())
    return (0);

  if (data[0] & 1)
    fuzz_client(data + 1, size - 1, (data[0] & 2) != 0);
  else
    fuzz_server(data + 1, size - 1);

  return (0);
}
