#include <unistd.h>
#include <stdio.h>
#include <poll.h>

#include "urldata.h"
#include "sendf.h"
#include "if2ip.h"
#include "strerror.h"
#include "cfilters.h"
#include "connect.h"
#include "cf-haproxy.h"
#include "cf-https-connect.h"
#include "cf-socket.h"
#include "select.h"
#include "url.h" /* for Curl_safefree() */
#include "multiif.h"
#include "sockaddr.h" /* required for Curl_sockaddr_storage */
#include "inet_ntop.h"


static const char *mock_input = "foobar\n";
static size_t input_length = 0;

ssize_t __wrap_read(int fd, void *buf, size_t count) {
    fprintf(stderr, "__wrap_read\n");

    size_t bytes_to_read = strlen(mock_input) - input_length;
    if (bytes_to_read == 0) return 0; // EOF
    if (bytes_to_read > count) bytes_to_read = count;

    memcpy(buf, mock_input + input_length, bytes_to_read);
    input_length += bytes_to_read;

    return bytes_to_read;
}

int __real_poll(struct pollfd *fds, nfds_t nfds, int timeout);
int __wrap_poll(struct pollfd *fds, nfds_t nfds, int timeout) {
    return -1;//__real_poll(fds, nfds, 1);
}

CURLcode __wrap_Curl_conn_cf_connect(struct Curl_cfilter *cf,
                              struct Curl_easy *data,
                              bool blocking, bool *done)
{
    return 0;
}


CURLcode __wrap_curl_easy_perform(CURL *data)
{
    return 0;
}