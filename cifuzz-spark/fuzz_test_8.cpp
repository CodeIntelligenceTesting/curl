#include "tool_setup.h"
#include "curlx.h"
#include "tool_getparam.h"
#include "tool_operate.h"
#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>

extern "C" {
  #include "tool_cfgable.h"
  #include "tool_cb_prg.h"
  #include "tool_filetime.h"
  #include "tool_formparse.h"
  #include "tool_getparam.h"
  #include "tool_helpers.h"
  #include "tool_libinfo.h"
  #include "tool_msgs.h"
  #include "tool_paramhlp.h"
  #include "tool_parsecfg.h"
  #include "dynbuf.h"
  #include "tool_stderr.h"
  #include "var.h"
}

FUZZ_TEST_SETUP() {
  // One-time initialization tasks, e.g., memory allocation, file opening.
}

FUZZ_TEST(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // Initialize necessary structures
  struct GlobalConfig global;
  struct OperationConfig config;
  config.global = &global;
  config.url_list = nullptr;

  // Fuzz the URL
  char *url = strdup(fdp.ConsumeRandomLengthString(100).c_str());
  if (!url) return;

  // Create a URL node
  struct getout *urlnode = (struct getout *)malloc(sizeof(struct getout));
  if (!urlnode) {
    free(url);
    return;
  }
  urlnode->url = url;
  urlnode->next = nullptr;
  config.url_list = urlnode;

  // Use curl_easy_init and set options
  CURL *curl = curl_easy_init();
  if (curl) {
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_cleanup(curl);
  }

  // Cleanup
  free(urlnode->url);
  free(urlnode);
}
