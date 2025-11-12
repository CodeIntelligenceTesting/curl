#include <assert.h>
#include <cifuzz/cifuzz.h>
#include <curl/curl.h>
#include <fuzzer/FuzzedDataProvider.h>

// Include necessary curl internal headers
extern "C" {
#include "urldata.h"
#include "connect.h"
}

FUZZ_TEST(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);
  
  CURLM *multi = curl_multi_init(); // Correct initialization using CURLM type
  CURL *easy = curl_easy_init();  // Correct initialization using CURL type
  if (!multi || !easy) return; // Ensure objects are initialized

  struct Curl_multi *multi_handle = (struct Curl_multi *)multi;
  struct Curl_easy *easy_handle = (struct Curl_easy *)easy;

  // Acquire booleans using FuzzedDataProvider
  bool connected = fdp.ConsumeBool();
  bool async = fdp.ConsumeBool();

  CURLcode result = Curl_connect(easy_handle, &async, &connected); // Correct Function Call

  assert(result == CURLE_OK || result == CURLE_NO_CONNECTION_AVAILABLE); // Expected result check

  curl_easy_cleanup(easy);
  curl_multi_cleanup(multi);
}
