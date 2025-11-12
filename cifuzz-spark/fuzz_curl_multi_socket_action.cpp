#include <assert.h>
#include <cifuzz/cifuzz.h>
#include <curl/curl.h>
#include <fuzzer/FuzzedDataProvider.h>

extern "C" {
  #include "warnless.h"
}

FUZZ_TEST_SETUP() {
  curl_global_init(CURL_GLOBAL_ALL);
}

FUZZ_TEST(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  CURLM *multi_handle = curl_multi_init();
  assert(multi_handle);

  CURL *easyHandle = curl_easy_init();
  assert(easyHandle);

  curl_easy_setopt(easyHandle, CURLOPT_VERBOSE, 1L);
  curl_multi_add_handle(multi_handle, easyHandle);

  curl_socket_t socket = fdp.ConsumeIntegral<curl_socket_t>();
  int numhandles = 0;

  // Choose which test to execute
  switch(fdp.ConsumeIntegralInRange<int>(0, 1)) {
    case 0: { // Test from the first code block
      int evBitmask = fdp.ConsumeIntegral<int>();
      CURLMcode result = curl_multi_socket_action(multi_handle, socket, evBitmask, &numhandles);
      assert(result == CURLM_OK);
      break;
    }
    case 1: { // Test from the second code block
      int evBitmask = 0;
      if (fdp.ConsumeBool()) evBitmask |= CURL_CSELECT_IN;
      if (fdp.ConsumeBool()) evBitmask |= CURL_CSELECT_OUT;
      CURLMcode result = curl_multi_socket_action(multi_handle, socket, evBitmask, &numhandles);
      assert(result == CURLM_OK || result == CURLM_BAD_SOCKET || result == CURLM_RECURSIVE_API_CALL);
      break;
    }
  }

  curl_multi_remove_handle(multi_handle, easyHandle);
  curl_easy_cleanup(easyHandle);
  curl_multi_cleanup(multi_handle);
}
