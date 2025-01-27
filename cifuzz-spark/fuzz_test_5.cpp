#include <assert.h>
#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>
#include "curl/curl.h"
#include "hsts.h"

FUZZ_TEST_SETUP() {
  // No specific setup required for this harness.
}

FUZZ_TEST(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // Create a dummy hsts structure
  struct hsts hsts_instance;
  memset(&hsts_instance, 0, sizeof(hsts_instance));

  // Generate strings for the second and third parameters
  std::string str1 = fdp.ConsumeRandomLengthString(128);
  std::string str2 = fdp.ConsumeRandomLengthString(128);

  // Logically handle the function call
  #if defined(CURL_HSTS_SUPPORT)
  CURLcode result = Curl_hsts_parse(&hsts_instance, str1.c_str(), str2.c_str());
  assert(result == CURLE_OK || result == CURLE_BAD_FUNCTION_ARGUMENT);
  #endif
}
