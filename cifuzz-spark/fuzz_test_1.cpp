#include <assert.h>
#include <cifuzz/cifuzz.h>
#include <curl/curl.h>
#include <fuzzer/FuzzedDataProvider.h>

// Setup function for one-time initialization
FUZZ_TEST_SETUP() {
  curl_global_init(CURL_GLOBAL_DEFAULT);
}

// Fuzz test entry point
FUZZ_TEST(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  CURL *curl = curl_easy_init();
  if (!curl) return;

  std::string url = fdp.ConsumeRandomLengthString(256);
  std::string proxy = fdp.ConsumeRandomLengthString(128);
  std::string userpwd = fdp.ConsumeRandomLengthString(128);
  long timeout = fdp.ConsumeIntegralInRange<long>(0, 30000);
  long follow_location = fdp.ConsumeBool() ? 1L : 0L;
  long ssl_verify_peer = fdp.ConsumeBool() ? 1L : 0L;

  curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(curl, CURLOPT_PROXY, proxy.c_str());
  curl_easy_setopt(curl, CURLOPT_USERPWD, userpwd.c_str());
  curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, timeout);
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, follow_location);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, ssl_verify_peer);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, NULL);

  curl_easy_perform(curl);
  curl_easy_cleanup(curl);
}

