#include <assert.h>
#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <curl/curl.h>
#include "urldata.h"
extern "C" {
  #include "url.h"
}

FUZZ_TEST_SETUP() {
  curl_global_init(CURL_GLOBAL_ALL);
}

FUZZ_TEST(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  std::string input = fdp.ConsumeRandomLengthString(100);
  char *userstr = NULL;
  char *passwdstr = NULL;
  char *options = NULL;

  CURLcode rc = Curl_parse_login_details(input.c_str(), input.length(), &userstr, &passwdstr, &options);

  if(rc == CURLE_OK) {
    // Simulate some operations on parsed data
    if(userstr) {
      free(userstr);
    }
    if(passwdstr) {
      free(passwdstr);
    }
    if(options) {
      free(options);
    }
  }
  
  curl_global_cleanup(); // Cleanup after fuzzing
}
