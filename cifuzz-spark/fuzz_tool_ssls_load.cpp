#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>
#include "tool_operate.h" // Ensures that struct definitions are available
#include "dynbuf.h"
#include "tool_ssls.h"
#include <cassert>
#include <string>

// Setup the global curl environment in FUZZ_TEST_SETUP()
FUZZ_TEST_SETUP() {
  curl_global_init(CURL_GLOBAL_WIN32);
}

// Main fuzz test entry point
FUZZ_TEST(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // Construct necessary structures with fuzz data processed by FuzzedDataProvider
  struct GlobalConfig globalConfig = {};
  struct OperationConfig operationConfig = {};
  
  // Obtain a std::string for the ssl_sessions to ensure the data persists
  std::string ssl_sessions_str = fdp.ConsumeRemainingBytesAsString();
  const char *ssl_sessions = ssl_sessions_str.c_str();

  CURLSH *share = curl_share_init();
  assert(share != nullptr);

  // Perform the fuzz test on tool_ssls_load
  tool_ssls_load(&globalConfig, &operationConfig, share, ssl_sessions);

  // Cleanup resources allocated in FUZZ_TEST_SETUP()
  curl_share_cleanup(share);
}
