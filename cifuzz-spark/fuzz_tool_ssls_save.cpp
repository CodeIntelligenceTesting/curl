#include <assert.h>
#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>
#define CURL_TEMP_PRINTF CURL_PRINTF
#include "tool_operate.h"
#include "tool_ssls.h"

extern "C" {
  #include "tool_cfgable.h"
  #include "tool_cb_dbg.h"
}

FUZZ_TEST_SETUP() {
  // Perform setup tasks if necessary, although none are needed for this specific test
}

FUZZ_TEST(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // Initialize GlobalConfig and other required objects
  GlobalConfig global_config = {};
  std::string ssl_session_string = fdp.ConsumeRandomLengthString(64);
  global_config.ssl_sessions = const_cast<char*>(ssl_session_string.c_str());

  // Initialize OperationConfig structure
  OperationConfig operation_config = {};

  // Initialize CURLSH object
  CURLSH *share_handle = curl_share_init();
  if (!share_handle) return; // Return if initialization fails

  // Ensure that the `tool_ssls_save` function exists and matches the expected signature.
  // Since it's a part of the system, ensure proper linkage in the build system.
  CURLcode result = tool_ssls_save(&global_config, &operation_config, share_handle, global_config.ssl_sessions);

  // Clean up share handle to avoid memory leaks
  curl_share_cleanup(share_handle);

  // Assert the tool_ssls_save result to check for normal conditions
  assert(result == CURLE_OK || result == CURLE_OUT_OF_MEMORY);
}
