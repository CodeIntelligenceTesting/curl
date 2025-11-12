#include <assert.h>
#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>

// Include necessary curl headers
#include "tool_setup.h"
#include "tool_getparam.h"

extern "C" {
  #include "tool_cfgable.h"
  #include "tool_parsecfg.h"
}

// Fuzz Test Setup: As `FUZZ_TEST_SETUP` does not collect resources or memory allocations, we focus on the test execution itself.
FUZZ_TEST_SETUP() {
  // (Optional) You can configure global initializations if required.
  // This setup has not been specified in the setup macro of the fuzz task, and thus is excluded.
}

// Fuzz Test: Using arbitrary data as configuration input to fuzz `parseconfig`
FUZZ_TEST(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);
  
  // Create instances of GlobalConfig and OperationConfig
  struct GlobalConfig global;
  struct OperationConfig config;

  // Initialize the OperationConfig structure
  config_init(&config);
  config.global = &global;

  // Generate configuration input string from fuzzer data provider
  std::string configInput = fdp.ConsumeRemainingBytesAsString();

  // Execute the target function
  parseconfig(configInput.c_str(), &global);
}
