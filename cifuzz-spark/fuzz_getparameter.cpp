#include <assert.h>
#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>
extern "C" {
  #include "tool_cfgable.h"
  #include "tool_getparam.h"
  #include "tool_helpers.h"
  #include "tool_findfile.h"
  #include "tool_msgs.h"
  #include "tool_parsecfg.h"
  #include "tool_util.h"
  #include "dynbuf.h"
}

// Ensure the global configuration is properly initialized
FUZZ_TEST_SETUP() {
  // No specific setup needed for this harness
}

// The entry point for the fuzz test
FUZZ_TEST(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // Create dummy GlobalConfig and OperationConfig objects
  struct GlobalConfig global{};
  struct OperationConfig operation{};
  global.last = &operation;

  // Generate filename and option using the fuzzer data
  std::string filename = fdp.ConsumeRandomLengthString();
  std::string option = fdp.ConsumeRandomLengthString();

  // Prepare filename and option strings, ensuring they're not null-representing
  const char *filename_cstr = (filename.empty() ? "<empty-filename>" : filename.c_str()); // Use a placeholder if empty
  const char *option_cstr = (option.empty() ? "<empty-option>" : option.c_str()); // Use a placeholder if empty

  // Get remaining bytes as parameter data
  std::string param = fdp.ConsumeRemainingBytesAsString();
  char *param_cstr = (param.empty() ? nullptr : const_cast<char*>(param.c_str())); // Allow null for param

  // Call parseconfig function (if required, otherwise can be removed)
  int parseResult = parseconfig(filename_cstr, &global);
  
  // Test the getparameter function
  bool usedarg = false;
  ParameterError res = getparameter(option_cstr, param_cstr, nullptr, &usedarg, &global, &operation);

  // Ensure that the fuzzer input is not causing undefined behavior
  assert(parseResult == 0 || res == PARAM_OK || res != PARAM_NO_MEM);
}
