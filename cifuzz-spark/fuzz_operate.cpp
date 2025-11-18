#include <fuzzer/FuzzedDataProvider.h>
#include <cifuzz/cifuzz.h>
#include <assert.h>
#include "tool_setup.h"

#include <signal.h>
#include <fcntl.h>
#include <cstring>
#include <vector>

#include <gtest/gtest.h>

// External headers wrapped in extern "C".
extern "C" {
  #include "tool_cfgable.h"
  #include "tool_msgs.h"
  #include "tool_operate.h"
  #include "tool_main.h"
  #include "tool_stderr.h"
}

// Inline function copied directly from the source file
static int main_checkfds(void) {
#if defined(HAVE_PIPE) && defined(HAVE_FCNTL)
  int fd[2];
  while((fcntl(STDIN_FILENO, F_GETFD) == -1) ||
        (fcntl(STDOUT_FILENO, F_GETFD) == -1) ||
        (fcntl(STDERR_FILENO, F_GETFD) == -1)) {
    if(pipe(fd))
      return 1;
  }
#endif
  return 0;
}

void testFunction (const uint8_t *data, size_t size) {
  // Initialize FuzzedDataProvider to generate inputs for fuzzing
  FuzzedDataProvider fdp(data, size);

  // Generate a random `argc` between 1 and 100 (arbitrary choice within realistic bounds)
  int argc = fdp.ConsumeIntegralInRange<int>(1, 100);

  // Generate random strings for `argv` (null-terminated) with a maximum length of 256 per string
  std::vector<std::string> args;
  for (int i = 0; i < argc; ++i) {
    args.emplace_back(fdp.ConsumeRandomLengthString(256));
  }

  // Create an array of char* to simulate the `argv` format
  std::vector<char*> argv;
  for (std::string &arg : args) {
    argv.push_back(arg.data());
  }

  // Ensure file descriptors are open
  if (main_checkfds() != 0) {
    return; // Fail gracefully if descriptors are unavailable
  }

  // Initialize global configuration
  if (globalconf_init() != CURLE_OK) {
    return; // Unable to initialize; exit gracefully
  }

  // Run the main operation logic
  operate(argc, argv.data());

  // Perform cleanup
  globalconf_free();
} 


// FUZZ_TEST_SETUP for one-time initialization tasks
FUZZ_TEST_SETUP() {
  // Initialize standard error output before the fuzzing process begins
  tool_init_stderr();
}

// The main fuzz test entry point
FUZZ_TEST(const uint8_t *data, size_t size) {
  testFunction(data, size);
}

TEST(OperateTests, DoubleCallTest) {
  size_t size = 5;
  const uint8_t* data = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>("\\{;{\001"));

  tool_init_stderr();
  testFunction(data, size);
  testFunction(data, size);
}

