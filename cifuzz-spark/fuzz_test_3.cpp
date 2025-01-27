#include <assert.h>
#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>
extern "C" {
#include "curl_md5.h"
}

FUZZ_TEST_SETUP() {
  // No one-time setup needed for this function.
}

FUZZ_TEST(const uint8_t *data, size_t size) {
  if (size < 1) return; // Ensure there is data to process.

  FuzzedDataProvider fdp(data, size);

  // Allocate buffer for the output MD5 hash (16 bytes).
  unsigned char md5_output[16];

  // Randomly decide the input size.
  const size_t input_size = fdp.ConsumeIntegralInRange<size_t>(1, size);
  std::vector<unsigned char> input_data = fdp.ConsumeBytes<unsigned char>(input_size);

  if (input_data.empty()) return; // Ensure input data is not empty.

  // Call the target function.
  Curl_md5it(md5_output, input_data.data(), input_data.size());
}
