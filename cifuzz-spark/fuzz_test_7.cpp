#include <assert.h>
#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>
extern "C" {
#include "curl.h"
#include "bufref.h"
}

FUZZ_TEST_SETUP() {
  // No specific one-time setup required for this function.
}

FUZZ_TEST(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  struct bufref buf;
  std::vector<uint8_t> input_vector = fdp.ConsumeRemainingBytes<uint8_t>();
  const void *input_data = input_vector.data();
  size_t input_size = input_vector.size();
  void (*cleanup_func)(void *) = fdp.ConsumeBool() ? [](void *) {} : nullptr;

  Curl_bufref_set(&buf, input_data, input_size, cleanup_func);

  // No assertions or checks, as we are just fuzzing for crashes.
}
