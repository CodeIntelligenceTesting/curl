#include <assert.h>
#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>
#include "urldata.h"
extern "C" {
  #include "progress.h"
}

// Define the fake_t_startsingle_time function
static void fake_t_startsingle_time(struct Curl_easy *data,
                                    struct curltime fake_now,
                                    int seconds_offset) {
  Curl_pgrsTime(data, TIMER_STARTSINGLE);
  data->progress.t_startsingle.tv_sec = fake_now.tv_sec + seconds_offset;
  data->progress.t_startsingle.tv_usec = fake_now.tv_usec;
}

FUZZ_TEST_SETUP() {
  // No one-time initialization required for this test.
}

FUZZ_TEST(const uint8_t *data, size_t size) {
  if (size < sizeof(int) * 10) return;

  FuzzedDataProvider fdp(data, size);

  struct Curl_easy curl_data = {0};  // Ensure curl_data is zero-initialized
  struct curltime now;
  now.tv_sec = fdp.ConsumeIntegral<int>();
  now.tv_usec = fdp.ConsumeIntegral<int>();

  curl_data.progress.t_nslookup = fdp.ConsumeIntegral<int>();
  curl_data.progress.t_connect = fdp.ConsumeIntegral<int>();
  curl_data.progress.t_appconnect = fdp.ConsumeIntegral<int>();
  curl_data.progress.t_pretransfer = fdp.ConsumeIntegral<int>();
  curl_data.progress.t_starttransfer = fdp.ConsumeIntegral<int>();
  curl_data.progress.t_redirect = fdp.ConsumeIntegral<int>();
  curl_data.progress.start.tv_sec = now.tv_sec - fdp.ConsumeIntegralInRange<int>(0, 10);
  curl_data.progress.start.tv_usec = now.tv_usec;

  fake_t_startsingle_time(&curl_data, now, fdp.ConsumeIntegral<int>());

  Curl_pgrsTime(&curl_data, TIMER_NAMELOOKUP);
  Curl_pgrsTime(&curl_data, TIMER_CONNECT);
  Curl_pgrsTime(&curl_data, TIMER_APPCONNECT);
  Curl_pgrsTime(&curl_data, TIMER_PRETRANSFER);
  Curl_pgrsTime(&curl_data, TIMER_STARTTRANSFER);

  // Simulate a redirect
  curl_data.progress.t_redirect = curl_data.progress.t_starttransfer + fdp.ConsumeIntegral<int>();
  fake_t_startsingle_time(&curl_data, now, fdp.ConsumeIntegral<int>());
  Curl_pgrsTime(&curl_data, TIMER_NAMELOOKUP);
  Curl_pgrsTime(&curl_data, TIMER_CONNECT);
  Curl_pgrsTime(&curl_data, TIMER_APPCONNECT);
  Curl_pgrsTime(&curl_data, TIMER_PRETRANSFER);
  Curl_pgrsTime(&curl_data, TIMER_STARTTRANSFER);
}
