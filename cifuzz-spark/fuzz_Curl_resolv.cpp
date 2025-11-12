#include <assert.h>
#include <cifuzz/cifuzz.h>
#include <string>
#include <fuzzer/FuzzedDataProvider.h>
#include "curl_setup.h"
extern "C" {
  #include "urldata.h"
  #include "sendf.h"
  #include "connect.h"
  #include "socks.h"
  #include "multiif.h"
  #include "url.h"
}

// Setup function with no specific one-time initialization needed.
FUZZ_TEST_SETUP() {
}

// The main fuzz test function.
FUZZ_TEST(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // Initialize Curl_easy and a mock connectdata.
  struct Curl_easy easy;
  memset(&easy, 0, sizeof(easy));
  struct connectdata conn;
  memset(&conn, 0, sizeof(conn));
  easy.conn = &conn;

  // Consume fuzzer data for test case.
  std::string hostname = fdp.ConsumeRandomLengthString(255);
  int port = fdp.ConsumeIntegral<int>();
  bool waitp = fdp.ConsumeBool();
  struct Curl_dns_entry *dns_entry = nullptr;

  // Call the function we want to fuzz.
  enum resolve_t res = Curl_resolv(&easy, hostname.c_str(), port, waitp, &dns_entry);

  // Handle dns_entry according to curl library error handling.
  if (dns_entry) {
    Curl_resolv_unlink(&easy, &dns_entry);
  }

  // Add an assert or similar internal consistency check if needed:
  assert(res == CURLRESOLV_PENDING || res == CURLRESOLV_ERROR);
}
