#include <assert.h>
#include <cifuzz/cifuzz.h>
#include <curl/curl.h>
#include <fuzzer/FuzzedDataProvider.h>

// Callback function for writing data
static size_t write_callback(void *ptr, size_t size, size_t nmemb, void *stream) {
  (void)ptr;
  (void)stream;
  return size * nmemb;
}

// Callback function for download progress
static int dload_progress_cb(void *a, curl_off_t b, curl_off_t c, curl_off_t d, curl_off_t e) {
  (void)a;
  (void)b;
  (void)c;
  (void)d;
  (void)e;
  return 0;
}

// Callback function for receiving data
static size_t write_cb(char *d, size_t n, size_t l, void *p) {
  (void)d;
  (void)p;
  return n * l;
}

FUZZ_TEST_SETUP() {
  CURLcode res = curl_global_init(CURL_GLOBAL_DEFAULT);
  assert(res == CURLE_OK);
}

FUZZ_TEST(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // Choose between different fuzz test paths using a switch statement
  uint8_t choice = fdp.ConsumeIntegral<uint8_t>() % 3;
  switch(choice) {
    case 0:
      {
        CURL *curl = curl_easy_init();
        if(curl) {
          std::string url = fdp.ConsumeRandomLengthString(100);    
          curl_easy_setopt(curl, CURLOPT_URL, url.c_str());      

          std::string range = fdp.ConsumeRandomLengthString(10);
          curl_easy_setopt(curl, CURLOPT_RANGE, range.c_str());

          CURLcode res = curl_easy_perform(curl);
          curl_easy_cleanup(curl);
        }
      }
      break;

    case 1:
      {
        CURL *curl = curl_easy_init();
        if(curl) {
          std::string url = fdp.ConsumeRandomLengthString(100);
          curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
          curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);

          int version_choice = fdp.ConsumeIntegralInRange<int>(0, 2);
          curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, (version_choice == 0) ? CURL_HTTP_VERSION_1_1 :
                           (version_choice == 1) ? CURL_HTTP_VERSION_2_0 : CURL_HTTP_VERSION_3);

          curl_easy_perform(curl);

          curl_easy_cleanup(curl);
        }
      }
      break;

    case 2:
      {
        CURL *hnd = curl_easy_init();
        if(hnd) {
          curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, write_cb);
          curl_easy_setopt(hnd, CURLOPT_ERRORBUFFER, NULL);
          curl_easy_setopt(hnd, CURLOPT_NOPROGRESS, 0L);
          curl_easy_setopt(hnd, CURLOPT_XFERINFOFUNCTION, dload_progress_cb);

          long limit = fdp.ConsumeIntegralInRange<long>(1, 12000);
          long time = fdp.ConsumeIntegralInRange<long>(1, 2);

          std::vector<uint8_t> url_data = fdp.ConsumeRemainingBytes<uint8_t>();
          std::string url(reinterpret_cast<const char*>(url_data.data()), url_data.size());
          curl_easy_setopt(hnd, CURLOPT_URL, url.c_str());

          curl_easy_setopt(hnd, CURLOPT_LOW_SPEED_LIMIT, limit);
          curl_easy_setopt(hnd, CURLOPT_LOW_SPEED_TIME, time);

          curl_easy_perform(hnd);

          curl_easy_cleanup(hnd);
        }
      }
      break;

    default:
      break;
  }

  curl_global_cleanup();
}
