#include <assert.h>
#include <cifuzz/cifuzz.h>
#include <stdio.h>
#include <string.h>
#include <string> // Required for std::string
#include <vector> // Required for std::vector
#include <fuzzer/FuzzedDataProvider.h> // Required for FuzzedDataProvider
extern "C" {
  #include <curl/curl.h>
}

// Define TRUE as in the original example
#define TRUE 1

// Utility function for tracing
static void dump(const char *text, FILE *stream, unsigned char *ptr,
                 size_t size, char nohex) {
  size_t i;
  size_t c;
  unsigned int width = 0x10;

  if(nohex)
    width = 0x40;

  fprintf(stream, "%s, %10.10lu bytes (0x%8.8lx)\n",
          text, (unsigned long)size, (unsigned long)size);

  for(i = 0; i < size; i += width) {
    fprintf(stream, "%4.4lx: ", (unsigned long)i);
    if(!nohex) {
      for(c = 0; c < width; c++)
        if(i + c < size)
          fprintf(stream, "%02x ", ptr[i + c]);
        else
          fputs("   ", stream);
    }

    for(c = 0; (c < width) && (i + c < size); c++) {
      if(nohex && (i + c + 1 < size) && ptr[i + c] == 0x0D &&
         ptr[i + c + 1] == 0x0A) {
        i += (c + 2 - width);
        break;
      }
      fprintf(stream, "%c",
              (ptr[i + c] >= 0x20) && (ptr[i + c] < 0x80) ? ptr[i + c] : '.');
      if(nohex && (i + c + 2 < size) && ptr[i + c + 1] == 0x0D &&
         ptr[i + c + 2] == 0x0A) {
        i += (c + 3 - width);
        break;
      }
    }
    fputc('\n', stream);
  }
  fflush(stream);
}

static int my_trace(CURL *handle, curl_infotype type,
                    unsigned char *data, size_t size,
                    void *userp) {
  const char *text;

  (void)userp;
  (void)handle;

  switch(type) {
  case CURLINFO_TEXT:
    fprintf(stderr, "== Info: %s", data);
    return 0;
  case CURLINFO_HEADER_OUT:
    text = "=> Send header";
    break;
  case CURLINFO_DATA_OUT:
    text = "=> Send data";
    break;
  case CURLINFO_HEADER_IN:
    text = "<= Recv header";
    break;
  case CURLINFO_DATA_IN:
    text = "<= Recv data";
    break;
  default:
    return 0;
  }

  dump(text, stderr, data, size, TRUE); // Fixed by defining TRUE
  return 0;
}

FUZZ_TEST_SETUP() {
  // One-time initialization tasks if needed
}

FUZZ_TEST(const uint8_t *data, size_t size) {
  CURL *http_handle = curl_easy_init();
  assert(http_handle);

  CURLM *multi_handle = curl_multi_init();
  assert(multi_handle);

  FuzzedDataProvider fdp(data, size);
  std::string url = fdp.ConsumeRandomLengthString(100);  // Generate random URL

  curl_easy_setopt(http_handle, CURLOPT_URL, url.c_str());
  curl_easy_setopt(http_handle, CURLOPT_DEBUGFUNCTION, my_trace);
  curl_easy_setopt(http_handle, CURLOPT_VERBOSE, 1L);

  curl_multi_add_handle(multi_handle, http_handle);

  int still_running = 0;
  do {
    CURLMcode mc = curl_multi_perform(multi_handle, &still_running);
    assert(mc == CURLM_OK);

    if(still_running) {
      mc = curl_multi_poll(multi_handle, NULL, 0, 1000, NULL);
      assert(mc == CURLM_OK);
    }
  } while(still_running);

  curl_multi_cleanup(multi_handle);
  curl_easy_cleanup(http_handle);
}
