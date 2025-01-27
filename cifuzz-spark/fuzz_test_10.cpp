#include <assert.h>
#include <cifuzz/cifuzz.h>
#include <curl/curl.h>
#include <fuzzer/FuzzedDataProvider.h>

FUZZ_TEST_SETUP() {
    curl_global_init(CURL_GLOBAL_ALL);
}

FUZZ_TEST(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    CURL *curl = curl_easy_init();
    if (!curl) {
        return;
    }

    std::string url = fdp.ConsumeRandomLengthString(100);
    std::string userpwd = fdp.ConsumeRandomLengthString(50);
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_USERPWD, userpwd.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_ANY);
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 0L);

    curl_easy_perform(curl);
    curl_easy_cleanup(curl);
}
