#include <assert.h>
#include <cifuzz/cifuzz.h>
#include <curl/curl.h>
#include <fuzzer/FuzzedDataProvider.h>

FUZZ_TEST_SETUP() {
    curl_global_init(CURL_GLOBAL_DEFAULT);
}

FUZZ_TEST(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);
    CURL *curl = curl_easy_init();
    if(curl) {
        std::string url = fdp.ConsumeRandomLengthString(256);
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, fdp.ConsumeBool());
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, fdp.ConsumeIntegralInRange<long>(1, 30));
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
    }
}
