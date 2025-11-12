#include <assert.h>
#include <cifuzz/cifuzz.h>
#include <curl/curl.h>
#include <pthread.h>
#include <fuzzer/FuzzedDataProvider.h>

extern "C" {
  #include "curl_threads.h"
}

#define THREAD_SIZE 16
#define PER_THREAD_SIZE 8

struct Ctx {
  const char *URL;
  CURLSH *share;
  int result;
  struct curl_slist *contents;
};

static void my_lock(CURL *handle, curl_lock_data data, curl_lock_access laccess, void *useptr) {
  (void)handle;
  (void)data;
  (void)laccess;
  (void)useptr;
}

static void my_unlock(CURL *handle, curl_lock_data data, void *useptr) {
  (void)handle;
  (void)data;
  (void)useptr;
}

static void test_lock(CURL *handle, curl_lock_data data, curl_lock_access access, void *useptr) {
  curl_mutex_t *mutexes = static_cast<curl_mutex_t*>(useptr);
  (void)handle;
  (void)access;
  Curl_mutex_acquire(&mutexes[data]);
}

static void test_unlock(CURL *handle, curl_lock_data data, void *useptr) {
  curl_mutex_t *mutexes = static_cast<curl_mutex_t*>(useptr);
  (void)handle;
  Curl_mutex_release(&mutexes[data]);
}

#if defined(_WIN32_WCE) || defined(CURL_WINDOWS_UWP)
DWORD
#else
unsigned int
#endif
CURL_STDCALL test_thread(void *ptr) {
  struct Ctx *ctx = static_cast<struct Ctx*>(ptr);
  CURLcode res = CURLE_OK;

  for(int i = 0; i < PER_THREAD_SIZE; i++) {
    CURL *curl = curl_easy_init();
    if(curl) {
      curl_easy_setopt(curl, CURLOPT_SHARE, ctx->share);
      curl_easy_setopt(curl, CURLOPT_URL, ctx->URL);
      curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
      res = curl_easy_perform(curl);
      curl_easy_cleanup(curl);
      if(res != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        ctx->result = static_cast<int>(res);
        return 0;
      }
    }
  }
  ctx->result = static_cast<int>(res);
  return 0;
}

FUZZ_TEST_SETUP() {
  // One-time setup if necessary
}

FUZZ_TEST(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);
  
  switch (fdp.ConsumeIntegralInRange<int>(0, 2)) {
    case 0: {
      CURLSH *share = curl_share_init();
      CURLSHcode code;
      
      curl_lock_data lock_data = fdp.PickValueInArray({
        CURL_LOCK_DATA_COOKIE,
        CURL_LOCK_DATA_DNS,
        CURL_LOCK_DATA_SSL_SESSION,
        CURL_LOCK_DATA_CONNECT,
        CURL_LOCK_DATA_PSL,
        CURL_LOCK_DATA_HSTS
      });
      
      code = curl_share_setopt(share, CURLSHOPT_SHARE, lock_data);
      curl_share_cleanup(share);
      break;
    }
    
    case 1: {
      CURLSH *share = curl_share_init();
      
      curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_CONNECT);
      curl_share_setopt(share, CURLSHOPT_LOCKFUNC, my_lock);
      curl_share_setopt(share, CURLSHOPT_UNLOCKFUNC, my_unlock);
      
      CURL *curl = curl_easy_init();
      if (curl) {
        std::string url = fdp.ConsumeRandomLengthString(256);
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_SHARE, share);
        
        CURLcode res = curl_easy_perform(curl);
        
        curl_easy_cleanup(curl);
      }
      
      curl_share_cleanup(share);
      break;
    }
    
    case 2: {
      char *url = strdup(fdp.ConsumeRandomLengthString(256).c_str());

      CURLSH *share = curl_share_init();
      struct Ctx ctx[THREAD_SIZE];
      curl_mutex_t mutexes[CURL_LOCK_DATA_LAST - 1];

      if(!share) {
        free(url);
        return;
      }

      for(int i = 0; i < CURL_LOCK_DATA_LAST - 1; i++) {
        Curl_mutex_init(&mutexes[i]);
      }

      curl_share_setopt(share, CURLSHOPT_LOCKFUNC, test_lock);
      curl_share_setopt(share, CURLSHOPT_UNLOCKFUNC, test_unlock);
      curl_share_setopt(share, CURLSHOPT_USERDATA, static_cast<void*>(mutexes));

      for(int i = 0; i < THREAD_SIZE; i++) {
        ctx[i].share = share;
        ctx[i].URL = url;
        ctx[i].result = 0;
        ctx[i].contents = nullptr;
      }

      curl_thread_t thread[THREAD_SIZE];
      for(int i = 0; i < THREAD_SIZE; i++) {
        thread[i] = Curl_thread_create(test_thread, static_cast<void*>(&ctx[i]));
      }

      for(int i = 0; i < THREAD_SIZE; i++) {
        if(thread[i]) {
          Curl_thread_join(&thread[i]);
          Curl_thread_destroy(thread[i]);
        }
      }

      curl_share_cleanup(share);
      free(url);
      break;
    }
    
    default:
      assert(false); // Should never reach here
      break;
  }
}
