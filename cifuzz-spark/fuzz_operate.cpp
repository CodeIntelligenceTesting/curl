#include <assert.h>
#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>
#include "tool_setup.h"
#include <sys/stat.h>
#include <signal.h>
#include <iostream>
#include <iomanip>
#include <cctype>
#include <cstring>
#include <fcntl.h>
#include "curlx.h"
#include "tool_doswin.h"
#include "tool_vms.h"
#include "tool_main.h"
#include "memdebug.h"
extern "C" {
  #include "tool_cfgable.h"
  #include "tool_msgs.h"
  #include "tool_operate.h"
  #include "tool_libinfo.h"
  #include "tool_stderr.h"
}

// Define missing functions inline where necessary.
#if defined(HAVE_PIPE) && defined(HAVE_FCNTL)
static int main_checkfds(void)
{
  int fd[2];
  while((fcntl(STDIN_FILENO, F_GETFD) == -1) ||
        (fcntl(STDOUT_FILENO, F_GETFD) == -1) ||
        (fcntl(STDERR_FILENO, F_GETFD) == -1))
    if(pipe(fd))
      return 1;
  return 0;
}
#else
#define main_checkfds() 0
#endif

#ifdef CURLDEBUG
static void memory_tracking_init(void)
{
  char *env;
  env = curl_getenv("CURL_MEMDEBUG");
  if(env) {
    char fname[CURL_MT_LOGFNAME_BUFSIZE];
    if(strlen(env) >= CURL_MT_LOGFNAME_BUFSIZE)
      env[CURL_MT_LOGFNAME_BUFSIZE-1] = '\0';
    strcpy(fname, env);
    curl_free(env);
    curl_dbg_memdebug(fname);
  }
  env = curl_getenv("CURL_MEMLIMIT");
  if(env) {
    char *endptr;
    long num = strtol(env, &endptr, 10);
    if((endptr != env) && (endptr == env + strlen(env)) && (num > 0))
      curl_dbg_memlimit(num);
    curl_free(env);
  }
}
#else
#  define memory_tracking_init() Curl_nop_stmt
#endif

static CURLcode main_init(struct GlobalConfig *config)
{
  CURLcode result = CURLE_OK;
  config->showerror = FALSE;
  config->styled_output = TRUE;
  config->parallel_max = PARALLEL_DEFAULT;

  config->first = config->last = (struct OperationConfig*)malloc(sizeof(struct OperationConfig));
  if(config->first) {
    result = curl_global_init(CURL_GLOBAL_DEFAULT);
    if(!result) {
      result = get_libcurl_info();
      if(!result) {
        config_init(config->first);
        config->first->global = config;
      }
      else {
        errorf(config, "error retrieving curl library information");
        free(config->first);
      }
    }
    else {
      errorf(config, "error initializing curl library");
      free(config->first);
    }
  }
  else {
    errorf(config, "error initializing curl");
    result = CURLE_FAILED_INIT;
  }
  return result;
}

static void free_globalconfig(struct GlobalConfig *config)
{
  Curl_safefree(config->trace_dump);

  if(config->trace_fopened && config->trace_stream)
    fclose(config->trace_stream);
  config->trace_stream = NULL;

  Curl_safefree(config->libcurl);
}

static void main_free(struct GlobalConfig *config)
{
  curl_global_cleanup();
  free_globalconfig(config);
  config_free(config->last);
  config->first = NULL;
  config->last = NULL;
}

static char** createArgv(FuzzedDataProvider& fdp, int& argc) {
  argc = fdp.ConsumeIntegralInRange<int>(1, 100);

  // Add progam name
  const char* dummyProgramName = "/home/patrice/CI/Projects/curl/build/src/curl";
  char** argv = new char*[argc + 1];
  argv[0] = new char[strlen(dummyProgramName) + 1];
  strcpy(argv[0], dummyProgramName);


  for (int i = 1; i < argc; ++i) {
    size_t length = fdp.ConsumeIntegralInRange<size_t>(2, 20);
    argv[i] = new char[length + 1];
    memset(argv[i], 0, length + 1); 

    auto arg = fdp.ConsumeBytesAsString(length);
    
    strcpy(argv[i], arg.c_str());
    if (isdigit(argv[i][0]) || argv[i][0] == 0x0) {
      argv[i][0] = '0';
    }

      // std::cerr << "Argument " << i << ": ";
      // for (size_t j = 0; j < length; ++j) {
      //     std::cerr << std::hex << std::setw(2) << std::setfill('0')
      //               << static_cast<int>(static_cast<unsigned char>(argv[i][j])) << " ";
      // }
      // std::cerr << std::dec << std::endl;
  }
  std::cerr << std::endl;

  argv[argc] = nullptr;

  return argv;
}

extern size_t feature_count;

FUZZ_TEST_SETUP() {
  tool_init_stderr();
}

FUZZ_TEST(const uint8_t *data, size_t size) {

  FuzzedDataProvider fdp(data, size);
  struct GlobalConfig global;
  memset(&global, 0, sizeof(global));

  int argc;
  char** argv = createArgv(fdp, argc);

  if(main_checkfds()) {
    errorf(&global, "out of file descriptors");
    return;
  }

  memory_tracking_init();
  
  CURLcode result = main_init(&global);
  if(!result) {
    result = operate(&global, argc, argv);
    main_free(&global);
  }

  for(int i = 0; i < argc; ++i) {
    delete[] argv[i];
  }
  delete[] argv;

  feature_count = 0;

#ifdef __VMS
  vms_special_exit(result, vms_show);
#endif
}
