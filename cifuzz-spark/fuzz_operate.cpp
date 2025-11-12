#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>
#include "tool_setup.h"

#ifndef UNDER_CE
#include <signal.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include <cctype>
#include <climits>
#include <cstdlib>
#include <cstring>
#include <string>

#include "memdebug.h"

extern "C" {
#include "tool_cfgable.h"
#include "tool_msgs.h"
#include "tool_operate.h"
#include "tool_libinfo.h"
#include "tool_stderr.h"
#include "tool_vms.h"
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
  /* if CURL_MEMDEBUG is set, this starts memory tracking message logging */
  env = curl_getenv("CURL_MEMDEBUG");
  if(env) {
    /* use the value as filename */
    char fname[512];
    if(strlen(env) >= sizeof(fname))
      env[sizeof(fname)-1] = '\0';
    strcpy(fname, env);
    curl_free(env);
    curl_dbg_memdebug(fname);
  }
  /* if CURL_MEMLIMIT is set, this enables fail-on-alloc-number-N feature */
  env = curl_getenv("CURL_MEMLIMIT");
  if(env) {
    curl_off_t num;
    const char *p = env;
    if(!curlx_str_number(&p, &num, LONG_MAX))
      curl_dbg_memlimit((long)num);
    curl_free(env);
  }
}
#else
#  define memory_tracking_init() tool_nop_stmt
#endif

static void destroyArgv(argv_item_t *argv, int count)
{
  if(!argv)
    return;

  for(int i = 0; i < count; ++i) {
    free(argv[i]);
    argv[i] = nullptr;
  }
  free(argv);
}

static argv_item_t *createArgv(FuzzedDataProvider &fdp, int *argc_out)
{
  if(!argc_out)
    return nullptr;

  int argc = fdp.ConsumeIntegralInRange<int>(1, 100);
  argv_item_t *argv =
    static_cast<argv_item_t *>(calloc(static_cast<size_t>(argc + 1),
                                      sizeof(*argv)));
  if(!argv) {
    *argc_out = 0;
    return nullptr;
  }

  const char *dummyProgramName = "/home/patrice/CI/Projects/curl/build/src/curl";
  argv[0] = strdup(dummyProgramName);
  if(!argv[0]) {
    destroyArgv(argv, 0);
    *argc_out = 0;
    return nullptr;
  }

  int allocated = 1;
  for(int i = 1; i < argc; ++i) {
    size_t length = fdp.ConsumeIntegralInRange<size_t>(1, 32);
    char *argbuf = static_cast<char *>(malloc(length + 1));
    if(!argbuf) {
      destroyArgv(argv, allocated);
      *argc_out = 0;
      return nullptr;
    }

    std::string bytes = fdp.ConsumeBytesAsString(length);
    size_t copy_len = bytes.size();
    if(copy_len > length)
      copy_len = length;
    if(copy_len)
      memcpy(argbuf, bytes.data(), copy_len);
    if(copy_len < length)
      memset(argbuf + copy_len, 0, length - copy_len);
    argbuf[length] = '\0';

    if(argbuf[0] == '\0')
      argbuf[0] = '0';

    argv[i] = argbuf;
    ++allocated;
  }

  *argc_out = argc;
  return argv;
}

static void reset_global_config(void)
{
  if(global) {
    struct GlobalConfig *cfg = global;
    memset(cfg, 0, sizeof(*cfg));
    global = nullptr;
  }
}

FUZZ_TEST_SETUP() {
  tool_init_stderr();
}

FUZZ_TEST(const uint8_t *data, size_t size) {

  FuzzedDataProvider fdp(data, size);

  int argc = 0;
  argv_item_t *argv = createArgv(fdp, &argc);
  if(!argv)
    return;

  if(main_checkfds()) {
    destroyArgv(argv, argc);
    return;
  }

#if defined(HAVE_SIGNAL) && defined(SIGPIPE)
  (void)signal(SIGPIPE, SIG_IGN);
#endif

  memory_tracking_init();

  CURLcode init_result = globalconf_init();
#ifdef __VMS
  CURLcode result = init_result;
#endif
  if(!init_result) {
#ifdef __VMS
    CURLcode operate_result = operate(argc, argv);
    result = operate_result;
#else
    (void)operate(argc, argv);
#endif
    globalconf_free();
  }

  destroyArgv(argv, argc);

  feature_count = 0;

#ifdef __VMS
  vms_special_exit(result, vms_show);
#endif

  reset_global_config();
}
