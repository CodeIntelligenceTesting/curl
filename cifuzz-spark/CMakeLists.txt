#cifuzz:build-template:begin
#add_fuzz_test({{ .FuzzTestName }} {{ .FileName }})
#target_link_libraries({{ .FuzzTestName }} PRIVATE curltool curlu wrappers -Wl,--wrap=read,--wrap=curl_multi_poll)
#target_include_directories({{ .FuzzTestName }} PRIVATE
#  "${PROJECT_BINARY_DIR}/lib"            # for "curl_config.h"
#  "${PROJECT_SOURCE_DIR}/lib"            # for "curl_setup.h"
#  "${PROJECT_SOURCE_DIR}/lib/curlx"
#  "${PROJECT_SOURCE_DIR}/src"
#  "${PROJECT_SOURCE_DIR}/tests/libtest"
#)
#cifuzz:build-template:end

add_library(wrappers STATIC wrappers.c)
target_link_libraries(wrappers PRIVATE curltool curlu)
target_include_directories(wrappers PRIVATE
"${PROJECT_BINARY_DIR}/lib"
"${PROJECT_SOURCE_DIR}/lib"
"${PROJECT_SOURCE_DIR}/src"
"${PROJECT_SOURCE_DIR}/tests/libtest"
)
add_fuzz_test(fuzz_curl_easy_perform fuzz_curl_easy_perform.cpp)
target_link_libraries(fuzz_curl_easy_perform PRIVATE curltool curlu)
target_include_directories(fuzz_curl_easy_perform PRIVATE
  "${PROJECT_BINARY_DIR}/lib"            # for "curl_config.h"
  "${PROJECT_SOURCE_DIR}/lib"            # for "curl_setup.h"
  "${PROJECT_SOURCE_DIR}/lib/curlx"
  "${PROJECT_SOURCE_DIR}/src"
  "${PROJECT_SOURCE_DIR}/tests/libtest"
)
add_fuzz_test(fuzz_curl_multi_socket_action fuzz_curl_multi_socket_action.cpp)
target_link_libraries(fuzz_curl_multi_socket_action PRIVATE curltool curlu)
target_include_directories(fuzz_curl_multi_socket_action PRIVATE
  "${PROJECT_BINARY_DIR}/lib"            # for "curl_config.h"
  "${PROJECT_SOURCE_DIR}/lib"            # for "curl_setup.h"
  "${PROJECT_SOURCE_DIR}/lib/curlx"
  "${PROJECT_SOURCE_DIR}/src"
  "${PROJECT_SOURCE_DIR}/tests/libtest"
)
add_fuzz_test(fuzz_curl_multi_perform fuzz_curl_multi_perform.cpp)
target_link_libraries(fuzz_curl_multi_perform PRIVATE curltool curlu)
target_include_directories(fuzz_curl_multi_perform PRIVATE
  "${PROJECT_BINARY_DIR}/lib"            # for "curl_config.h"
  "${PROJECT_SOURCE_DIR}/lib"            # for "curl_setup.h"
  "${PROJECT_SOURCE_DIR}/lib/curlx"
  "${PROJECT_SOURCE_DIR}/src"
  "${PROJECT_SOURCE_DIR}/tests/libtest"
)
add_fuzz_test(fuzz_Curl_doh fuzz_Curl_doh.cpp)
target_link_libraries(fuzz_Curl_doh PRIVATE curltool curlu)
target_include_directories(fuzz_Curl_doh PRIVATE
  "${PROJECT_BINARY_DIR}/lib"            # for "curl_config.h"
  "${PROJECT_SOURCE_DIR}/lib"            # for "curl_setup.h"
  "${PROJECT_SOURCE_DIR}/lib/curlx"
  "${PROJECT_SOURCE_DIR}/src"
  "${PROJECT_SOURCE_DIR}/tests/libtest"
)
add_fuzz_test(fuzz_parse_args fuzz_parse_args.cpp)
target_link_libraries(fuzz_parse_args PRIVATE curltool curlu)
target_include_directories(fuzz_parse_args PRIVATE
  "${PROJECT_BINARY_DIR}/lib"            # for "curl_config.h"
  "${PROJECT_SOURCE_DIR}/lib"            # for "curl_setup.h"
  "${PROJECT_SOURCE_DIR}/lib/curlx"
  "${PROJECT_SOURCE_DIR}/src"
  "${PROJECT_SOURCE_DIR}/tests/libtest"
)
add_fuzz_test(fuzz_parseconfig fuzz_parseconfig.cpp)
target_link_libraries(fuzz_parseconfig PRIVATE curltool curlu)
target_include_directories(fuzz_parseconfig PRIVATE
  "${PROJECT_BINARY_DIR}/lib"            # for "curl_config.h"
  "${PROJECT_SOURCE_DIR}/lib"            # for "curl_setup.h"
  "${PROJECT_SOURCE_DIR}/lib/curlx"
  "${PROJECT_SOURCE_DIR}/src"
  "${PROJECT_SOURCE_DIR}/tests/libtest"
)
add_fuzz_test(fuzz_tool_setopt_mimepost fuzz_tool_setopt_mimepost.cpp)
target_link_libraries(fuzz_tool_setopt_mimepost PRIVATE curltool curlu)
target_include_directories(fuzz_tool_setopt_mimepost PRIVATE
  "${PROJECT_BINARY_DIR}/lib"            # for "curl_config.h"
  "${PROJECT_SOURCE_DIR}/lib"            # for "curl_setup.h"
  "${PROJECT_SOURCE_DIR}/lib/curlx"
  "${PROJECT_SOURCE_DIR}/src"
  "${PROJECT_SOURCE_DIR}/tests/libtest"
)
add_fuzz_test(fuzz_curl_share_setopt fuzz_curl_share_setopt.cpp)
target_link_libraries(fuzz_curl_share_setopt PRIVATE curltool curlu)
target_include_directories(fuzz_curl_share_setopt PRIVATE
  "${PROJECT_BINARY_DIR}/lib"            # for "curl_config.h"
  "${PROJECT_SOURCE_DIR}/lib"            # for "curl_setup.h"
  "${PROJECT_SOURCE_DIR}/lib/curlx"
  "${PROJECT_SOURCE_DIR}/src"
  "${PROJECT_SOURCE_DIR}/tests/libtest"
)
