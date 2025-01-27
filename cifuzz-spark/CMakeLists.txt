#cifuzz:build-template:begin
#add_fuzz_test({{ .FuzzTestName }} {{ .FileName }})
#target_link_libraries({{ .FuzzTestName }} PRIVATE curltool curlu)
#target_include_directories({{ .FuzzTestName }} PRIVATE
#  "${PROJECT_BINARY_DIR}/lib"            # for "curl_config.h"
#  "${PROJECT_SOURCE_DIR}/lib"            # for "curl_setup.h"
#  "${PROJECT_SOURCE_DIR}/src"
#  "${PROJECT_SOURCE_DIR}/tests/libtest"
#)
#cifuzz:build-template:end

add_fuzz_test(fuzz_test_1 fuzz_test_1.cpp)
target_link_libraries(fuzz_test_1 PRIVATE curltool curlu)
target_include_directories(fuzz_test_1 PRIVATE
  "${PROJECT_BINARY_DIR}/lib"            # for "curl_config.h"
  "${PROJECT_SOURCE_DIR}/lib"            # for "curl_setup.h"
  "${PROJECT_SOURCE_DIR}/src"
  "${PROJECT_SOURCE_DIR}/tests/libtest"
)

add_fuzz_test(fuzz_test_2 fuzz_test_2.cpp)
target_link_libraries(fuzz_test_2 PRIVATE curltool curlu)
target_include_directories(fuzz_test_2 PRIVATE
  "${PROJECT_BINARY_DIR}/lib"            # for "curl_config.h"
  "${PROJECT_SOURCE_DIR}/lib"            # for "curl_setup.h"
  "${PROJECT_SOURCE_DIR}/src"
  "${PROJECT_SOURCE_DIR}/tests/libtest"
)

add_fuzz_test(fuzz_test_3 fuzz_test_3.cpp)
target_link_libraries(fuzz_test_3 PRIVATE curltool curlu)
target_include_directories(fuzz_test_3 PRIVATE
  "${PROJECT_BINARY_DIR}/lib"            # for "curl_config.h"
  "${PROJECT_SOURCE_DIR}/lib"            # for "curl_setup.h"
  "${PROJECT_SOURCE_DIR}/src"
  "${PROJECT_SOURCE_DIR}/tests/libtest"
)

add_fuzz_test(fuzz_test_4 fuzz_test_4.cpp)
target_link_libraries(fuzz_test_4 PRIVATE curltool curlu)
target_include_directories(fuzz_test_4 PRIVATE
  "${PROJECT_BINARY_DIR}/lib"            # for "curl_config.h"
  "${PROJECT_SOURCE_DIR}/lib"            # for "curl_setup.h"
  "${PROJECT_SOURCE_DIR}/src"
  "${PROJECT_SOURCE_DIR}/tests/libtest"
)

add_fuzz_test(fuzz_test_5 fuzz_test_5.cpp)
target_link_libraries(fuzz_test_5 PRIVATE curltool curlu)
target_include_directories(fuzz_test_5 PRIVATE
  "${PROJECT_BINARY_DIR}/lib"            # for "curl_config.h"
  "${PROJECT_SOURCE_DIR}/lib"            # for "curl_setup.h"
  "${PROJECT_SOURCE_DIR}/src"
  "${PROJECT_SOURCE_DIR}/tests/libtest"
  "${PROJECT_SOURCE_DIR}/include/curl"
)

add_fuzz_test(fuzz_test_6 fuzz_test_6.cpp)
target_link_libraries(fuzz_test_6 PRIVATE curltool curlu)
target_include_directories(fuzz_test_6 PRIVATE
  "${PROJECT_BINARY_DIR}/lib"            # for "curl_config.h"
  "${PROJECT_SOURCE_DIR}/lib"            # for "curl_setup.h"
  "${PROJECT_SOURCE_DIR}/src"
  "${PROJECT_SOURCE_DIR}/tests/libtest"
  "${PROJECT_SOURCE_DIR}/include/curl"
)

add_fuzz_test(fuzz_test_7 fuzz_test_7.cpp)
target_link_libraries(fuzz_test_7 PRIVATE curltool curlu)
target_include_directories(fuzz_test_7 PRIVATE
  "${PROJECT_BINARY_DIR}/lib"            # for "curl_config.h"
  "${PROJECT_SOURCE_DIR}/lib"            # for "curl_setup.h"
  "${PROJECT_SOURCE_DIR}/src"
  "${PROJECT_SOURCE_DIR}/tests/libtest"
  "${PROJECT_SOURCE_DIR}/include/curl"
)

add_fuzz_test(fuzz_test_8 fuzz_test_8.cpp)
target_link_libraries(fuzz_test_8 PRIVATE curltool curlu)
target_include_directories(fuzz_test_8 PRIVATE
  "${PROJECT_BINARY_DIR}/lib"            # for "curl_config.h"
  "${PROJECT_SOURCE_DIR}/lib"            # for "curl_setup.h"
  "${PROJECT_SOURCE_DIR}/src"
  "${PROJECT_SOURCE_DIR}/tests/libtest"
  "${PROJECT_SOURCE_DIR}/include/curl"
)

add_fuzz_test(fuzz_test_9 fuzz_test_9.cpp)
target_link_libraries(fuzz_test_9 PRIVATE curltool curlu)
target_include_directories(fuzz_test_9 PRIVATE
  "${PROJECT_BINARY_DIR}/lib"            # for "curl_config.h"
  "${PROJECT_SOURCE_DIR}/lib"            # for "curl_setup.h"
  "${PROJECT_SOURCE_DIR}/src"
  "${PROJECT_SOURCE_DIR}/tests/libtest"
  "${PROJECT_SOURCE_DIR}/include/curl"
)

add_fuzz_test(fuzz_test_10 fuzz_test_10.cpp)
target_link_libraries(fuzz_test_10 PRIVATE curltool curlu)
target_include_directories(fuzz_test_10 PRIVATE
  "${PROJECT_BINARY_DIR}/lib"            # for "curl_config.h"
  "${PROJECT_SOURCE_DIR}/lib"            # for "curl_setup.h"
  "${PROJECT_SOURCE_DIR}/src"
  "${PROJECT_SOURCE_DIR}/tests/libtest"
  "${PROJECT_SOURCE_DIR}/include/curl"
)

