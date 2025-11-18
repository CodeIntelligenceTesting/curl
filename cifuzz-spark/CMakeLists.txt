include(FetchContent)
FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
)
FetchContent_MakeAvailable(googletest)
include(GoogleTest)

add_executable(operate_test fuzz_operate.cpp)
target_include_directories(operate_test PRIVATE
  "${PROJECT_BINARY_DIR}/lib"            # for "curl_config.h"
  "${PROJECT_SOURCE_DIR}/lib"            # for "curl_setup.h"
  "${PROJECT_SOURCE_DIR}/src"
  "${PROJECT_SOURCE_DIR}/tests/libtest"
)
target_link_libraries(operate_test PRIVATE curltool curlu GTest::gtest_main )
gtest_discover_tests(operate_test)

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

add_fuzz_test(fuzz_operate fuzz_operate.cpp)
target_link_libraries(fuzz_operate PRIVATE curltool curlu GTest::gtest)
target_include_directories(fuzz_operate PRIVATE
  "${PROJECT_BINARY_DIR}/lib"            # for "curl_config.h"
  "${PROJECT_SOURCE_DIR}/lib"            # for "curl_setup.h"
  "${PROJECT_SOURCE_DIR}/src"
  "${PROJECT_SOURCE_DIR}/tests/libtest"
)
