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
target_link_libraries(fuzz_operate PRIVATE curltool curlu)
target_include_directories(fuzz_operate PRIVATE
  "${PROJECT_BINARY_DIR}/lib"            # for "curl_config.h"
  "${PROJECT_SOURCE_DIR}/lib"            # for "curl_setup.h"
  "${PROJECT_SOURCE_DIR}/src"
  "${PROJECT_SOURCE_DIR}/tests/libtest"
)
