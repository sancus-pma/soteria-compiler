if(POLICY CMP0057)
  cmake_policy(SET CMP0057 NEW)
endif()

include(CompilerConfig)
include(LLVMConfig)

set(SRC
    SancusModuleCreator.cpp
    FunctionCcInfo.cpp
    SancusModuleInfo.cpp
    AnnotationParser.cpp
)

include_directories(${CMAKE_CURRENT_BINARY_DIR})
add_llvm_loadable_module(SancusModuleCreator ${SRC})
