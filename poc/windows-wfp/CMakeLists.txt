cmake_minimum_required(VERSION 3.21)
project(ActShiftWfpPoc LANGUAGES CXX)

if(NOT WIN32)
  message(FATAL_ERROR "The WFP PoC must be built with the Windows SDK on Windows.")
endif()

add_executable(actshift-wfp-poc main.cpp)
target_compile_features(actshift-wfp-poc PRIVATE cxx_std_17)
target_compile_definitions(actshift-wfp-poc PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
target_link_libraries(actshift-wfp-poc PRIVATE fwpuclnt advapi32)

if(MSVC)
  target_compile_options(actshift-wfp-poc PRIVATE /W4 /WX /EHsc)
endif()
