cmake_minimum_required(VERSION 3.20)
project(usb_research_toolkit VERSION 0.5.2 LANGUAGES CXX)

option(USB_RESEARCH_BUILD_TESTS "Build unit tests" ON)
option(USB_RESEARCH_BUILD_LIBUSB_HOST_TEST "Build optional libusb host exerciser if libusb is available" ON)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS ON) # linux/raw_gadget.h uses flexible array members

add_library(usb_research
    src/json.cpp
    src/profile.cpp
    src/trace.cpp
    src/raw_gadget_backend_linux.cpp
)
target_include_directories(usb_research PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
if(MSVC)
  target_compile_options(usb_research PRIVATE /W4 /permissive-)
else()
  target_compile_options(usb_research PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_executable(usb-config apps/usb_config_main.cpp)
target_link_libraries(usb-config PRIVATE usb_research)
add_executable(usb-connect apps/usb_connect_main.cpp)
target_link_libraries(usb-connect PRIVATE usb_research)
add_executable(usb-trace apps/usb_trace_main.cpp)
target_link_libraries(usb-trace PRIVATE usb_research)

add_executable(usb-profile-gen apps/usb_profile_gen_main.cpp)
target_link_libraries(usb-profile-gen PRIVATE usb_research)
target_compile_definitions(usb-profile-gen PRIVATE USB_RESEARCH_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}")

if(USB_RESEARCH_BUILD_TESTS)
  enable_testing()
  add_executable(usb-research-tests tests/test_main.cpp)
  target_link_libraries(usb-research-tests PRIVATE usb_research)
  target_compile_definitions(usb-research-tests PRIVATE USB_RESEARCH_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}")
  add_test(NAME usb-research-tests COMMAND usb-research-tests)
  find_package(Python3 COMPONENTS Interpreter QUIET)
  if(Python3_Interpreter_FOUND)
    add_test(NAME usb-normalizer-tests
      COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_normalizer.py
              ${CMAKE_CURRENT_SOURCE_DIR}/scripts/normalize-tshark.py)
    add_test(NAME usb-profile-generator-tests
      COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_profile_generator.py
              $<TARGET_FILE:usb-profile-gen> $<TARGET_FILE:usb-config> ${CMAKE_CURRENT_SOURCE_DIR})
    add_test(NAME usb-lab-tests
      COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_usb_lab.py
              ${CMAKE_CURRENT_SOURCE_DIR}/scripts/usb-lab.py)
    add_test(NAME usb-fuzz-tests
      COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_usb_fuzz.py
              ${CMAKE_CURRENT_SOURCE_DIR}/scripts/usb-fuzz.py)
    add_test(NAME usb-gadget-campaign-tests
      COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_usb_gadget_campaign.py
              ${CMAKE_CURRENT_SOURCE_DIR}/scripts/usb-gadget-campaign.py)
    add_test(NAME usb-host-log-transport-tests
      COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_host_log_transport.py)
    add_test(NAME usb-raw-gadget-backend-tests
      COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_raw_gadget_backend.py
              ${CMAKE_CURRENT_SOURCE_DIR}/src/raw_gadget_backend_linux.cpp)
    add_test(NAME usb-class-profile-tests
      COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_class_profiles.py
              $<TARGET_FILE:usb-config> ${CMAKE_CURRENT_SOURCE_DIR}/profiles/templates)
    add_test(NAME usb-msd-image-tests
      COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_msd_image.py
              ${CMAKE_CURRENT_SOURCE_DIR}/scripts/create-msd-image.py)
    add_test(NAME usb-campaign-byte-report-tests
      COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_campaign_byte_report.py
              ${CMAKE_CURRENT_SOURCE_DIR}/scripts/report-usb-campaign.py)
  endif()
endif()
if(USB_RESEARCH_BUILD_LIBUSB_HOST_TEST)
  find_package(libusb CONFIG QUIET)
  find_package(unofficial-libusb CONFIG QUIET)
  find_package(PkgConfig QUIET)
  if(PkgConfig_FOUND)
    pkg_check_modules(LIBUSB QUIET IMPORTED_TARGET libusb-1.0)
  endif()
  if(TARGET libusb::libusb)
    set(USB_RESEARCH_LIBUSB_TARGET libusb::libusb)
  elseif(TARGET unofficial::libusb::libusb)
    set(USB_RESEARCH_LIBUSB_TARGET unofficial::libusb::libusb)
  elseif(TARGET PkgConfig::LIBUSB)
    set(USB_RESEARCH_LIBUSB_TARGET PkgConfig::LIBUSB)
  endif()
  if(USB_RESEARCH_LIBUSB_TARGET)
    add_executable(usb-host-test apps/usb_host_test.cpp)
    target_link_libraries(usb-host-test PRIVATE usb_research ${USB_RESEARCH_LIBUSB_TARGET})
    message(STATUS "libusb found: optional usb-host-test will be built")
  else()
    message(STATUS "libusb-1.0 not found: skipping optional usb-host-test")
  endif()
endif()

install(TARGETS usb-config usb-connect usb-trace usb-profile-gen RUNTIME DESTINATION bin)
