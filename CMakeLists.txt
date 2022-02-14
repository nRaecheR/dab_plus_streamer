cmake_minimum_required(VERSION 3.2)

project(Dab-Plus-Streamer VERSION 0.0.0 LANGUAGES C CXX)

if(NOT DAB-PLUS-STREAMER_VERSION)
  set(DAB-PLUS-STREAMER_VERSION ${PROJECT_VERSION})
endif()

set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 14)

option(KISS_FFT          "KISS FFT instead of FFTW"              OFF )
option(PROFILING         "Enable profiling (see README.md)"      OFF )
option(AIRSPY            "Compile with Airspy support"           OFF )
option(RTLSDR            "Compile with RTL-SDR support"          OFF )
option(SOAPYSDR          "Compile with SoapySDR support"         OFF )

add_definitions(-Wall)
add_definitions(-g)
add_definitions(-DDABLIN_AAC_FAAD2)


if(NOT CMAKE_BUILD_TYPE)
   set(CMAKE_BUILD_TYPE "Release")
   message(STATUS "Build type not specified: defaulting to release.")
endif(NOT CMAKE_BUILD_TYPE)
set(CMAKE_BUILD_TYPE ${CMAKE_BUILD_TYPE} CACHE STRING "")

#enable_testing()

list(INSERT CMAKE_MODULE_PATH 0 ${CMAKE_SOURCE_DIR}/cmake/Modules)

include(GNUInstallDirs)

set(GUI_INSTALL_DIR "${CMAKE_INSTALL_BINDIR}")

if(PROFILING)
    add_definitions(-DWITH_PROFILING)
endif()

find_package(ALSA)
if(ALSA_FOUND)
    add_definitions(-DHAVE_ALSA)
endif()

if(KISS_FFT)
    add_definitions(-DKISSFFT)
    set(fft_sources src/libs/kiss_fft/kiss_fft.c)
    set(KISS_INCLUDE_DIRS src/libs/kiss_fft)
else()
    find_package(FFTW3f REQUIRED)
    set(fft_sources "")
    set(KISS_INCLUDE_DIRS "")
endif()

find_package(Lame REQUIRED)
find_package(Threads REQUIRED)
find_package(Faad REQUIRED)
find_package(MPG123 REQUIRED)

if (RTLSDR)
    find_package(LibRTLSDR REQUIRED)
endif()

if (AIRSPY)
    find_package(LibAIRSPY REQUIRED)
endif()

if (SOAPYSDR)
  find_package(SoapySDR NO_MODULE REQUIRED)
  # Note: SoapySDRConfig.cmake sets C++11 standard so it needs to be reset to C++14
  set(CMAKE_CXX_STANDARD 14)
endif()

include_directories(
    src
    src/backend
    src/output
    src/various
    src/input
    src/libs/fec
    ${FFTW3F_INCLUDE_DIRS}
    ${KISS_INCLUDE_DIRS}
    ${FAAD_INCLUDE_DIRS}
    ${LIBRTLSDR_INCLUDE_DIRS}
    ${SoapySDR_INCLUDE_DIRS}
)

set(backend_sources
    src/backend/dab-audio.cpp
    src/backend/decoder_adapter.cpp
    src/backend/dab_decoder.cpp
    src/backend/dabplus_decoder.cpp
    src/backend/charsets.cpp
    src/backend/dab-constants.cpp
    src/backend/mot_manager.cpp
    src/backend/pad_decoder.cpp
    src/backend/eep-protection.cpp
    src/backend/fib-processor.cpp
    src/backend/fic-handler.cpp
    src/backend/msc-handler.cpp
    src/backend/freq-interleaver.cpp
    src/backend/ofdm-decoder.cpp
    src/backend/ofdm-processor.cpp
    src/backend/phasereference.cpp
    src/backend/phasetable.cpp
    src/backend/tii-decoder.cpp
    src/backend/protTables.cpp
    src/backend/radio-receiver.cpp
    src/backend/tools.cpp
    src/backend/uep-protection.cpp
    src/backend/viterbi.cpp
    src/various/Socket.cpp
    src/various/Xtan2.cpp
    src/various/channels.cpp
    src/various/fft.cpp
    src/various/profiling.cpp
    src/various/wavfile.c
    src/libs/fec/decode_rs_char.c
    src/libs/fec/encode_rs_char.c
    src/libs/fec/init_rs_char.c
)

set(server_sources
    src/server/server.cpp
    src/server/alsa-output.cpp
    src/server/webradiointerface.cpp
    src/server/jsonconvert.cpp
    src/server/webprogrammehandler.cpp
    src/server/tests.cpp
)

set(input_sources
    src/input/input_factory.cpp
    src/input/null_device.cpp
    src/input/raw_file.cpp
    src/input/rtl_tcp.cpp
)

if(LIBRTLSDR_FOUND)
    add_definitions (-DHAVE_RTLSDR)
    set(input_sources  ${input_sources} src/input/rtl_sdr.cpp)
endif()

if(LIBAIRSPY_FOUND)
    add_definitions (-DHAVE_AIRSPY)
    set(input_sources  ${input_sources} src/input/airspy_sdr.cpp)
endif()

if(SoapySDR_FOUND)
    add_definitions (-DHAVE_SOAPYSDR)
    set(input_sources  ${input_sources} src/input/soapy_sdr.cpp)
endif()

if(NOT GIT_COMMIT_HASH)
  execute_process(
    COMMAND git rev-parse --short HEAD
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    OUTPUT_VARIABLE GIT_COMMIT_HASH
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )
endif()

if(GIT_COMMIT_HASH)
  add_definitions("-DGITHASH=\"${GIT_COMMIT_HASH}\"")
endif()

if(NOT GIT_DESCRIBE)
  execute_process(
    COMMAND git describe --tags --long
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    OUTPUT_VARIABLE GIT_DESCRIBE
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )
endif()

if(GIT_DESCRIBE)
  add_definitions("-DGITDESCRIBE=\"${GIT_DESCRIBE}\"")
endif()

STRING(TIMESTAMP BUILD_DATE "%s" UTC)
add_definitions("-DBUILD_DATE=\"${BUILD_DATE}\"")


set(ExecutableName dab_plus_streamer)
add_executable (${ExecutableName} ${server_sources} ${backend_sources} ${input_sources} ${fft_sources})

if(CMAKE_BUILD_TYPE MATCHES Debug)
  SET_TARGET_PROPERTIES(${ExecutableName} PROPERTIES COMPILE_FLAGS "-O2 -fno-omit-frame-pointer -fsanitize=address")
  SET_TARGET_PROPERTIES(${ExecutableName} PROPERTIES LINK_FLAGS "-fno-omit-frame-pointer -fsanitize=address")
endif(CMAKE_BUILD_TYPE MATCHES Debug)

target_link_libraries (${ExecutableName}
  ${LIBRTLSDR_LIBRARIES}
  ${LIBAIRSPY_LIBRARIES}
  ${FFTW3F_LIBRARIES}
  ${FAAD_LIBRARIES}
  ${ALSA_LIBRARIES}
  ${LAME_LIBRARIES}
  ${SoapySDR_LIBRARIES}
  ${MPG123_LIBRARIES}
  Threads::Threads
)

add_custom_command(
		TARGET ${ExecutableName} POST_BUILD
		COMMAND ${CMAKE_COMMAND} -E copy
				${CMAKE_SOURCE_DIR}/src/server/index.html
				${CMAKE_CURRENT_BINARY_DIR}/index.html)
add_custom_command(
		TARGET ${ExecutableName} POST_BUILD
		COMMAND ${CMAKE_COMMAND} -E copy
				${CMAKE_SOURCE_DIR}/src/server/index.js
				${CMAKE_CURRENT_BINARY_DIR}/index.js)

	INSTALL (TARGETS ${ExecutableName} RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
	INSTALL (FILES src/server/doc/man/dab-plus-streamer.1 DESTINATION ${CMAKE_INSTALL_MANDIR}/man1/)
	INSTALL (
		FILES
			${PROJECT_SOURCE_DIR}/src/server/index.html
			${PROJECT_SOURCE_DIR}/src/server/index.js
		DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/server/html/
	)

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/cmake_uninstall.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
    IMMEDIATE @ONLY)

add_custom_target(uninstall
    COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)
