cmake_minimum_required(VERSION 3.10)

# set the project name
project(OPRFGarbledCircuit)

enable_testing() # apparently necessary for boost unit tests

set(MY_SOURCES   oprf_test.cpp garbling-scheme.cpp)
#Write brinaries to bin/
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

add_subdirectory(emp-tool)
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

find_package(Boost REQUIRED)


# add the executable
add_executable(oprf_test ${MY_SOURCES})
add_executable(test_test test.cpp garbling-scheme.cpp)
add_executable(test_user oprf_user.cpp garbling-scheme.cpp)
add_executable(test_server oprf_server.cpp garbling-scheme.cpp)
add_executable(2HashDH_server 2HashDH_Server.cpp)
add_executable(2HashDH_user 2HashDH_User.cpp hash2Curve.cpp)
add_executable(hash2Curve_test hash2Curve_unit_tests.cpp hash2Curve.cpp)

target_link_libraries(oprf_test ${OPENSSL_LIBRARIES})
target_link_libraries(oprf_test emp-tool)
target_link_libraries(test_test ${OPENSSL_LIBRARIES})
target_link_libraries(test_test emp-tool)
target_link_libraries(test_server ${OPENSSL_LIBRARIES})
target_link_libraries(test_server emp-tool)
target_link_libraries(test_user ${OPENSSL_LIBRARIES})
target_link_libraries(test_user emp-tool)
target_link_libraries(2HashDH_user ${OPENSSL_LIBRARIES})
target_link_libraries(2HashDH_user emp-tool)
target_link_libraries(2HashDH_server ${OPENSSL_LIBRARIES})
target_link_libraries(2HashDH_server emp-tool)
target_link_libraries(hash2Curve_test ${OPENSSL_LIBRARIES})




target_include_directories(oprf_test PUBLIC . emp-tool)
target_include_directories(test_test PUBLIC . emp-tool)
target_include_directories(test_user PUBLIC . emp-tool)
target_include_directories(test_server PUBLIC . emp-tool)
target_include_directories(2HashDH_server PUBLIC . emp-tool)
target_include_directories(2HashDH_user PUBLIC . emp-tool)

target_include_directories(hash2Curve_test PRIVATE ${BOOST_INCLUDE_DIR})
add_test(NAME test_hash2Curve COMMAND hash2Curve_test)


set(CMAKE_FOLDER emp-tool/)
include(emp-tool/cmake/emp-base.cmake)
set(CMAKE_FOLDER .)


