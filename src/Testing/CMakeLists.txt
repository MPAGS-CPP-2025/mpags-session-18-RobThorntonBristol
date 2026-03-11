# - Build sub-script for the MPAGSCipher library unit tests

# - Set a CMake policy to avoid warning messages from FetchContent when downloading
#   due to our low minimum required CMake version
#   - See:
#     - https://cmake.org/cmake/help/latest/command/cmake_policy.html
#     - https://cmake.org/cmake/help/latest/policy/CMP0135.html
cmake_policy(SET CMP0135 NEW)

# - Import googletest into our project (v1.17.0)
#   - https://github.com/google/googletest/releases/tag/v1.17.0
#   - Uses CMake's capability to download and make another CMake based project
#     and effective "subproject"
#   - Generally should only be used to import things you won't end up installing
#     otherwise you can quickly mess things up. It **is not** a substitute for
#     a proper package management system 
#   - For more details see:
#     - https://cmake.org/cmake/help/latest/module/FetchContent.html
include(FetchContent)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/52eb8108c5bdec04579160ae17225d66034bd723.zip
)
# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
# Don't build the gmock component
set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)
# Don't install gtest itself
set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)
# - end of GoogleTest setup

# Most basic test
add_executable(testHello testHello.cpp)
add_test(NAME test-hello COMMAND testHello)

# First GTest-based test
add_executable(testGTest testGTest.cpp)
target_link_libraries(testGTest PRIVATE GTest::gtest_main)
add_test(NAME test-gtest COMMAND testGTest)

# Test TransformChar
add_executable(testTransformChar testTransformChar.cpp)
target_link_libraries(testTransformChar PRIVATE GTest::gtest_main MPAGSCipher)
add_test(NAME test-transformchar COMMAND testTransformChar)

# Test ProcessCommandLine
add_executable(testProcessCommandLine testProcessCommandLine.cpp)
target_link_libraries(testProcessCommandLine PRIVATE GTest::gtest_main MPAGSCipher)
add_test(NAME test-processcommandline COMMAND testProcessCommandLine)

# Test CaesarCipher
add_executable(testCaesarCipher testCaesarCipher.cpp)
target_link_libraries(testCaesarCipher PRIVATE GTest::gtest_main MPAGSCipher)
add_test(NAME test-caesarcipher COMMAND testCaesarCipher)

# Test PlayfairCipher
add_executable(testPlayfairCipher testPlayfairCipher.cpp)
target_link_libraries(testPlayfairCipher PRIVATE GTest::gtest_main MPAGSCipher)
add_test(NAME test-playfaircipher COMMAND testPlayfairCipher)

# Test VigenereCipher
add_executable(testVigenereCipher testVigenereCipher.cpp)
target_link_libraries(testVigenereCipher PRIVATE GTest::gtest_main MPAGSCipher)
add_test(NAME test-vigenerecipher COMMAND testVigenereCipher)

# Test all Cipher classes
add_executable(testCiphers testCiphers.cpp)
target_link_libraries(testCiphers PRIVATE GTest::gtest_main MPAGSCipher)
add_test(NAME test-ciphers COMMAND testCiphers)
