//! Unit Tests for MPAGSCipher CaesarCipher Class
#include "gtest/gtest.h"

#include "CaesarCipher.hpp"

#include <limits>    // For std::numeric_limits

const std::size_t numericKey{10};
const std::string stringKey{"10"};
const std::string plainText{"HELLOWORLD"};
const std::string cipherText{"ROVVYGYBVN"};

TEST(CaesarCipher, Encrypt)
{
    CaesarCipher cc_n{numericKey};
    EXPECT_EQ(cc_n.applyCipher(plainText, CipherMode::Encrypt), cipherText);

    CaesarCipher cc_s{stringKey};
    EXPECT_EQ(cc_s.applyCipher(plainText, CipherMode::Encrypt), cipherText);
}

TEST(CaesarCipher, Decrypt)
{
    CaesarCipher cc_n{numericKey};
    EXPECT_EQ(cc_n.applyCipher(cipherText, CipherMode::Decrypt), plainText);

    CaesarCipher cc_s{stringKey};
    EXPECT_EQ(cc_s.applyCipher(cipherText, CipherMode::Decrypt), plainText);
}

TEST(CaesarCipher, ValidKey)
{
    // "No" key
    EXPECT_NO_THROW(auto c = CaesarCipher("0"));

    // Within alphabet size
    EXPECT_NO_THROW(auto c = CaesarCipher("13"));

    // Larger than alphabet size
    EXPECT_NO_THROW(auto c = CaesarCipher("142"));

    // Largest possible key value as string
    // Often useful to test at numeric limits, which C++ provides a range
    // of functions to query in the <limits> header:
    // - https://en.cppreference.com/w/cpp/types/numeric_limits.html
    // Here, maxKey will be the largest possible value for a value
    // of type std::size_t:
    const auto maxKey = std::numeric_limits<std::size_t>::max();
    const auto maxString = std::to_string(maxKey);
    EXPECT_NO_THROW(auto c = CaesarCipher(maxString));
}

TEST(CaesarCipher, NegativeKey)
{
    EXPECT_THROW(auto c = CaesarCipher("-1"), InvalidKey);
}

TEST(CaesarCipher, NonNumericKey)
{
    EXPECT_THROW(auto c = CaesarCipher("hello"), InvalidKey);
}

TEST(CaesarCipher, OutOfRangeKey)
{
    EXPECT_THROW(auto c = CaesarCipher("999999999999999999999"), InvalidKey);
}
