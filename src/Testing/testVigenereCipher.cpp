//! Unit Tests for MPAGSCipher CaesarCipher Class
#include "gtest/gtest.h"

#include "VigenereCipher.hpp"

const std::string key{"hello"};
const std::string plainText{
    "THISISQUITEALONGMESSAGESOTHEKEYWILLNEEDTOREPEATAFEWTIMES"};
const std::string cipherText{
    "ALTDWZUFTHLEWZBNQPDGHKPDCALPVSFATWZUIPOHVVPASHXLQSDXTXSZ"};

TEST(VigenereCipher, Encrypt)
{
    VigenereCipher cc{key};
    EXPECT_EQ(cc.applyCipher(plainText, CipherMode::Encrypt), cipherText);
}

TEST(VigenereCipher, Decrypt)
{
    VigenereCipher cc{key};

    EXPECT_EQ(cc.applyCipher(cipherText, CipherMode::Decrypt), plainText);
}

TEST(VigenereCipher, GoodKey)
{
    // Minimal key
    EXPECT_NO_THROW(auto c = VigenereCipher("a"));
    // Minimal mixed keys
    EXPECT_NO_THROW(auto c = VigenereCipher("g4"));
    EXPECT_NO_THROW(auto c = VigenereCipher("$k"));
    // Mixed key
    EXPECT_NO_THROW(auto c = VigenereCipher("!$jdgfF45GHK_(*)19"));
    // Mixed key and whitespace
    EXPECT_NO_THROW(auto c = VigenereCipher("  826£*£F   JFJ8e$ "));
}

TEST(VigenereCipher, BadKey)
{
    EXPECT_THROW(auto a = VigenereCipher(""), InvalidKey);
    EXPECT_THROW(auto b = VigenereCipher("!"), InvalidKey);
    EXPECT_THROW(auto c = VigenereCipher("1"), InvalidKey);
}
