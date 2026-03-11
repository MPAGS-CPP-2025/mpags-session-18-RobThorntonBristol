//! Unit Tests for MPAGSCipher transformChar interface
#include "gtest/gtest.h"

#include "TransformChar.hpp"

TEST(AlphaNumeric, CharactersAreUppercased)
{
    const std::string upper{"ABCDEFGHIJKLMNOPQRSTUVWXYZ"};
    const std::string lower{"abcdefghijklmnopqrstuvwxyz"};

    for (std::size_t i{0}; i < upper.size(); i++) {
        EXPECT_EQ(transformChar(lower[i]), std::string{upper[i]});
    }
}

TEST(AlphaNumeric, DigitsAreTransliterated)
{
    EXPECT_EQ(transformChar('0'), "ZERO");
    EXPECT_EQ(transformChar('1'), "ONE");
    EXPECT_EQ(transformChar('2'), "TWO");
    EXPECT_EQ(transformChar('3'), "THREE");
    EXPECT_EQ(transformChar('4'), "FOUR");
    EXPECT_EQ(transformChar('5'), "FIVE");
    EXPECT_EQ(transformChar('6'), "SIX");
    EXPECT_EQ(transformChar('7'), "SEVEN");
    EXPECT_EQ(transformChar('8'), "EIGHT");
    EXPECT_EQ(transformChar('9'), "NINE");
}

TEST(Punctuation, SpecialCharactersAreRemoved)
{
    const std::string special{"!@£$%^&*()-=][;\'/.,<>?:|}{+_"};

    for (auto& c : special) {
        EXPECT_EQ(transformChar(c), "");
    }
}
