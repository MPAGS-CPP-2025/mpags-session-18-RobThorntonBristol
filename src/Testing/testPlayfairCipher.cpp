//! Unit Tests for MPAGSCipher CaesarCipher Class
#include "gtest/gtest.h"

#include "PlayfairCipher.hpp"

TEST(PlayfairCipher, Encrypt)
{
    PlayfairCipher cc{"hello"};
    EXPECT_EQ(
        cc.applyCipher("BOBISSOMESORTOFJUNIORCOMPLEXXENOPHONEONEZEROTHING",
                       CipherMode::Encrypt),
        "FHIQXLTLKLTLSUFNPQPKETFENIOLVSWLTFIAFTLAKOWATEQOKPPA");
}

TEST(PlayfairCipher, Decrypt)
{
    PlayfairCipher cc{"hello"};
    EXPECT_EQ(
        cc.applyCipher("FHIQXLTLKLTLSUFNPQPKETFENIOLVSWLTFIAFTLAKOWATEQOKPPA",
                       CipherMode::Decrypt),
        "BOBISXSOMESORTOFIUNIORCOMPLEXQXENOPHONEONEZEROTHINGZ");
}
