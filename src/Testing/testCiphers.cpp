//! Unit Tests for MPAGSCipher Cipher Classes
#include "gtest/gtest.h"

#include <map>
#include <string>

#include "CaesarCipher.hpp"
#include "Cipher.hpp"
#include "CipherMode.hpp"
#include "CipherType.hpp"
#include "PlayfairCipher.hpp"
#include "VigenereCipher.hpp"

std::map<CipherType, std::string> plainText{
    {CipherType::Caesar, "HELLOWORLD"},
    {CipherType::Playfair,
     "BOBISXSOMESORTOFIUNIORCOMPLEXQXENOPHONEONEZEROTHINGZ"},
    {CipherType::Vigenere,
     "THISISQUITEALONGMESSAGESOTHEKEYWILLNEEDTOREPEATAFEWTIMES"}};

std::map<CipherType, std::string> cipherText{
    {CipherType::Caesar, "ROVVYGYBVN"},
    {CipherType::Playfair,
     "FHIQXLTLKLTLSUFNPQPKETFENIOLVSWLTFIAFTLAKOWATEQOKPPA"},
    {CipherType::Vigenere,
     "ALTDWZUFTHLEWZBNQPDGHKPDCALPVSFATWZUIPOHVVPASHXLQSDXTXSZ"}};

bool testCipher(const Cipher& cipher, const CipherMode mode,
                const std::string& inputText, const std::string& outputText)
{
    return cipher.applyCipher(inputText, mode) == outputText;
}

TEST(Cipher, Encryption)
{
    CaesarCipher cc{10};
    PlayfairCipher pc{"hello"};
    VigenereCipher vc{"hello"};

    EXPECT_TRUE(testCipher(cc, CipherMode::Encrypt,
                           plainText[CipherType::Caesar],
                           cipherText[CipherType::Caesar]));
    EXPECT_TRUE(testCipher(pc, CipherMode::Encrypt,
                           plainText[CipherType::Playfair],
                           cipherText[CipherType::Playfair]));
    EXPECT_TRUE(testCipher(vc, CipherMode::Encrypt,
                           plainText[CipherType::Vigenere],
                           cipherText[CipherType::Vigenere]));
}

TEST(Cipher, Decryption)
{
    CaesarCipher cc{10};
    PlayfairCipher pc{"hello"};
    VigenereCipher vc{"hello"};

    EXPECT_TRUE(testCipher(cc, CipherMode::Decrypt,
                           cipherText[CipherType::Caesar],
                           plainText[CipherType::Caesar]));
    EXPECT_TRUE(testCipher(pc, CipherMode::Decrypt,
                           cipherText[CipherType::Playfair],
                           plainText[CipherType::Playfair]));
    EXPECT_TRUE(testCipher(vc, CipherMode::Decrypt,
                           cipherText[CipherType::Vigenere],
                           plainText[CipherType::Vigenere]));
}
