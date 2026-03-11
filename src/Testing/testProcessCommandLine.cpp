//! Unit Tests for MPAGSCipher processCommandLine interface
#include "gtest/gtest.h"

#include "ProcessCommandLine.hpp"

TEST(CommandLine, HelpFoundCorrectly)
{
    ProgramSettings settings;
    const std::vector<std::string> cmdLine{"mpags-cipher", "--help"};
    EXPECT_NO_THROW(settings = processCommandLine(cmdLine));
    EXPECT_TRUE(settings.helpRequested);
}

TEST(CommandLine, VersionFoundCorrectly)
{
    ProgramSettings settings;
    const std::vector<std::string> cmdLine{"mpags-cipher", "--version"};
    EXPECT_NO_THROW(settings = processCommandLine(cmdLine));
    EXPECT_TRUE(settings.versionRequested);
}

TEST(CommandLine, EncryptModeActivated)
{
    ProgramSettings settings;
    const std::vector<std::string> cmdLine{"mpags-cipher", "--encrypt"};
    EXPECT_NO_THROW(settings = processCommandLine(cmdLine));
    EXPECT_EQ(settings.cipherMode, CipherMode::Encrypt);
}

TEST(CommandLine, DecryptModeActivated)
{
    ProgramSettings settings;
    const std::vector<std::string> cmdLine{"mpags-cipher", "--decrypt"};
    EXPECT_NO_THROW(settings = processCommandLine(cmdLine));
    EXPECT_EQ(settings.cipherMode, CipherMode::Decrypt);
}

TEST(CommandLine, KeyEnteredWithoutSpecification)
{
    ProgramSettings settings;
    const std::vector<std::string> cmdLine{"mpags-cipher", "-k"};
    EXPECT_THROW(settings = processCommandLine(cmdLine), MissingArgument);
}

TEST(CommandLine, KeyEnteredAndSpecified)
{
    ProgramSettings settings;
    const std::vector<std::string> cmdLine{"mpags-cipher", "-k", "4"};
    EXPECT_NO_THROW(settings = processCommandLine(cmdLine));
    EXPECT_EQ(settings.cipherKey.size(), 1);
    EXPECT_EQ(settings.cipherKey[0], "4");
}

TEST(CommandLine, InputFileWithoutArg)
{
    ProgramSettings settings;
    const std::vector<std::string> cmdLine{"mpags-cipher", "-i"};
    EXPECT_THROW(settings = processCommandLine(cmdLine), MissingArgument);
}

TEST(CommandLine, InputFileDeclared)
{
    ProgramSettings settings;
    const std::vector<std::string> cmdLine{"mpags-cipher", "-i", "input.txt"};
    EXPECT_NO_THROW(settings = processCommandLine(cmdLine));
    EXPECT_EQ(settings.inputFile, "input.txt");
}

TEST(CommandLine, OutputFileWithoutArg)
{
    ProgramSettings settings;
    const std::vector<std::string> cmdLine{"mpags-cipher", "-o"};
    EXPECT_THROW(settings = processCommandLine(cmdLine), MissingArgument);
}

TEST(CommandLine, OutputFileDeclared)
{
    ProgramSettings settings;
    const std::vector<std::string> cmdLine{"mpags-cipher", "-o", "output.txt"};
    EXPECT_NO_THROW(settings = processCommandLine(cmdLine));
    EXPECT_EQ(settings.outputFile, "output.txt");
}

TEST(CommandLine, CipherTypeWithoutArg)
{
    ProgramSettings settings;
    const std::vector<std::string> cmdLine{"mpags-cipher", "-c"};
    EXPECT_THROW(settings = processCommandLine(cmdLine), MissingArgument);
}

TEST(CommandLine, CipherTypeUnknown)
{
    ProgramSettings settings;
    const std::vector<std::string> cmdLine{"mpags-cipher", "-c", "rubbish"};
    EXPECT_THROW(settings = processCommandLine(cmdLine), UnknownArgument);
}

TEST(CommandLine, CipherTypeCaesar)
{
    ProgramSettings settings;
    const std::vector<std::string> cmdLine{"mpags-cipher", "-c", "caesar"};
    EXPECT_NO_THROW(settings = processCommandLine(cmdLine));
    EXPECT_EQ(settings.cipherType.size(), 1);
    EXPECT_EQ(settings.cipherType[0], CipherType::Caesar);
}

TEST(CommandLine, CipherTypePlayfair)
{
    ProgramSettings settings;
    const std::vector<std::string> cmdLine{"mpags-cipher", "-c", "playfair"};
    EXPECT_NO_THROW(settings = processCommandLine(cmdLine));
    EXPECT_EQ(settings.cipherType.size(), 1);
    EXPECT_EQ(settings.cipherType[0], CipherType::Playfair);
}

TEST(CommandLine, CipherTypeVigenere)
{
    ProgramSettings settings;
    const std::vector<std::string> cmdLine{"mpags-cipher", "-c", "vigenere"};
    EXPECT_NO_THROW(settings = processCommandLine(cmdLine));
    EXPECT_EQ(settings.cipherType.size(), 1);
    EXPECT_EQ(settings.cipherType[0], CipherType::Vigenere);
}

TEST(CommandLine, MultiCipherWithoutArg)
{
    ProgramSettings settings;
    const std::vector<std::string> cmdLine{"mpags-cipher", "--multi-cipher"};
    EXPECT_THROW(settings = processCommandLine(cmdLine), MissingArgument);
}

TEST(CommandLine, MultiCipherInvalidArg)
{
    ProgramSettings settings;
    const std::vector<std::string> cmdLine{"mpags-cipher", "--multi-cipher",
                                           "a"};
    EXPECT_THROW(settings = processCommandLine(cmdLine), InvalidArgument);
}

TEST(CommandLine, MultiCipherMismatchedArgs)
{
    ProgramSettings settings;
    const std::vector<std::string> cmdLine{
        "mpags-cipher", "--multi-cipher", "2", "-c", "caesar", "-k", "23"};
    EXPECT_THROW(settings = processCommandLine(cmdLine), InconsistentArguments);
}

TEST(CommandLine, MultiCipherMatchedArgs)
{
    ProgramSettings settings;
    const std::vector<std::string> cmdLine{"mpags-cipher",
                                           "--multi-cipher",
                                           "2",
                                           "-c",
                                           "caesar",
                                           "-k",
                                           "23",
                                           "-c",
                                           "playfair",
                                           "-k",
                                           "playfairexample"};

    EXPECT_NO_THROW(settings = processCommandLine(cmdLine));
    EXPECT_EQ(settings.cipherType.size(), 2);
    EXPECT_EQ(settings.cipherType[0], CipherType::Caesar);
    EXPECT_EQ(settings.cipherType[1], CipherType::Playfair);
    EXPECT_EQ(settings.cipherKey.size(), 2);
    EXPECT_EQ(settings.cipherKey[0], "23");
    EXPECT_EQ(settings.cipherKey[1], "playfairexample");
}
