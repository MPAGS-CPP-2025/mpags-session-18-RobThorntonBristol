#include "CipherFactory.hpp"
#include "CipherMode.hpp"
#include "CipherType.hpp"
#include "ProcessCommandLine.hpp"
#include "TransformChar.hpp"

#include <algorithm>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <future>
#include <chrono>
#include <thread>

int main(int argc, char* argv[])
{
    // Convert the command-line arguments into a more easily usable form
    const std::vector<std::string> cmdLineArgs{argv, argv + argc};

    // Process command line arguments
    ProgramSettings settings;
    try {
        settings = processCommandLine(cmdLineArgs);

    } catch (const MissingArgument& e) {
        std::cerr << "[error] Missing argument: " << e.what() << std::endl;
        return 1;

    } catch (const UnknownArgument& e) {
        std::cerr << "[error] Unknown argument: " << e.what() << std::endl;
        return 1;
    } catch (const InvalidArgument& e) {
        std::cerr << "[error] Invalid argument: " << e.what() << std::endl;
        return 1;
    } catch (const InconsistentArguments& e) {
        std::cerr << "[error] Inconsistent arguments: " << e.what()
                  << std::endl;
        return 1;
    }

    // Handle help, if requested
    if (settings.helpRequested) {
        // Line splitting for readability
        std::cout
            << "Usage: mpags-cipher [-i/--infile <file>] [-o/--outfile <file>] [--multi-cipher <N_ciphers>] [-c/--cipher <cipher>] [-k/--key <key>] [--encrypt/--decrypt]\n\n"
            << "Encrypts/Decrypts input alphanumeric text using classical ciphers\n\n"
            << "Available options:\n\n"
            << "  -h|--help\n"
            << "                      Print this help message and exit\n\n"
            << "  -v|--version\n"
            << "                      Print version information\n\n"
            << "  -i|--infile FILE\n"
            << "                      Read text to be processed from FILE\n"
            << "                      Stdin will be used if not supplied\n\n"
            << "  -o|--outfile FILE\n"
            << "                      Write processed text to FILE\n"
            << "                      Stdout will be used if not supplied\n\n"
            << "  --multi-cipher N\n"
            << "                      Specify the number of ciphers to be used in sequence\n"
            << "                      N should be a positive integer - defaults to 1\n\n"
            << "  -c|--cipher CIPHER\n"
            << "                      Specify the cipher to be used to perform the encryption/decryption\n"
            << "                      CIPHER can be caesar, playfair or vigenere - caesar is the default\n\n"
            << "  -k|--key KEY\n"
            << "                      Specify the cipher KEY\n"
            << "                      A null key, i.e. no encryption, is used if not supplied\n\n"
            << "  --encrypt\n"
            << "                      Will use the cipher to encrypt the input text (default behaviour)\n\n"
            << "  --decrypt\n"
            << "                      Will use the cipher to decrypt the input text\n\n"
            << "  --threads N\n"
            << "                      Number of threads to use for Caesar cipher (default = hardware cores or length of input text whichever is smaller)\n\n"
            << std::endl;
        // Help requires no further action, so return from main
        // with 0 used to indicate success
        return 0;
    }

    // Handle version, if requested
    // Like help, requires no further action,
    // so return from main with zero to indicate success
    if (settings.versionRequested) {
        std::cout << "0.5.0" << std::endl;
        return 0;
    }

    // Initialise variables
    char inputChar{'x'};
    std::string cipherText;

    // Read in user input from stdin/file
    if (!settings.inputFile.empty()) {
        // Open the file and check that we can read from it
        std::ifstream inputStream{settings.inputFile};
        if (!inputStream.good()) {
            std::cerr << "[error] failed to create istream on file '"
                      << settings.inputFile << "'" << std::endl;
            return 1;
        }

        // Loop over each character from the file
        while (inputStream >> inputChar) {
            cipherText += transformChar(inputChar);
        }

    } else {
        // Loop over each character from user input
        // (until Return then CTRL-D (EOF) pressed)
        while (std::cin >> inputChar) {
            cipherText += transformChar(inputChar);
        }
    }

    /// Setting nThreads
    std::size_t nThreads = settings.nThreads;

    if(nThreads == 0){
        nThreads = std::thread::hardware_concurrency();
    }

    if(nThreads == 0){
        nThreads = 2;
    }

    nThreads = std::min(nThreads, cipherText.size());

    // Request construction of the appropriate cipher(s)
    std::vector<std::unique_ptr<Cipher>> ciphers;
    std::size_t nCiphers{settings.cipherType.size()};
    ciphers.reserve(nCiphers);
    for (std::size_t iCipher{0}; iCipher < nCiphers; ++iCipher) {
        try {
            ciphers.push_back(CipherFactory::makeCipher(
                settings.cipherType[iCipher], settings.cipherKey[iCipher]));
        } catch (const InvalidKey& e) {
            std::cerr << "[error] Invalid key: " << e.what() << std::endl;
            return 1;
        }

        // Check that the cipher was constructed successfully
        if (!ciphers.back()) {
            std::cerr << "[error] problem constructing requested cipher"
                      << std::endl;
            return 1;
        }
    }

    // If we are decrypting, we need to reverse the order of application of the ciphers
    if (settings.cipherMode == CipherMode::Decrypt) {
        std::reverse(ciphers.begin(), ciphers.end());
    }

    // Run the cipher(s) on the input text, specifying whether to encrypt/decrypt
    for (const auto& cipher : ciphers) {

        // Only parallelise Caesar
        if(settings.cipherType[0] == CipherType::Caesar){

            std::vector<std::future<std::string>> futures;
            futures.reserve(nThreads);

            std::size_t textLength = cipherText.size();
            std::size_t chunkSize = textLength / nThreads;

            for(std::size_t i = 0; i < nThreads; ++i){

                std::size_t start = i * chunkSize;

                std::size_t end;
                if(i == nThreads - 1){
                    end = textLength;
                } else {
                    end = start + chunkSize;
                }

                std::string chunk = cipherText.substr(start, end - start);
                //std::cout << chunk << std::endl; // Used for debugging

                futures.push_back(
                    std::async(std::launch::async,
                        [&cipher, &settings, chunk]()
                        {
                            return cipher->applyCipher(chunk, settings.cipherMode);
                        }
                    )
                );
            }

            // Wait for threads to finish
            for(auto& f : futures){
                f.wait();
            }

            // Combine results
            std::string result;
            result.reserve(cipherText.size());

            for(auto& f : futures){
                result += f.get();
            }

            cipherText = result;

        }
        else{
            // Non-Caesar ciphers run sequentially
            cipherText = cipher->applyCipher(cipherText, settings.cipherMode);
        }
    }

    // Output the encrypted/decrypted text to stdout/file
    if (!settings.outputFile.empty()) {
        // Open the file and check that we can write to it
        std::ofstream outputStream{settings.outputFile};
        if (!outputStream.good()) {
            std::cerr << "[error] failed to create ostream on file '"
                      << settings.outputFile << "'" << std::endl;
            return 1;
        }

        // Print the encrypted/decrypted text to the file
        outputStream << cipherText << std::endl;

    } else {
        // Print the encrypted/decrypted text to the screen
        std::cout << cipherText << std::endl;
    }

    // No requirement to return from main, but we do so for clarity
    // and for consistency with other functions
    return 0;
}
