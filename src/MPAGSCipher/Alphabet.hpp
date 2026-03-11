#ifndef MPAGSCIPHER_ALPHABET_HPP
#define MPAGSCIPHER_ALPHABET_HPP

#include <string_view>

/**
 * \file Alphabet.hpp
 * \brief Contains the declaration of the Alphabet namespace, which holds various commonly used constants
 */

/**
 * \namespace Alphabet
 * \brief Namespace to hold alphabet-related constants
 */
namespace Alphabet {
    /// The alphabet
    constexpr std::string_view alphabet{"ABCDEFGHIJKLMNOPQRSTUVWXYZ"};

    /// The size of the alphabet
    constexpr std::size_t size{alphabet.size()};
}    // namespace Alphabet

#endif    // MPAGSCIPHER_ALPHABET_HPP