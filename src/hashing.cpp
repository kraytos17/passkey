#include "../include/hashing.hpp"

#include <array>
#include <cstddef>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sstream>
#include <stdexcept>
#include <string>

std::string Hashing::generateSalt() const {
    constexpr size_t saltSize{32};
    std::array<u_char, saltSize> salt{};
    if (!RAND_bytes(salt.data(), saltSize)) {
        throw std::runtime_error("Salt generation failed.");
    }

    std::ostringstream oss;
    for (const auto& byte: salt) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }

    return oss.str();
}

HashingResult Hashing::hashMasterPassword(const std::string& password, const std::string& salt,
                                          size_t iterations = 100000) const {
    constexpr size_t keySize{32};
    std::array<u_char, keySize> derivedKey{};

    if (PKCS5_PBKDF2_HMAC(password.c_str(), password.size(),
                          reinterpret_cast<const u_char*>(salt.c_str()), salt.size(), iterations,
                          EVP_sha256(), derivedKey.size(), derivedKey.data()) != 1) {
        throw std::runtime_error("Key derivation failed.");
    }

    std::ostringstream oss;
    for (const auto& byte: derivedKey) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }

    return HashingResult{salt, oss.str()};
}

bool Hashing::verifyMasterPassword(const std::string& password, const std::string& salt,
                                   const std::string& storedHash) const {
    auto computedResult = hashMasterPassword(password, salt);
    return computedResult.hash == storedHash;
}
