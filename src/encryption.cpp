#include "../include/encryption.hpp"

#include <array>
#include <cstddef>
#include <iomanip>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sstream>
#include <vector>

namespace {
    std::vector<u_char> hexStringToBytes(const std::string& hexString) {
        std::vector<u_char> bytes;
        bytes.reserve(hexString.length() / 2);

        for (size_t i{0}; i < hexString.length(); i += 2) {
            auto byte = static_cast<u_char>(std::stoi(hexString.substr(i, 2), nullptr, 16));
            bytes.push_back(byte);
        }
        return bytes;
    }

    std::string bytesToHexString(const std::vector<u_char>& bytes) {
        std::ostringstream oss;
        for (const auto& byte: bytes) {
            oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }
        return oss.str();
    }
} // namespace

std::array<u_char, 32> Encryption::deriveKeyFromPassword(const std::string& password,
                                                         const std::string& salt, int iterations) {
    std::array<u_char, 32> derivedKey{};
    if (PKCS5_PBKDF2_HMAC(password.c_str(), password.size(),
                          reinterpret_cast<const u_char*>(salt.c_str()), salt.size(), iterations,
                          EVP_sha256(), derivedKey.size(), derivedKey.data()) != 1) {
        throw std::runtime_error("Key derivation failed.");
    }
    return derivedKey;
}

std::string Encryption::generateSalt() {
    constexpr size_t saltSize{32};
    std::array<u_char, saltSize> salt{};
    if (!RAND_bytes(salt.data(), saltSize)) {
        throw std::runtime_error("Salt generation failed.");
    }
    return std::string(reinterpret_cast<char*>(salt.data()), salt.size());
}

EncryptionResult Encryption::encryptPassword(const std::string& password, const std::string& key) {
    constexpr size_t ivSize{AES_BLOCK_SIZE};
    constexpr size_t tagSize{16};

    std::string salt = generateSalt();
    auto derivedKey = deriveKeyFromPassword(key, salt, 100000);

    std::array<u_char, ivSize> iv{};
    if (!RAND_bytes(iv.data(), ivSize)) {
        throw std::runtime_error("IV generation failed.");
    }

    auto* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create encryption context.");
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, derivedKey.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Encryption initialization failed.");
    }

    std::vector<u_char> encryptedData(password.size() + AES_BLOCK_SIZE);
    int outLen{0};
    if (EVP_EncryptUpdate(ctx, encryptedData.data(), &outLen,
                          reinterpret_cast<const u_char*>(password.c_str()),
                          password.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Password encryption failed.");
    }

    int finalLen{0};
    if (EVP_EncryptFinal_ex(ctx, encryptedData.data() + outLen, &finalLen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Finalizing encryption failed.");
    }

    std::array<u_char, tagSize> authTag{};
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tagSize, authTag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to retrieve authentication tag.");
    }

    EVP_CIPHER_CTX_free(ctx);
    encryptedData.resize(outLen + finalLen);

    return EncryptionResult{std::move(encryptedData), std::vector<u_char>(salt.begin(), salt.end()),
                            std::vector<u_char>(iv.begin(), iv.end()),
                            std::vector<u_char>(authTag.begin(), authTag.end())};
}

DecryptionResult Encryption::decryptPassword(const std::string& encryptedPasswordHex,
                                             const std::string& key) {
    constexpr size_t saltSize{32};
    constexpr size_t ivSize{AES_BLOCK_SIZE};
    constexpr size_t tagSize{16};

    auto encryptedData = hexStringToBytes(encryptedPasswordHex);
    if (encryptedData.size() < saltSize + ivSize + tagSize) {
        return DecryptionResult("Encrypted data too short.");
    }

    std::vector<u_char> salt(encryptedData.begin(), encryptedData.begin() + saltSize);
    std::vector<u_char> iv(encryptedData.begin() + saltSize,
                           encryptedData.begin() + saltSize + ivSize);
    std::vector<u_char> authTag(encryptedData.begin() + saltSize + ivSize,
                                encryptedData.begin() + saltSize + ivSize + tagSize);
    std::vector<u_char> cipherText(encryptedData.begin() + saltSize + ivSize + tagSize,
                                   encryptedData.end());

    auto derivedKey = deriveKeyFromPassword(key, std::string(salt.begin(), salt.end()), 100000);

    auto* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return DecryptionResult("Failed to create decryption context.");
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, derivedKey.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return DecryptionResult("Decryption initialization failed.");
    }

    std::vector<u_char> decryptedData(cipherText.size());
    int outLen{0};
    if (EVP_DecryptUpdate(ctx, decryptedData.data(), &outLen, cipherText.data(),
                          cipherText.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return DecryptionResult("Decryption failed.");
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tagSize, authTag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return DecryptionResult("Failed to set authentication tag.");
    }

    int finalLen{0};
    if (EVP_DecryptFinal_ex(ctx, decryptedData.data() + outLen, &finalLen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return DecryptionResult("Authentication failed. Invalid password or corrupted data.");
    }

    EVP_CIPHER_CTX_free(ctx);
    decryptedData.resize(outLen + finalLen);

    return DecryptionResult(std::string(decryptedData.begin(), decryptedData.end()));
}
