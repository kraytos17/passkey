#include "../include/encryption.hpp"
#include "../include/utils.hpp"

#include <array>
#include <cstddef>
#include <memory>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <vector>

namespace {
    auto makeCipherContext() {
        return std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>(
                EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free);
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

EncryptionResult Encryption::encryptPassword(const std::string& password, const std::string& key) {
    constexpr size_t ivSize{AES_BLOCK_SIZE};
    constexpr size_t tagSize{16};

    std::string salt = utils::generateSalt();
    auto derivedKey = deriveKeyFromPassword(key, salt, 100000);

    std::array<u_char, ivSize> iv{};
    if (!RAND_bytes(iv.data(), ivSize)) {
        throw std::runtime_error("IV generation failed.");
    }

    auto ctx = makeCipherContext();
    if (!ctx) {
        throw std::runtime_error("Failed to create encryption context.");
    }

    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, derivedKey.data(), iv.data()) !=
        1) {
        throw std::runtime_error("Encryption initialization failed.");
    }

    std::vector<u_char> encryptedData(password.size() + AES_BLOCK_SIZE);
    int outLen{0};
    if (EVP_EncryptUpdate(ctx.get(), encryptedData.data(), &outLen,
                          reinterpret_cast<const u_char*>(password.c_str()),
                          password.size()) != 1) {
        throw std::runtime_error("Password encryption failed.");
    }

    int finalLen{0};
    if (EVP_EncryptFinal_ex(ctx.get(), encryptedData.data() + outLen, &finalLen) != 1) {
        throw std::runtime_error("Finalizing encryption failed.");
    }

    std::array<u_char, tagSize> authTag{};
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, tagSize, authTag.data()) != 1) {
        throw std::runtime_error("Failed to retrieve authentication tag.");
    }

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

    auto encryptedData = utils::hexStringToBytes(encryptedPasswordHex);
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
    auto ctx = makeCipherContext();
    if (!ctx) {
        return DecryptionResult("Failed to create decryption context.");
    }

    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, derivedKey.data(), iv.data()) !=
        1) {
        return DecryptionResult("Decryption initialization failed.");
    }

    std::vector<u_char> decryptedData(cipherText.size());
    int outLen{0};
    if (EVP_DecryptUpdate(ctx.get(), decryptedData.data(), &outLen, cipherText.data(),
                          cipherText.size()) != 1) {
        return DecryptionResult("Decryption failed.");
    }

    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, tagSize, authTag.data()) != 1) {
        return DecryptionResult("Failed to set authentication tag.");
    }

    int finalLen{0};
    if (EVP_DecryptFinal_ex(ctx.get(), decryptedData.data() + outLen, &finalLen) != 1) {
        return DecryptionResult("Authentication failed. Invalid password or corrupted data.");
    }

    decryptedData.resize(outLen + finalLen);

    return DecryptionResult(std::string(decryptedData.begin(), decryptedData.end()));
}
