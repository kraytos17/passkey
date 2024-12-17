#include <format>
#include <openssl/aes.h>
#include <string>
#include <sys/types.h>

#include "../include/results.hpp"
#include "../include/utils.hpp"

std::string EncryptionResult::encodeEncryptionResult(const EncryptionResult& result) {
    return std::format("{}{}{}{}", utils::bytesToHexString(result.salt),
                       utils::bytesToHexString(result.iv), utils::bytesToHexString(result.authTag),
                       utils::bytesToHexString(result.encryptedData));
}

EncryptionResult EncryptionResult::decodeEncryptionResult(const std::string& encodedString) {
    constexpr size_t saltSize{32}, ivSize{AES_BLOCK_SIZE}, tagSize{16};

    auto encryptedData = utils::hexStringToBytes(encodedString);
    return EncryptionResult{
            std::vector<u_char>(encryptedData.begin() + saltSize + ivSize + tagSize,
                                encryptedData.end()),
            std::vector<u_char>(encryptedData.begin(), encryptedData.begin() + saltSize),
            std::vector<u_char>(encryptedData.begin() + saltSize,
                                encryptedData.begin() + saltSize + ivSize),
            std::vector<u_char>(encryptedData.begin() + saltSize + ivSize,
                                encryptedData.begin() + saltSize + ivSize + tagSize)};
}
