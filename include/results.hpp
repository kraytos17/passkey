#pragma once

#include <optional>
#include <string>
#include <sys/types.h>
#include <vector>

struct EncryptionResult {
    std::vector<u_char> encryptedData;
    std::vector<u_char> salt;
    std::vector<u_char> iv;
    std::vector<u_char> authTag;

    EncryptionResult(std::vector<u_char> data, std::vector<u_char> s, std::vector<u_char> i,
                     std::vector<u_char> tag) :
        encryptedData(std::move(data)),
        salt(std::move(s)),
        iv(std::move(i)),
        authTag(std::move(tag)) {}
};

struct DecryptionResult {
    std::optional<std::string> decryptedData;
    bool success{};
    std::string errorMessage;

    DecryptionResult(std::string data) :
        decryptedData(std::move(data)), success(true), errorMessage("") {}

    DecryptionResult(const char* error) :
        decryptedData(std::nullopt), success(false), errorMessage(error) {}
};
