#pragma once

#include <string>

class PasswordManager {
public:
    constexpr PasswordManager() = default;

    void storePassword(const std::string& service, const std::string& password);
    std::string generateAndStorePassword(const std::string& service, std::size_t len);
    bool verifyMasterPassword(const std::string& masterPassword);
};
