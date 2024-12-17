#pragma once

#include <string>

struct HashResult {
    std::string salt;
    std::string hash;
};

class Hasher final {
public:
    static std::string generateSalt();
    static HashResult hashMasterPassword(const std::string& password, const std::string& salt,
                                         size_t iterations);

    static bool verifyMasterPassword(const std::string& password, const std::string& salt,
                                     const std::string& storedHash);
};
