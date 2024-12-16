#pragma once

#include <string>

struct HashingResult {
    std::string salt;
    std::string hash;
};

class Hashing {
public:
    std::string generateSalt() const;
    HashingResult hashMasterPassword(const std::string& password, const std::string& salt,
                                     size_t iterations) const;

    bool verifyMasterPassword(const std::string& password, const std::string& salt,
                              const std::string& storedHash) const;
};
