#pragma once

#include <string>
#include <sys/types.h>

#include "results.hpp"

class Encryption {
public:
    EncryptionResult encryptPassword(const std::string& password, const std::string& key);
    DecryptionResult decryptPassword(const std::string& encryptedPassword, const std::string& key);
    std::array<u_char, 32> deriveKeyFromPassword(const std::string& password,
                                                 const std::string& salt, int iterations);

    std::string generateSalt();
};
