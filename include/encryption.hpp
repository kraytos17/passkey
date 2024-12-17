#pragma once

#include <string>
#include <sys/types.h>

#include "results.hpp"

class Encryption final {
public:
    static EncryptionResult encryptPassword(const std::string& password, const std::string& key);
    static DecryptionResult decryptPassword(const std::string& encryptedPassword,
                                            const std::string& key);

    static std::array<u_char, 32> deriveKeyFromPassword(const std::string& password,
                                                        const std::string& salt, int iterations);
};
