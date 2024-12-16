#pragma once

#include <string>

class Storage {
public:
    void SavePassword(const std::string& service, const std::string& encryptedPassword);
    void LoadPasswords();
};
