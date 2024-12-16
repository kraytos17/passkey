#pragma once

#include <cstddef>
#include <string>

class PasswordGen {
public:
    std::string GeneratePassword(std::size_t length);
};
