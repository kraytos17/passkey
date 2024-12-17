#pragma once

#include <array>
#include <iomanip>
#include <ios>
#include <openssl/rand.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace utils {
    inline constexpr std::string generateSalt() {
        constexpr size_t saltSize{32};
        std::array<u_char, saltSize> salt{};
        if (!RAND_bytes(salt.data(), saltSize)) {
            throw std::runtime_error("Salt generation failed.");
        }
        return std::string(reinterpret_cast<char*>(salt.data()), salt.size());
    }

    inline constexpr std::string generatePassword(std::size_t length) { return ""; }

    inline std::vector<u_char> hexStringToBytes(const std::string& hexString) {
        std::vector<u_char> bytes;
        bytes.reserve(hexString.length() / 2);

        for (size_t i{0}; i < hexString.length(); i += 2) {
            auto byte = static_cast<u_char>(std::stoi(hexString.substr(i, 2), nullptr, 16));
            bytes.push_back(byte);
        }
        return bytes;
    }

    inline std::string bytesToHexString(const std::vector<u_char>& bytes) {
        std::ostringstream oss;
        for (const auto& byte: bytes) {
            oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }
        return oss.str();
    }
} // namespace utils
