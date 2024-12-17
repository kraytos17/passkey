#include <optional>
#include <string>

class Storage {
public:
    void saveOrUpdatePassword(const std::string& service, const std::string& encryptedPassword);
    void loadPasswords();
    std::optional<std::string> retrievePassword(const std::string& service);
    bool deletePassword(const std::string& service);
};
