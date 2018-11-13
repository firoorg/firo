#ifndef AUTHHELPER_H
#define AUTHHELPER_H

/**
 * Generates and manages one-time authorization keys
 * for sensitive
 */
class AuthorizationHelper {
public:
    static AuthorizationHelper & inst();

    bool authorize(std::string const & function_name, std::string const & auth_code);
    std::string generateAuthorizationCode(std::string const & function_name);
private:
    AuthorizationHelper();
    ~AuthorizationHelper();
    AuthorizationHelper(const AuthorizationHelper&) = delete;
    AuthorizationHelper& operator=(const AuthorizationHelper&) = delete;

    struct Impl;
    Impl & pImpl;
};

#endif /* AUTHHELPER_H */

