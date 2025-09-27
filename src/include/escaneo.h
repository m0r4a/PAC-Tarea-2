#ifndef ESCANEO_H
#define ESCANEO_H

#include <string>

class Scanner {
public:
    Scanner(const std::string& ip, int port);
    bool scanTCP();

private:
    std::string target_ip;
    int target_port;
};

#endif
