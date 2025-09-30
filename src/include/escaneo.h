#ifndef ESCANEO_H
#define ESCANEO_H

#include <string>
#include "common.h"

class Scanner {
public:
    Scanner(const std::string& ip, int timeout_ms);

    PortStatus scanTCP(int port);

    bool sendUDPProbe(int port);

private:
    std::string target_ip;
    int timeout_ms;
};

#endif
