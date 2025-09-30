#ifndef COMMON_H
#define COMMON_H

#include <string>
#include <vector>

enum class Protocol { TCP, UDP };

enum class PortStatus { 
    OPEN, 
    CLOSED, 
    FILTERED,
    OPEN_FILTERED,
    UNKNOWN 
};

struct ScanResult {
    int port = 0;
    Protocol protocol = Protocol::TCP;
    PortStatus status = PortStatus::UNKNOWN;
    std::string service = "unknown";
    std::vector<unsigned char> header_bytes;
};

#endif
