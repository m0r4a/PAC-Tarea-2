#ifndef SNIFFER_H
#define SNIFFER_H

#include <string>
#include <pcap.h>

class Sniffer {
public:
    Sniffer(const std::string& interface, const std::string& ip, int port);
    void startTCP();
    // void startUDP(); esto es para al rato

private:
    void print_header_bytes(const u_char* data, int size);
    std::string interface;
    std::string target_ip;
    int target_port;
};

#endif
