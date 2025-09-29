#include "./include/escaneo.h"
#include <iostream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

Scanner::Scanner(const std::string& ip, int port) : target_ip(ip), target_port(port) {}

bool Scanner::scanTCP() {
    std::cout << "Starting the TCP scan..." << std::endl;
    std::cout << "Target: " << target_ip << ":" << target_port << std::endl;

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        std::cerr << "Couldn't create the socket" << std::endl;
        return false;
    }

    sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(target_port);

    if (inet_pton(AF_INET, target_ip.c_str(), &server_addr.sin_addr) <= 0) {
        std::cerr << "Invalid IP" << std::endl;
        close(sock);
        return false;
    }

    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cout << "The port " << target_port << " it's closed or filtered" << std::endl;
        std::cerr << "Reason: " << strerror(errno) << std::endl;
        close(sock);
        return false;
    }

    std::cout << "The port " << target_port << " it's open" << std::endl;
    close(sock);
    return true;
}

bool Scanner::scanUDP() {
    std::cout << "Starting the UDP scan..." << std::endl;
    std::cout << "Target: " << target_ip << ":" << target_port << std::endl;

    // NOTE: Aquí se abre un socket igual pero en lugar de SOCK_STEAM, se usa SOCK_DGRAM
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        std::cerr << "Couldn't create the socket" << std::endl;
        return false;
    }

    sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(target_port);

    if (inet_pton(AF_INET, target_ip.c_str(), &server_addr.sin_addr) <= 0) {
        std::cerr << "Invalid IP" << std::endl;
        close(sock);
        return false;
    }

    // Se envia un "datagrama" vacío para ver si responde
    char payload[] = "";
    if (sendto(sock, payload, sizeof(payload), 0, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "Error sending UDP packet: " << strerror(errno) << std::endl;
        close(sock);
        return false;
    }

    std::cout << "UDP probe packet sent. The sniffer will now listen for a reply" << std::endl;
    close(sock);
    return true;
}
