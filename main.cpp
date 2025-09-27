#include <iostream>
#include <string>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pcap.h>

// simple config
const char* TARGET_IP = "127.0.0.1";
const int TARGET_PORT = 80;
const char* INTERFACE = "lo";

void print_header_bytes(const u_char* data, int size) {
    for (int i = 0; i < size; ++i) {
        printf("%02x ", data[i]);
    }
    printf("\n");
}

int main() {
    std::cout << "Starting the TCP scan..." << std::endl;
    std::cout << "Target: " << TARGET_IP << ":" << TARGET_PORT << std::endl;

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        std::cerr << "Couldn't create the socket" << std::endl;
        return 1;
    }

    sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(TARGET_PORT);

    if (inet_pton(AF_INET, TARGET_IP, &server_addr.sin_addr) <= 0) {
        std::cerr << "Invalid IP" << std::endl;
        close(sock);
        return 1;
    }

    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cout << "The port " << TARGET_PORT << " it's closed or filtered" << std::endl;
        std::cerr << "Reason: " << strerror(errno) << std::endl;
        close(sock);
        return 0;
    }

    std::cout << "The port " << TARGET_PORT << " it's open" << std::endl;

    close(sock); // Resaltar esto


    std::cout << "Starting the sniffing on " << INTERFACE << std::endl;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(INTERFACE, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Couldn't open the interface: " << INTERFACE << ": " << errbuf << std::endl;
        return 1;
    }

    // solo importan los paquetes que tengan de source la IP y Puerto objetivo
    std::string filter_exp = "src host " + std::string(TARGET_IP) + " and src port " + std::to_string(TARGET_PORT);
    std::cout << "Applying BPF filter: \"" << filter_exp << "\"" << std::endl;

    bpf_program fp;
    if (pcap_compile(handle, &fp, filter_exp.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "Couldn't compile the BPF filter: " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        return 1;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "Couldn't apply the BPF filter: " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        return 1;
    }

    // Captura el siguiente paquete que coincida con el filtro
    pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);

    if (res > 0) {
        std::cout << "Response trace captured, with a lenght of " << header->caplen << " bytes" << std::endl;
        std::cout << "First 16 bytes of the header: ";
        print_header_bytes(packet, 16);
    } else if (res == 0) {
        std::cout << "Couldn't capture a reply" << std::endl;
    } else {
        std::cerr << "Error capturing the packet: " << pcap_geterr(handle) << std::endl;
    }

    pcap_freecode(&fp);
    pcap_close(handle);

    return 0;
}
