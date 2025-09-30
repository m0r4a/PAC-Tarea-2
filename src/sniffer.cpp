#include "include/sniffer.h"
#include <iostream>
#include <netinet/ip.h>
#include <atomic>

Sniffer::Sniffer(const std::string& iface, const std::string& ip, int port)
    : interface(iface), target_ip(ip), target_port(port), packet_found(false) {}

void Sniffer::print_header_bytes(const u_char* data, int size) {
    for (int i = 0; i < size; ++i) {
        printf("%02x ", data[i]);
    }
    printf("\n");
}

// pcap llama a esta función automáticamente por cada paquete que capture
// tiene que ser estática porque pcap es de C y no usa objetos
 
void Sniffer::packet_handler(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    // Se necesita convertir el ptr "user_data" en un objeto Sniffer para usarlo
    Sniffer* sniffer = reinterpret_cast<Sniffer*>(user_data);

    if (sniffer->packet_found) {
        return;
    }
    sniffer->packet_found = true;

    std::cout << "Response trace captured, with a lenght of " << pkthdr->caplen << " bytes" << std::endl;

    if (sniffer->scan_protocol == Protocol::TCP) {
        std::cout << "First 16 bytes of the header: ";
        sniffer->print_header_bytes(packet, 16);
    } else {
        // Analizamos la cabecera IP para ver si es ICMP (cerrado) o UDP (abierto)
        // Ahora hay que revisar la cabecera, si es ICMP significa que el puerto está cerrado y si es UDP está abierto

        // Aparentemente las cabeceras son de longitudes diferentes dependiendo si es ethernet o no, como no le quiero
        // agregar muchísima complejidad sólo asumiré que es por ethernet estableciendo una longitud de 14 bytes
        const struct ip* ip_header = (const struct ip*)(packet + 14);

        if (ip_header->ip_p == IPPROTO_ICMP) {
            std::cout << "Received an ICMP packet -> the port " << sniffer->target_port << " it's closed" << std::endl;
        } else if (ip_header->ip_p == IPPROTO_UDP) {
            std::cout << "Received a UDP packet -> the port " << sniffer->target_port << " it's open" << std::endl;
        }
        
        std::cout << "First 16 bytes of the header: ";
        sniffer->print_header_bytes(packet, 16);
    }
}

void Sniffer::start(Protocol protocol, std::atomic<bool>& stop_signal) {
    this->scan_protocol = protocol;
    this->packet_found = false;

    std::string filter_exp;

    if (protocol == Protocol::TCP) {
        std::cout << "\nStarting the sniffing on " << interface << std::endl;
        // Aquí se aplica el filtro BPF para TCP
        filter_exp = "src host " + target_ip + " and src port " + std::to_string(target_port);
    } else {
        std::cout << "\nStarting the UDP sniffing on " << interface << std::endl;
        // Aquí se aplica el filtro BPF para UDP, se captura una respuesta de UDP o un error ICMP
        filter_exp = "(udp and src host " + target_ip + " and src port " + std::to_string(target_port) + ") or (icmp and src host " + target_ip + ")";
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    // este timeout es muy bajo porque el control del tiempo lo lleva el loop
    pcap_t* handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        std::cerr << "Couldn't open the interface: " << interface << ": " << errbuf << std::endl;
        return;
    }

    // Ahora sí, modo no bloqueante
    pcap_setnonblock(handle, 1, errbuf);

    std::cout << "Applying BPF filter: \"" << filter_exp << "\"" << std::endl;
    
    // Mucho texto copiado de un foro
    bpf_program fp;
    if (pcap_compile(handle, &fp, filter_exp.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "Couldn't compile the BPF filter: " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        return;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "Couldn't apply the BPF filter: " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        return;
    }
    
    // Y este es el bucle de captura, mientras que main no diga que stop_signl y mientras
    // no se haya encontrado un paquete continua
    while (!stop_signal.load() && !this->packet_found) {
        pcap_dispatch(handle, -1, packet_handler, reinterpret_cast<u_char*>(this));
    }
    
    pcap_freecode(&fp);
    pcap_close(handle);

    // Si es bucle terminó es porque main nos paró y no pudimos encontrar un paquete
    if (!this->packet_found) {
        if (protocol == Protocol::TCP) {
            std::cout << "Couldn't capture a reply" << std::endl;
        } else {
            // Aparentemente si tienes un timeout de UDP significa que el puerto está abierto o filtrado
            std::cout << "Couldn't capture a reply (timeout) -> The port " << target_port << " it's open or filtered" << std::endl;
        }
    }
}
