#include "include/sniffer.h"
#include <iostream>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <algorithm>

// Esto es lo que se usa para pasarle datos a la función de pcap
// solo acepta un puntero genérico u_char*
struct PcapUserData {
    // Promesa para comunicar el resultado de vuelta del hilo que inició el sniffer
    std::promise<SnifferResult> result_promise;

    // flag ATOOOOMICO para asegurarse que solo el primer paquete relevante sea procesado
    // es muy importante para evitar race conditions y varias llamas a set_value()
    std::atomic<bool> packet_found_flag{false};

    // Desplazamiento en bytes para saltar el header de la capa de enlace (eth o lo)
    int link_layer_offset;

    // pointer a la instancia del Sniffer para poder usar sus métodos (stop())
    Sniffer* sniffer_instance;
};

Sniffer::Sniffer(const std::string& iface, const std::string& ip, int port)
    : interface(iface), target_ip(ip), target_port(port), handle(nullptr) {}

Sniffer::~Sniffer() {
    // La liberación del handle de pcap se hace explícitamente con start() para
    // asegurarse que se cierre tan pronto como la captura termine
}

// Detener de forma segura el bucle de captura de pcap desde otro hilo
void Sniffer::stop() {
    if (handle) {
        pcap_breakloop(handle);
    }
}

// Función de callback estática que pcap usa para cada paquete
void Sniffer::packet_handler(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    // Transforma el puntero genérico de nuevo a la estructura de datos
    auto* pcap_data = reinterpret_cast<PcapUserData*>(user_data);
    
    // Calcula la posición del encabezado IP saltando a la capa de enlace
    const struct ip* ip_header = (const struct ip*)(packet + pcap_data->link_layer_offset);
    int ip_header_len = ip_header->ip_hl * 4;
    
    // Esto es el pre-filtrado paca ICMP
    // Un paquete ICMP tiene el header IP/UDP oliginal que lo causó
    // así que se verifica que ese headel corresponde a el sondeo UDP que se hizo
    if (ip_header->ip_p == IPPROTO_ICMP) {
        const auto* icmp_header = (struct icmp*)((u_char*)ip_header + ip_header_len);
        if (icmp_header->icmp_type == ICMP_UNREACH && icmp_header->icmp_code == ICMP_UNREACH_PORT) {
            // "Desempaqueta" el header IP y UDP originales del payload ICMP
            const struct ip* orig_ip = (const struct ip*)((u_char*)icmp_header + 8);
            int orig_ip_len = orig_ip->ip_hl * 4;
            const struct udphdr* orig_udp = (const struct udphdr*)((u_char*)orig_ip + orig_ip_len);
            
            // Si el puerto de destino original NO es el que se está escaneando, se ignora el paquete
            if (ntohs(orig_udp->uh_dport) != pcap_data->sniffer_instance->target_port) {
                return;
            }
        }
    }
    
    // Se usa compare_exchange para asegurarse que 1 solo hilo (idealmente solo debería haber 1 hilo
    // llamando este handler) pueda procesar el primer paquete
    // Si packet_found_flag ya es true entonces la función retorna y ya
    bool expected_false = false;
    if (!pcap_data->packet_found_flag.compare_exchange_strong(expected_false, true)) return;

    SnifferResult result;
    result.packet_found = true;

    // Esto copia los primeros bytes del header
    int bytes_to_copy = std::min((int)pkthdr->len - pcap_data->link_layer_offset, 16);
    if (bytes_to_copy > 0) {
        result.header_bytes.assign((const u_char*)ip_header, (const u_char*)ip_header + bytes_to_copy);
    }

    // Esta función determina el estado del puerto basado en el protocolo y las flags del paquete de respuesta
    switch (ip_header->ip_p) {
        case IPPROTO_TCP: {
            const struct tcphdr* tcp_header = (const struct tcphdr*)((u_char*)ip_header + ip_header_len);
            if (tcp_header->rst) { // Un pacuete RST significa que está cerrado
                result.status = PortStatus::CLOSED;
            } else if (tcp_header->syn && tcp_header->ack) { // SYN/ACk significa abierto
                result.status = PortStatus::OPEN;
            } else if (tcp_header->ack) { // Un ACK sin SYN puede ser varias cosas, pero diremos que abierto xd
                result.status = PortStatus::OPEN;
            } else {
                result.status = PortStatus::UNKNOWN;
            }
            break;
        }
        case IPPROTO_UDP:
            // CUALQUIER respuesta UDP válida significa que está abierto, ya que si estuviera cerrado solo mandaría un ICMP
            result.status = PortStatus::OPEN;
            break;
        case IPPROTO_ICMP: {
            const auto* icmp_header = (struct icmp*)((u_char*)ip_header + ip_header_len);
            // Si recibes un Port Unreachable es literalmente "puerto cerrado"
            if (icmp_header->icmp_type == ICMP_UNREACH && icmp_header->icmp_code == ICMP_UNREACH_PORT) {
                result.status = PortStatus::CLOSED;
            } else {
                result.status = PortStatus::UNKNOWN;
            }
            break;
        }
        default:
            result.status = PortStatus::UNKNOWN;
            break;
    }
    
    // Mandas el resultado al hilo principal usando la promise
    pcap_data->result_promise.set_value(std::move(result));
    
    // Ya teniendo el resultado le decimos a pcap que deje de capturar
    // es un punto clave ya que no queremos procesar paquetes innecesarios
    if (pcap_data->sniffer_instance) {
        pcap_data->sniffer_instance->stop();
    }
}

// Esto configura e inicia el bucle de pcap
void Sniffer::start(Protocol protocol, std::promise<SnifferResult> result_promise) {
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 500, errbuf);
    if (!handle) {
        result_promise.set_value(SnifferResult{}); // Avisa del fallo si no se puede abrir la interfaz
        return;
    }

    // En lugar de asumir un tamaño fijo (14 para eth), le preguntas a pcap el tipo de enlace, esto hace
    // que el sniffer sea más portable para eth, wifi, lo
    int link_layer_offset;
    int link_type = pcap_datalink(handle);
    if (link_type == DLT_EN10MB) {
        link_layer_offset = 14; // Ethernet
    } else if (link_type == DLT_NULL || link_type == DLT_LOOP) {
        link_layer_offset = 4;  // Loopback / Null
    } else {
        std::cerr << "Link-layer type no reconocido (" << link_type << "). Asumiendo 14 bytes." << std::endl;
        link_layer_offset = 14; // Un valor por defecto
    }
    
    // El filtro BPF se compila y se pasa al kernel lo que permite descartar paquetes indeseados a muy bajo nivel.
    // esto hace que tenga menos carga de CPU
    std::string filter_exp;
    if (protocol == Protocol::TCP) {
        // Para TCP solo importan los paquetes que vengan del puerto y host DESTINO
        filter_exp = "src host " + target_ip + " and src port " + std::to_string(target_port);
    } else {
        // Para UDP, quieres una respuesta UDP directa o un mensaje ICMP del host DESTINO
        filter_exp = "(udp and src host " + target_ip + " and src port " + std::to_string(target_port) + ") or "
                     "(icmp and icmp[0] == 3 and icmp[1] == 3 and src host " + target_ip + ")";
    }

    bpf_program fp;

    // Compilar y aplicar el filtro a la sesión de captura
    if (pcap_compile(handle, &fp, filter_exp.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) { pcap_close(handle); handle = nullptr; result_promise.set_value(SnifferResult{}); return; }
    if (pcap_setfilter(handle, &fp) == -1) { pcap_freecode(&fp); pcap_close(handle); handle = nullptr; result_promise.set_value(SnifferResult{}); return; }
    pcap_freecode(&fp); // Ya no se necesita el filtro despues de pcap_setfilter
    
    PcapUserData pcap_data;
    pcap_data.result_promise = std::move(result_promise);
    pcap_data.link_layer_offset = link_layer_offset;
    pcap_data.sniffer_instance = this;

    // Este es el bucle de captura, sí es una llamada bloqueante que solo retorna cuando
    // se llama a pcap_breakloop() o hay error. -1 es captura indefinidamente
    pcap_loop(handle, -1, packet_handler, reinterpret_cast<u_char*>(&pcap_data));
    
    pcap_close(handle);
    handle = nullptr;

    // Si pcap_loop termina sin haber encontrado un paquete (como un timeout del hilo main)
    // te aseguras de resolver la promise para que el otro hilo no se bloquee infinitamente
    if (!pcap_data.packet_found_flag.load()) {
        try { pcap_data.result_promise.set_value(SnifferResult{}); } catch (...) {}
    }
}
