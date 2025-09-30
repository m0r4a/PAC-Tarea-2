#include "include/escaneo.h"
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <sys/select.h>

Scanner::Scanner(const std::string& ip, int timeout)
    : target_ip(ip), timeout_ms(timeout) {}

PortStatus Scanner::scanTCP(int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return PortStatus::UNKNOWN;

    // aquí es donde se configura el socket creado en modo no bloquente para que cuando se
    // use connect() no se quede esperando
    fcntl(sock, F_SETFL, O_NONBLOCK);

    sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port); // Usa el puerto del argumento
    inet_pton(AF_INET, target_ip.c_str(), &server_addr.sin_addr);

    // esto es lo que hace el handshake TCP, como es no bloqueande retonra inmediatamente
    // usualmente con error EINPROGRESS
    connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr));

    fd_set fdset;
    FD_ZERO(&fdset);
    FD_SET(sock, &fdset);

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    // select() monitorea el descriptor de archivo para ver si el estado cambió
    // Se espera a que el socket se haga "writeable" lo que significa que el handshake terminó
    // ya sea con error o no
    if (select(sock + 1, NULL, &fdset, NULL, &tv) == 1) {
        int so_error;
        socklen_t len = sizeof(so_error);
        // ya que se terminó el handshake consulta el socket para ver qué pasó
        getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
        close(sock);
        // Si retorna error 0 entonces sí hubo conexión y el puerto está abierto, si no,
        // entonces está cerrado
        return (so_error == 0) ? PortStatus::OPEN : PortStatus::CLOSED;
    }

    // Si select() expira (timeout) entonces no hubo respuesta.
    // El puerto se asume como filtrado.
    close(sock);
    return PortStatus::FILTERED;
}

bool Scanner::sendUDPProbe(int port) {
    // con UDP se usa SOCK_DGRAM (datagramas sin conexión)
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("Error al crear socket UDP");
        return false;
    }

    sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    inet_pton(AF_INET, target_ip.c_str(), &server_addr.sin_addr);

    // Un payload de 0 bytes es suficiente para generar una respuesta ICMP si el puerto está cerrado

    // Mandar algo vacío al menos en m testeo causa que el servidor/puerto no sepa que responder
    // y como uso la respuesta del servidor para basarme en si está abierto o no causa que aparezca como
    // cerrado auque esté abierto
    char payload[] = "";
    
    // Esto valida que el SO acepta el paquete para transmitirlo pero no confirma si llegó
    // así que sirve para errores locales como permisos o así
    if (sendto(sock, payload, 0, 0, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Error en sendto() al enviar paquete UDP");
        close(sock);
        return false;
    }
    
    close(sock);
     // Retorna true si el paquete se puso en cola para que el SO lo mande
    return true;
}
