#include "escaneo.h"
#include <iostream>
#include <chrono>
#include <map>
#include <regex>
#include <thread>
#include <future>
#include <vector>
#include <algorithm>
#include <fcntl.h> // esta creo que puede ser opcional
#include <cstring>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  typedef SOCKET socket_t;
  #define CLOSESOCKET closesocket
#else
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <unistd.h>
  #include <fcntl.h>
  #include <errno.h>
  typedef int socket_t;
  #define INVALID_SOCKET (-1)
  #define SOCKET_ERROR   (-1)
  #define CLOSESOCKET close
#endif

/**
 * Mapa de servicios comunes con puertos conocidos.
 * Permite mostrar nombre del servicio segun el puerto.
 */
static std::map<int, std::string> serviciosComunes = {
    {20, "FTP Data"}, {21, "FTP Control"}, {22, "SSH"}, {23, "Telnet"},
    {25, "SMTP"}, {53, "DNS"}, {67, "DHCP Server"}, {68, "DHCP Client"},
    {69, "TFTP"}, {80, "HTTP"}, {110, "POP3"}, {123, "NTP"},
    {135, "RPC"}, {139, "NetBIOS"}, {143, "IMAP"}, {161, "SNMP"},
    {389, "LDAP"}, {443, "HTTPS"}, {445, "SMB"}, {993, "IMAPS"},
    {995, "POP3S"}, {1433, "MSSQL"}, {1521, "Oracle"}, {3306, "MySQL"},
    {3389, "RDP"}, {5432, "PostgreSQL"}, {5900, "VNC"}, {6379, "Redis"},
    {8080, "HTTP-Alt"}, {8443, "HTTPS-Alt"}, {9200, "Elasticsearch"}
};

#ifdef _WIN32
/**
 * Implementacion a windows
 * Inicializa Winsock en Windows.
 * Debe llamarse antes de usar cualquier función de sockets.
 * Lanza una excepción si la inicialización falla.
 */
void Escaneo::inicializarWinsock() {
    WSADATA wsaData;
    int resultado = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (resultado != 0) {
        throw std::runtime_error("Error al inicializar Winsock: " + std::to_string(resultado));
    }
}

/**
 * Limpia Winsock en Windows.
 * Debe llamarse al final del uso de sockets para liberar recursos.
 */
void Escaneo::limpiarWinsock() {
    WSACleanup();
}
#else

/**
 * En Linux/Unix no se requiere inicialización de sockets,
 * pero se mantienen las funciones para compatibilidad cross-platform.
 */
void Escaneo::inicializarWinsock() {
    // No es necesario en Linux/Unix
}

/**
 * En Linux/Unix no se requiere limpieza de sockets,
 * pero se mantiene para compatibilidad cross-platform.
 */
void Escaneo::limpiarWinsock() {
    // No es necesario en Linux/Unix
}
#endif


/**
 * Valida si una cadena es una dirección IPv4 válida.
 * Utiliza expresiones regulares para comprobar el formato.
 * parametro: ip Dirección IP en formato string.
 * return: true si la IP es válida, false en caso contrario.
 */
bool Escaneo::validarIP(const std::string& ip) {
    std::regex ipRegex(
        R"(^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$)"
    );
    return std::regex_match(ip, ipRegex);
}

/**
 * Obtiene el nombre del servicio asociado a un puerto.
 * Si el puerto no está en la lista común, se clasifica según su rango:
 * - <1024: Sistema/Privilegiado
 * - 1024-49151: Registrado
 * - >=49152: Dinámico/Privado
 * @param puerto Número de puerto
 * @return Nombre del servicio como string
 */
std::string Escaneo::obtenerServicio(int puerto) {
    auto it = serviciosComunes.find(puerto);
    if (it != serviciosComunes.end()) return it->second;
    if (puerto < 1024) return "Sistema/Privilegiado";
    if (puerto < 49152) return "Registrado";
    return "Dinámico/Privado";
}

/**
 * Verifica si un puerto está abierto, cerrado o filtrado.
 * Se mide el tiempo de respuesta en milisegundos.
 * Utiliza sockets TCP y modo no bloqueante con timeout.
 * @param ip Dirección IP del host objetivo
 * @param puerto Número de puerto a verificar
 * @param tiempoRespuesta Variable donde se guardará el tiempo de respuesta (ms)
 * @return EstadoPuerto (ABIERTO, CERRADO o FILTRADO)
 */
EstadoPuerto Escaneo::verificarPuerto(const std::string& ip, int puerto, int& tiempoRespuesta) {
    auto inicio = std::chrono::high_resolution_clock::now();

    socket_t sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        tiempoRespuesta = -1;
        return EstadoPuerto::FILTRADO;
    }

#ifdef _WIN32
    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);
#else
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
#endif

    struct sockaddr_in direccion;
    direccion.sin_family = AF_INET;
    direccion.sin_port = htons(puerto);
    direccion.sin_addr.s_addr = INADDR_NONE;

    int resultado = inet_pton(AF_INET, ip.c_str(), &direccion.sin_addr);
    if (resultado <= 0) {
        CLOSESOCKET(sock);
        tiempoRespuesta = -1;
        return EstadoPuerto::FILTRADO;
    }

    int conectar = connect(sock, (struct sockaddr*)&direccion, sizeof(direccion));
    if (conectar == 0) {
        auto fin = std::chrono::high_resolution_clock::now();
        tiempoRespuesta = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(fin - inicio).count());
        CLOSESOCKET(sock);
        return EstadoPuerto::ABIERTO;
    }

#ifdef _WIN32
    if (WSAGetLastError() != WSAEWOULDBLOCK) {
#else
    if (errno != EINPROGRESS) {
#endif
        auto fin = std::chrono::high_resolution_clock::now();
        tiempoRespuesta = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(fin - inicio).count());
        CLOSESOCKET(sock);
        return EstadoPuerto::CERRADO;
    }

    fd_set fdset;
    struct timeval timeout;
    FD_ZERO(&fdset);
    FD_SET(sock, &fdset);
    timeout.tv_sec = 0;
    timeout.tv_usec = 500000; // 500ms

    int selectResult = select(static_cast<int>(sock + 1), NULL, &fdset, NULL, &timeout);

    auto fin = std::chrono::high_resolution_clock::now();
    tiempoRespuesta = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(fin - inicio).count());

    if (selectResult == 1) {
        int error = 0;
        socklen_t len = sizeof(error);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&error, &len);
        CLOSESOCKET(sock);
        if (error == 0) return EstadoPuerto::ABIERTO;
        return EstadoPuerto::CERRADO;
    } else if (selectResult == 0) {
        CLOSESOCKET(sock);
        return EstadoPuerto::FILTRADO;
    } else {
        CLOSESOCKET(sock);
        return EstadoPuerto::FILTRADO;
    }
}


/**
 * Escanea un puerto individual llamando a verificarPuerto y obteniendo el servicio.
 * @parametro: ip Dirección IP del host objetivo
 * @parametro: puerto Número de puerto a escanear
 * @return: Estructura Puerto con número, estado, servicio y tiempo de respuesta
 */
static Puerto escanearPuertoIndividual(const std::string& ip, int puerto) {
    int tiempoRespuesta = 0;
    EstadoPuerto estado = Escaneo::verificarPuerto(ip, puerto, tiempoRespuesta);
    std::string servicio = Escaneo::obtenerServicio(puerto);
    return Puerto(puerto, estado, servicio, tiempoRespuesta);
}

/**
 * Escanea múltiples puertos de un host usando hilos.
 * Determina la cantidad óptima de hilos según la plataforma y cantidad de puertos.
 * Muestra progreso en consola y ordena resultados por número de puerto.
 * @parametro: ip Dirección IP del host objetivo
 * @parametro: puertos Vector de puertos a escanear
 * @parametro: requestedThreads Número de hilos deseados (opcional)
 * @return: Vector de estructuras Puerto con resultados del escaneo
 */
std::vector<Puerto> Escaneo::escanearPuertos(const std::string& ip, const std::vector<int>& puertos, size_t requestedThreads /* = 0 */) {
    std::vector<Puerto> resultados;

    try {
        inicializarWinsock();

        // Determinar número de hilos a usar
        size_t numThreads = 0;
        if (requestedThreads > 0) {
            numThreads = std::min(requestedThreads, puertos.size());
        } else {
#ifdef _WIN32
            numThreads = std::min<size_t>(5, puertos.size());
#else
            size_t hw = std::thread::hardware_concurrency();
            if (hw == 0) hw = 2;
            size_t maxThreads = hw * 2;
            numThreads = std::min(maxThreads, puertos.size());
#endif
        }

        if (numThreads == 0) numThreads = 1;

        size_t batchSize = (puertos.size() + numThreads - 1) / numThreads; // ceil

        std::cout << "Usando " << numThreads << " hilos para escanear " << puertos.size() << " puertos..." << std::endl;

        std::vector<std::future<std::vector<Puerto>>> futures;
        futures.reserve(numThreads);

        for (size_t i = 0; i < puertos.size(); i += batchSize) {
            size_t end = std::min(i + batchSize, puertos.size());
            std::vector<int> lote(puertos.begin() + i, puertos.begin() + end);

            futures.push_back(std::async(std::launch::async, [ip, lote]() -> std::vector<Puerto> {
                std::vector<Puerto> resultadosLote;
                resultadosLote.reserve(lote.size());
                for (int puerto : lote) {
                    resultadosLote.push_back(escanearPuertoIndividual(ip, puerto));
                }
                return resultadosLote;
            }));
        }

        size_t completados = 0;
        for (auto& fut : futures) {
            std::vector<Puerto> loteResultados = fut.get();
            resultados.insert(resultados.end(), loteResultados.begin(), loteResultados.end());
            completados += loteResultados.size();
            std::cout << "\rProgreso: " << completados << "/" << puertos.size()
                      << " (" << (100 * completados / puertos.size()) << "%)" << std::flush;
        }
        std::cout << "\rEscaneo completado: " << resultados.size() << " puertos.          " << std::endl;

        // Ordenar resultados por número de puerto
        std::sort(resultados.begin(), resultados.end(), [](const Puerto& a, const Puerto& b) {
            return a.numero < b.numero;
        });

        limpiarWinsock();

    } catch (...) {
        limpiarWinsock();
        throw;
    }

    return resultados;
}

