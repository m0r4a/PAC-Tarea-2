#ifndef ESCANEO_H
#define ESCANEO_H

#include <string>
#include <vector>

enum class EstadoPuerto {
    ABIERTO,
    CERRADO,
    FILTRADO
};

struct Puerto {
    int numero;
    EstadoPuerto estado;
    std::string servicio;
    int tiempoRespuesta; // ms
    std::string razonSospecha;

    Puerto() : numero(0), estado(EstadoPuerto::FILTRADO), servicio(""), tiempoRespuesta(0), razonSospecha("") {}
    Puerto(int n, EstadoPuerto e, const std::string& s, int t)
      : numero(n), estado(e), servicio(s), tiempoRespuesta(t), razonSospecha("") {}
};

class Escaneo {
public:
    // Iniciar y limpiar Winsock
    static void inicializarWinsock();
    static void limpiarWinsock();

    // No sé, trabajo sobre IPs?
    static bool validarIP(const std::string& ip);
    static std::string obtenerServicio(int puerto);

    // Revisar un puerto individual (devuelve su estado y tiempo de resp.)
    static EstadoPuerto verificarPuerto(const std::string& ip, int puerto, int& tiempoRespuesta);

    // Y ps este es el escaneo
    static std::vector<Puerto> escanearPuertos(const std::string& ip, const std::vector<int>& puertos, size_t requestedThreads = 0);
};

#endif

