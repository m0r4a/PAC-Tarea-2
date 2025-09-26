#ifndef ANALISIS_H
#define ANALISIS_H

#include "escaneo.h"
#include <vector>
#include <set>

class Analisis {
public:
    // Función principal
    static std::vector<Puerto> identificarSospechosos(const std::vector<Puerto>& puertos, int nivelSensibilidad);
    
    // Esto es lo de sospecha
    static bool esPuertoConocidoMalicioso(int puerto);
    static bool esPuertoAdministrativo(int puerto);
    static bool esPuertoTrojan(int puerto);
    static bool esPuertoBackdoor(int puerto);
    static bool esPuertoP2P(int puerto);
    static bool esPuertoInusual(int puerto);
    
    // patrones
    static bool tienePatronSospechoso(const std::vector<Puerto>& puertos);
    static std::vector<int> detectarSecuenciasSospechosas(const std::vector<Puerto>& puertos);
    
    // Utils
    static std::string obtenerRazonSospecha(const Puerto& puerto, int nivelSensibilidad);
    static int calcularPuntuacionRiesgo(const Puerto& puerto);

private:
    // constantes con los puertos
    static const std::set<int> PUERTOS_MALICIOSOS;
    static const std::set<int> PUERTOS_ADMINISTRATIVOS;
    static const std::set<int> PUERTOS_TROJANS;
    static const std::set<int> PUERTOS_BACKDOORS;
    static const std::set<int> PUERTOS_P2P;
    static const std::set<int> PUERTOS_DESARROLLO;
};

#endif
