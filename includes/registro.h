#ifndef REGISTRO_H
#define REGISTRO_H

#include "escaneo.h"
#include <string>
#include <vector>
#include <fstream>

class Registro {
public:
    static bool guardarResultados(const std::string& nombreArchivo, 
                                 const std::string& ip,
                                 const std::vector<Puerto>& resultados,
                                 const std::vector<Puerto>& sospechosos);
    
    static std::string obtenerFechaHora();
    static std::string formatearEstado(EstadoPuerto estado);
    static bool validarNombreArchivo(const std::string& nombreArchivo);
    
    static void escribirEncabezado(std::ofstream& archivo, const std::string& ip);
    static void escribirResultadosCompletos(std::ofstream& archivo, const std::vector<Puerto>& resultados);
    static void escribirPuertosSospechosos(std::ofstream& archivo, const std::vector<Puerto>& sospechosos);
    static void escribirEstadisticas(std::ofstream& archivo, const std::vector<Puerto>& resultados);
    static void escribirRecomendaciones(std::ofstream& archivo, const std::vector<Puerto>& sospechosos);
    
    static void manejarErrorArchivo(const std::string& nombreArchivo, const std::string& operacion);

private:
    static const std::string SEPARADOR;
};

#endif
