#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <algorithm>
#include "includes/escaneo.h"
#include "includes/analisis.h"
#include "includes/registro.h"

static std::vector<int> parsearPuertos(const std::string& input) {
    std::vector<int> puertos;
    std::stringstream ss(input);
    std::string token;

    while (std::getline(ss, token, ',')) {
        token.erase(0, token.find_first_not_of(" \t"));
        token.erase(token.find_last_not_of(" \t") + 1);

        if (token.empty()) continue;

        size_t guion = token.find('-');
        try {
            if (guion != std::string::npos) {
                int inicio = std::stoi(token.substr(0, guion));
                int fin    = std::stoi(token.substr(guion + 1));
                if (inicio < 1) inicio = 1;
                if (fin > 65535) fin = 65535;
                if (inicio > fin) std::swap(inicio, fin);
                for (int p = inicio; p <= fin; ++p) puertos.push_back(p);
            } else {
                int puerto = std::stoi(token);
                if (puerto >= 1 && puerto <= 65535) puertos.push_back(puerto);
            }
        } catch (...) {
        }
    }

    std::sort(puertos.begin(), puertos.end());
    puertos.erase(std::unique(puertos.begin(), puertos.end()), puertos.end());
    return puertos;
}

static void imprimirUso(const char* prog) {
    std::cout << "Uso: " << prog << " <objetivo> [opciones]\n\n";
    std::cout << "Argumentos:\n";
    std::cout << "  objetivo               Dirección IP o nombre del host a escanear\n\n";
    std::cout << "Opciones:\n";
    std::cout << "  -p, --puertos RANGO    Rango de puertos a escanear\n";
    std::cout << "                         Ejemplos: 1-1000, 22,80,443, 1-65535\n";
    std::cout << "  -s, --sensibilidad N   Nivel de sensibilidad del escaneo (1-3)\n";
    std::cout << "                         1=Bajo, 2=Medio, 3=Alto (predeterminado: 2)\n";
    std::cout << "  -t, --threads N        Número de hilos de ejecución\n";
    std::cout << "                         Sobrescribe el límite predeterminado\n";
    std::cout << "  -o, --output ARCHIVO   Archivo de salida para el reporte\n";
    std::cout << "  -h, --help             Muestra esta ayuda y termina\n\n";
    std::cout << "Ejemplos:\n";
    std::cout << "  " << prog << " 192.168.1.10\n";
    std::cout << "  " << prog << " 192.168.1.10 -p 1-1000 -s 3 -t 8\n";
    std::cout << "  " << prog << " ejemplo.com --puertos 22,80,443 --output reporte.txt\n";
}

int main(int argc, char* argv[]) {
    try {
        if (argc < 2) {
            imprimirUso(argv[0]);
            return 1;
        }

        std::string ip = argv[1];
        std::string puertoInput = "1-1024"; // default
        int nivelSensibilidad = 2;          // default
        size_t requestedThreads = 0;        // 0 => comportamiento por defecto
        std::string archivoSalida = "";     // vacío => no generar reporte

        // Esto es el infierno, no recomiendo tratar de leerlo

        for (int i = 2; i < argc; ++i) {
          std::string arg = argv[i];
          if ((arg == "-p" || arg == "--puertos") && i + 1 < argc) {
            puertoInput = argv[++i];
          } else if (arg.rfind("-p", 0) == 0 && arg.length() > 2) {
            puertoInput = arg.substr(2);
          } else if (arg.rfind("--puertos=", 0) == 0) {
            puertoInput = arg.substr(10);
          }
          else if ((arg == "-s" || arg == "--sensibilidad") && i + 1 < argc) {
            try {
              nivelSensibilidad = std::stoi(argv[++i]);
            } catch (...) {
              nivelSensibilidad = 2;
            }
          } else if (arg.rfind("-s", 0) == 0 && arg.length() > 2) {
            try {
              nivelSensibilidad = std::stoi(arg.substr(2));
            } catch (...) {
              nivelSensibilidad = 2;
            }
          } else if (arg.rfind("--sensibilidad=", 0) == 0) {
            try {
              nivelSensibilidad = std::stoi(arg.substr(15));
            } catch (...) {
              nivelSensibilidad = 2;
            }
          }
          else if ((arg == "-t" || arg == "--threads") && i + 1 < argc) {
            try {
              requestedThreads =
                  static_cast<size_t>(std::max(1, std::stoi(argv[++i])));
            } catch (...) {
              requestedThreads = 0;
            }
          } else if (arg.rfind("-t", 0) == 0 && arg.length() > 2) {
            try {
              requestedThreads =
                  static_cast<size_t>(std::max(1, std::stoi(arg.substr(2))));
            } catch (...) {
              requestedThreads = 0;
            }
          } else if (arg.rfind("--threads=", 0) == 0) {
            try {
              requestedThreads =
                  static_cast<size_t>(std::max(1, std::stoi(arg.substr(10))));
            } catch (...) {
              requestedThreads = 0;
            }
          }
          else if ((arg == "-o" || arg == "--output") && i + 1 < argc) {
            archivoSalida = argv[++i];
          } else if (arg.rfind("-o", 0) == 0 && arg.length() > 2) {
            archivoSalida = arg.substr(2);
          } else if (arg.rfind("--output=", 0) == 0) {
            archivoSalida = arg.substr(9);
          }
          else if (arg == "-h" || arg == "--help") {
            imprimirUso(argv[0]);
            return 0;
          }
          else {
            std::cerr << "Advertencia: Argumento desconocido ignorado: " << arg
                      << std::endl;
          }
        }

        if (nivelSensibilidad < 1 || nivelSensibilidad > 3)
          nivelSensibilidad = 2;

        if (!Escaneo::validarIP(ip)) {
          std::cerr << "Dirección IP inválida: " << ip << std::endl;
          return 1;
        }

        std::vector<int> puertos = parsearPuertos(puertoInput);
        if (puertos.empty()) {
            std::cerr << "No se especificaron puertos válidos en: " << puertoInput << std::endl;
            return 1;
        }

        std::cout << "Iniciando escaneo de " << puertos.size() << " puertos en " << ip
                  << " (puertos: " << puertoInput << ", sensibilidad: " << nivelSensibilidad;
        if (requestedThreads > 0) std::cout << ", threads solicitados: " << requestedThreads;
        if (!archivoSalida.empty()) std::cout << ", reporte: " << archivoSalida;
        std::cout << ")...\n\n";

        // Llamar al escaneo
        std::vector<Puerto> resultados = Escaneo::escanearPuertos(ip, puertos, requestedThreads);

        // Imprimir solo puertos abiertos
        std::cout << "=== PUERTOS ABIERTOS ===\n";
        bool anyOpen = false;
        for (const auto& p : resultados) {
            if (p.estado == EstadoPuerto::ABIERTO) {
                anyOpen = true;
                std::cout << "Puerto " << p.numero;
                if (!p.servicio.empty()) std::cout << " (" << p.servicio << ")";
                std::cout << " ABIERTO\n";
            }
        }
        if (!anyOpen) {
            std::cout << "Ningún puerto abierto detectado.\n";
        }

        // hacer el análisis
        std::vector<Puerto> sospechosos = Analisis::identificarSospechosos(resultados, nivelSensibilidad);
        std::cout << "\n=== PUERTOS SOSPECHOSOS (sensibilidad " << nivelSensibilidad << ") ===\n";
        if (sospechosos.empty()) {
            std::cout << "Ningún puerto considerado sospechoso con este nivel.\n";
        } else {
            for (const auto& p : sospechosos) {
                std::cout << "Puerto " << p.numero;
                if (!p.servicio.empty()) std::cout << " (" << p.servicio << ")";
                std::cout << " -> " << p.razonSospecha << "\n";
            }
        }

        // generar reporte si hay -o (algo)
        if (!archivoSalida.empty()) {
            std::cout << "\nGenerando reporte en: " << archivoSalida << "... ";
            if (Registro::guardarResultados(archivoSalida, ip, resultados, sospechosos)) {
                std::cout << "\n\033[32mReporte generado correctamente.\033[0m\n";
            } else {
                std::cout << "\n\033[31mError al generar el reporte.\033[0m\n";
                return 1;
            }
        }

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
