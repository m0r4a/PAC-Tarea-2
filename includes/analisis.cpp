#include "analisis.h"
#include <algorithm>

// =============================================================
// Definición de los conjuntos de puertos sospechosos
// Estos sets almacenan listas estáticas de puertos asociados
// con diferentes tipos de riesgos (malware, backdoors, P2P, etc.)
// =============================================================

const std::set<int> Analisis::PUERTOS_MALICIOSOS = {
    // Trojans conocidos
    1243, 1999, 2001, 2115, 2140, 3129, 3150, 4590, 5000, 5001, 5011,
    6400, 6670, 6711, 6712, 6713, 6776, 7000, 7300, 7301, 7306, 7307,
    7308, 9872, 9873, 9874, 9875, 10067, 10167, 12223, 12345, 12346,
    16969, 20034, 21544, 30100, 31337, 31338, 54321
};

const std::set<int> Analisis::PUERTOS_ADMINISTRATIVOS = {
    // Servicios administrativos sensibles
    22, 23, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900, 5901,
    5902, 5903, 5904, 5905, 6000, 6001, 6002, 8080, 8443, 9200
};

const std::set<int> Analisis::PUERTOS_TROJANS = {
    // Puertos comúnmente usados por trojans
    1234, 1243, 1245, 1492, 1600, 1807, 1981, 1999, 2001, 2023,
    2115, 2140, 2989, 3024, 3150, 3700, 4000, 4092, 4590, 5000,
    5001, 5011, 5321, 5400, 5401, 5402, 5550, 5569, 5637, 5638,
    6400, 6670, 6771, 6776, 6912, 6969, 7000, 7300, 7301, 7306,
    7307, 7308, 7789, 9872, 9873, 9874, 9875, 9989, 10067, 10167,
    11000, 11223, 12076, 12223, 12345, 12346, 12361, 12362, 13000,
    16969, 20000, 20001, 20034, 21544, 22222, 23456, 26274, 30100,
    30101, 30102, 31336, 31337, 31338, 33333, 40412, 40421, 40422,
    40423, 40426, 47262, 50505, 50766, 53001, 54320, 54321, 61466,
    65000
};

const std::set<int> Analisis::PUERTOS_BACKDOORS = {
    // Backdoors comunes
    1524, 1999, 2001, 4444, 6667, 6668, 6669, 7000, 8080, 8888,
    9999, 10000, 31337, 31338, 54321
};

const std::set<int> Analisis::PUERTOS_P2P = {
    // Aplicaciones P2P
    411, 412, 1214, 4661, 4662, 4665, 4672, 6346, 6347, 6881, 6882,
    6883, 6884, 6885, 6886, 6887, 6888, 6889, 6890, 6891, 6892,
    6893, 6894, 6895, 6896, 6897, 6898, 6899, 6969
};

const std::set<int> Analisis::PUERTOS_DESARROLLO = {
    // Puertos comunes de desarrollo que podrían ser sospechosos en producción
    3000, 4000, 5000, 8000, 8080, 8081, 8888, 9000, 9090
};


// =============================================================
// Funciones de verificación básica de puertos
// Determinan si un número de puerto pertenece a alguna de las
// categorías definidas anteriormente (malicioso, trojan, etc.)
// =============================================================

bool Analisis::esPuertoConocidoMalicioso(int puerto) {
    return PUERTOS_MALICIOSOS.find(puerto) != PUERTOS_MALICIOSOS.end();
}

bool Analisis::esPuertoAdministrativo(int puerto) {
    return PUERTOS_ADMINISTRATIVOS.find(puerto) != PUERTOS_ADMINISTRATIVOS.end();
}

bool Analisis::esPuertoTrojan(int puerto) {
    return PUERTOS_TROJANS.find(puerto) != PUERTOS_TROJANS.end();
}

bool Analisis::esPuertoBackdoor(int puerto) {
    return PUERTOS_BACKDOORS.find(puerto) != PUERTOS_BACKDOORS.end();
}

bool Analisis::esPuertoP2P(int puerto) {
    return PUERTOS_P2P.find(puerto) != PUERTOS_P2P.end();
}

// =============================================================
// Funciones de verificación básica de puertos
// Determinan si un número de puerto pertenece a alguna de las
// categorías definidas anteriormente (malicioso, trojan, etc.)
// =============================================================

bool Analisis::esPuertoInusual(int puerto) {
    // Puertos en rangos inusuales o específicos
    return (puerto > 49152) || // Puertos dinámicos/privados
           (puerto >= 1024 && puerto <= 5000 && puerto % 1000 == 0) || // Puertos "redondos"
           (puerto >= 31000 && puerto <= 33000); // Rango comúnmente usado por malware
}

// =============================================================
// Calcular puntuación de riesgo de un puerto
// Suma puntos según características del puerto, como:
// - Si es malicioso, trojan, backdoor, P2P, administrativo o inusual
// - Si pertenece a puertos de desarrollo
// - Si responde muy rápido (posible servicio configurado)
// Devuelve un número que representa el nivel de riesgo
// =============================================================

int Analisis::calcularPuntuacionRiesgo(const Puerto& puerto) {
    int puntuacion = 0;
    
    if (puerto.estado == EstadoPuerto::ABIERTO) {
        puntuacion += 10;
        
        if (esPuertoConocidoMalicioso(puerto.numero)) puntuacion += 50;
        if (esPuertoTrojan(puerto.numero)) puntuacion += 40;
        if (esPuertoBackdoor(puerto.numero)) puntuacion += 35;
        if (esPuertoP2P(puerto.numero)) puntuacion += 25;
        if (esPuertoAdministrativo(puerto.numero)) puntuacion += 20;
        if (esPuertoInusual(puerto.numero)) puntuacion += 15;
        
        // Puertos de desarrollo en sistemas que no deberían tenerlos
        if (PUERTOS_DESARROLLO.find(puerto.numero) != PUERTOS_DESARROLLO.end()) {
            puntuacion += 15;
        }
        
        // Tiempo de respuesta muy rápido puede indicar servicio configurado
        if (puerto.tiempoRespuesta < 10) puntuacion += 5;
    }
    
    return puntuacion;
}

// =============================================================
// Obtener la razón de sospecha de un puerto
// Devuelve un string con las causas por las cuales un puerto fue
// marcado como sospechoso (ej: malware, trojan, rango inusual, etc.)
// =============================================================

std::string Analisis::obtenerRazonSospecha(const Puerto& puerto, int nivelSensibilidad) {
    std::vector<std::string> razones;
    
    if (esPuertoConocidoMalicioso(puerto.numero)) {
        razones.push_back("Puerto asociado con malware conocido");
    }
    
    if (esPuertoTrojan(puerto.numero)) {
        razones.push_back("Comúnmente usado por trojans");
    }
    
    if (esPuertoBackdoor(puerto.numero)) {
        razones.push_back("Puerto típico de backdoors");
    }
    
    if (esPuertoP2P(puerto.numero)) {
        razones.push_back("Puerto P2P que puede violar políticas");
    }
    
    if (esPuertoAdministrativo(puerto.numero)) {
        razones.push_back("Servicio administrativo sensible expuesto");
    }
    
    if (esPuertoInusual(puerto.numero)) {
        razones.push_back("Puerto en rango inusual o sospechoso");
    }
    
    if (PUERTOS_DESARROLLO.find(puerto.numero) != PUERTOS_DESARROLLO.end()) {
        razones.push_back("Puerto de desarrollo en sistema de producción");
    }
    
    // Para nivel alto, agregar más criterios
    if (nivelSensibilidad >= 3) {
        if (puerto.numero > 10000 && puerto.numero < 65535) {
            razones.push_back("Puerto en rango alto poco común para servicios estándar");
        }
    }
    
    if (razones.empty()) {
        return "Puerto abierto sin clasificación específica de riesgo";
    }
    
    std::string resultado;
    for (size_t i = 0; i < razones.size(); i++) {
        if (i > 0) resultado += "; ";
        resultado += razones[i];
    }
    
    return resultado;
}

// =============================================================
// Obtener la razón de sospecha de un puerto
// Devuelve un string con las causas por las cuales un puerto fue
// marcado como sospechoso (ej: malware, trojan, rango inusual, etc.)
// =============================================================

std::vector<int> Analisis::detectarSecuenciasSospechosas(const std::vector<Puerto>& puertos) {
    std::vector<int> sospechosos;
    std::vector<int> abiertos;
    
    // Obtener puertos abiertos ordenados
    for (const auto& puerto : puertos) {
        if (puerto.estado == EstadoPuerto::ABIERTO) {
            abiertos.push_back(puerto.numero);
        }
    }
    
    std::sort(abiertos.begin(), abiertos.end());
    
    // Detectar secuencias consecutivas largas (posible escaneo o configuración automática)
    if (abiertos.size() >= 5) {
        for (size_t i = 0; i < abiertos.size() - 4; i++) {
            bool consecutivo = true;
            for (int j = 1; j < 5; j++) {
                if (abiertos[i + j] - abiertos[i + j - 1] != 1) {
                    consecutivo = false;
                    break;
                }
            }
            if (consecutivo) {
                for (int j = 0; j < 5; j++) {
                    sospechosos.push_back(abiertos[i + j]);
                }
            }
        }
    }
    
    return sospechosos;
}

// =============================================================
// Verificación de patrones sospechosos generales
// Marca como sospechoso si:
// - Hay demasiados puertos administrativos abiertos
// - Hay al menos un puerto malicioso
// - Hay más de 20 puertos abiertos en total
// =============================================================

bool Analisis::tienePatronSospechoso(const std::vector<Puerto>& puertos) {
    int puertosAbiertos = 0;
    int puertosAdministrativos = 0;
    int puertosMaliciosos = 0;
    
    for (const auto& puerto : puertos) {
        if (puerto.estado == EstadoPuerto::ABIERTO) {
            puertosAbiertos++;
            if (esPuertoAdministrativo(puerto.numero)) puertosAdministrativos++;
            if (esPuertoConocidoMalicioso(puerto.numero)) puertosMaliciosos++;
        }
    }
    
    // Patrones sospechosos:
    // 1. Demasiados puertos administrativos abiertos
    if (puertosAdministrativos > 3) return true;
    
    // 2. Cualquier puerto malicioso conocido
    if (puertosMaliciosos > 0) return true;
    
    // 3. Demasiados puertos abiertos en general (posible honeypot o sistema comprometido)
    if (puertosAbiertos > 20) return true;
    
    return false;
}

// =============================================================
// Función principal de análisis
// - Aplica umbrales de riesgo según nivel de sensibilidad
// - Marca como sospechosos puertos que superen el umbral
// - Añade los que formen secuencias consecutivas sospechosas
// - Ordena y devuelve la lista final de puertos sospechosos
// =============================================================

std::vector<Puerto> Analisis::identificarSospechosos(const std::vector<Puerto>& puertos, int nivelSensibilidad) {
    std::vector<Puerto> sospechosos;
    
    // Umbrales según nivel de sensibilidad
    int umbralRiesgo;
    switch (nivelSensibilidad) {
        case 1: umbralRiesgo = 40; break; // Bajo: solo muy sospechosos
        case 2: umbralRiesgo = 25; break; // Medio: moderadamente sospechosos
        case 3: umbralRiesgo = 15; break; // Alto: cualquier cosa potencialmente sospechosa
        default: umbralRiesgo = 25; break;
    }
    
    // Evaluar cada puerto abierto
    for (auto puerto : puertos) {
        if (puerto.estado == EstadoPuerto::ABIERTO) {
            int puntuacion = calcularPuntuacionRiesgo(puerto);
            
            if (puntuacion >= umbralRiesgo) {
                puerto.razonSospecha = obtenerRazonSospecha(puerto, nivelSensibilidad);
                sospechosos.push_back(puerto);
            }
        }
    }
    
    // Detectar patrones adicionales
    std::vector<int> secuenciasSospechosas = detectarSecuenciasSospechosas(puertos);
    
    // Agregar puertos de secuencias sospechosas que no estén ya incluidos
    for (int numeroSecuencia : secuenciasSospechosas) {
        bool yaIncluido = false;
        for (const auto& sospechoso : sospechosos) {
            if (sospechoso.numero == numeroSecuencia) {
                yaIncluido = true;
                break;
            }
        }
        
        if (!yaIncluido) {
            // Buscar el puerto original
            for (auto puerto : puertos) {
                if (puerto.numero == numeroSecuencia && puerto.estado == EstadoPuerto::ABIERTO) {
                    puerto.razonSospecha = "Parte de secuencia consecutiva sospechosa de puertos abiertos";
                    sospechosos.push_back(puerto);
                    break;
                }
            }
        }
    }
    
    // Ordenar por número de puerto
    std::sort(sospechosos.begin(), sospechosos.end(), 
              [](const Puerto& a, const Puerto& b) {
                  return a.numero < b.numero;
              });
    
    return sospechosos;
}
