# Herramienta de Escaneo de Puertos TCP/UDP con Captura de Tramas

## Objetivo General

Desarrollar en C++ una herramienta para Linux que realice un escaneo real de puertos TCP y UDP sobre un host objetivo, capture la primera trama de respuesta de cada puerto abierto mediante sniffing, y al finalizar genere un informe JSON detallado con los servicios detectados y los primeros bytes de cabecera de cada respuesta.

## Trabajo en Equipo

- **Equipos de 1 a 4 personas**
- Cada integrante debe asumir la responsabilidad de al menos un módulo del proyecto (Escaneo, Sniffing, JSON)
- Documentar en comentarios dentro del código el nombre del responsable de cada módulo
- Usar GitHub para colaboración, control de versiones y revisión mediante pull requests

## Descripción del Reto

### Escaneo Real de Puertos

- **TCP**: Intentar conexión no bloqueante a cada puerto y determinar "abierto", "cerrado" o "filtrado" según timeout y respuesta
- **UDP**: Enviar un datagrama vacío al puerto y evaluar ICMP "port unreachable" o respuesta de servicio

### Sniffing de la Primera Respuesta

- Abrir interface en modo promiscuo con libpcap o sockets RAW
- Aplicar filtro BPF para capturar únicamente paquetes de respuesta al host y puertos escaneados
- Guardar los primeros N bytes (por ejemplo, 16) de la cabecera IP/TCP o IP/UDP de la primera trama recibida por puerto abierto

### Integración

- Ejecutar escaneo y captura de forma concurrente para optimizar tiempos
- Asociar cada intento de conexión o envío UDP con su trama capturada correspondiente

## Investigación Sugerida

- **Conexiones TCP no bloqueantes**: `connect()` + `select()` o `poll()` para timeout
- **Escaneo UDP**: `sendto()`, manejo de ICMP "port unreachable"
- **Captura de paquetes con libpcap**: filtros BPF (`pcap_compile`/`pcap_setfilter`)
- **Concurrencia en C++17**: `std::thread`, `std::mutex`, `std::future` o `asio::io_context`
- **Generación de JSON**: bibliotecas header-only como `nlohmann/json` o `cJSON`

## Entrada Esperada del Programa

Al iniciar, solicitar al usuario:

- Dirección IP objetivo (string)
- Puerto inicial (int) y puerto final (int) o lista de puertos (int[])
- Timeout en milisegundos para TCP y UDP (int, opcional)
- Nombre del archivo de salida JSON (string)

## Salida Esperada del Programa

### En Consola

Para cada puerto:
- Protocolo (TCP/UDP)
- Estado: Abierto / Cerrado / Filtrado
- Servicio estimado (basado en estándar o banner)

### Archivo JSON

**Ejemplo: `resultado.json`**

```json
[
  {
    "ip": "192.168.1.100",
    "port": 22,
    "protocol": "TCP",
    "service": "ssh",
    "header_bytes": "45 00 00 34 12 34 40 00"
  },
  {
    "ip": "192.168.1.100",
    "port": 161,
    "protocol": "UDP",
    "service": "snmp",
    "header_bytes": "45 00 00 2c 56 78 00 00"
  }
]
```

## Requisitos Técnicos

### Lenguaje y Estructura

- **Lenguaje**: C++17 o superior
- **Modularidad**: Mínimo tres módulos separados:
  - `Escaneo.cpp` / `Escaneo.h`: lógica de escaneo TCP y UDP
  - `Sniffer.cpp` / `Sniffer.h`: captura y filtrado de paquetes
  - `JSONGen.cpp` / `JSONGen.h`: construcción y escritura del JSON
  - `main.cpp`: validación de entrada, orquestación y sincronización de módulos

### Dependencias

- **libpcap** (o sockets RAW con `<netinet/ip.h>`)
- **Biblioteca JSON** header-only (ej. `nlohmann/json`)

### Características Técnicas

- **Concurrencia**: Uso de hilos o asincronía para escaneo y sniffing simultáneos
- **Manejo de errores**:
  - Validar formato de IP y rangos de puertos
  - Controlar timeouts y fallos de socket
  - Detectar errores al abrir libpcap o sockets RAW
- **Documentación**: `README.md` con instrucciones claras
