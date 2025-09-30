# Escáner híbrido de puertos y sniffing en C++ con informe JSON

Me acabo de dar cuenta que está horriblemente hecho, tengo que refactorizar mucho de esto, el flujo era:

1. Mandar paquete -> Ver si el puerto estaba abierto -> Sniffear la respuesta

De hecho ahora que lo escribo no está tan mal, sí se puede hacer sólo me falta automatizar el envío del paquete y que el mismo escaneo llame a sniff después de enviar el paquete
puede ser que no necesita tanta refactorización

## TODOs:

1. Quizas hacer que el request se haga solo, por ahora hago un `curl http://localhost:80 -4` y funciona la captura pero se puede mejorar

Falta hacer lo de json, parámetros y así pero prefiero ir trabajandolo poco a poco

## Notas

Mandar un paquete UDP por el puerto 53 a el DNS de Google

```bash
dig @8.8.8.8 google.com
```

comando para abrir un puerto UDP y que responda

```bash
sudo socat UDP-LISTEN:50,fork,reuseaddr EXEC:'echo hello'
```

## Known issues

Cuando hace un escaneo UDP por la interfaz ethernet a la IP propia dentro de la red el escaneo no sirve, supongo que es porque como el kernel detecta que es una IP propia usa la interfaz loopback y produce errores inesperados de falsos positivos.

<p align="center">
    <img src="resources/udp_ethint_falso_positivo.png" alt="UDP falso positivo"/>
</p>


Sin embargo el escaneo SÍ funciona para interfaces ethernet, en este caso se testeó con una máquina virtual:

De forma manual se muesta que sí se recibe de verdad el paquete:

<p align="center">
    <img src="resources/udp_virbr0int_vm_manual.png" alt="UDP request manual"/>
</p>


Y un el escaneo exitoso:

<p align="center">
    <img src="resources/udp_virbr0int_vm_escaneo_valido.png" alt="UDP escaneo válido"/>
</p>


## Problemas

### Condiciones de carrera

### Headerbytes

Usando esto de respuesta

```bash
sudo socat UDP-LISTEN:50,fork,reuseaddr EXEC:'echo hello'
```

Output: 00 00 00 00 00 00 00 00 00 00 00 00 08 00 45 00 00 22 45 31 40 00 40 11 


```bash
sudo socat UDP-LISTEN:50,fork,reuseaddr EXEC:'echo babai'
```

Output: 00 00 00 00 00 00 00 00 00 00 00 00 08 00 45 00 00 22 fe 60 40 00 40 11

El problema era que mis headerbytes se capturaban así:

```
[
    {
        "header_bytes": "00 00 00 00 00 00 00 00 00 00 00 00 08 00 45 00",
        "ip": "127.0.0.1",
        "port": 50,
        "protocol": "UDP",
        "service": "unknown",
        "status": "open"
    }
]
```
