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
