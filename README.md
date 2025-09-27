# Escáner híbrido de puertos y sniffing en C++ con informe JSON

## TODOs:

1. Quizas hacer que el request se haga solo, por ahora hago un `curl http://localhost:80 -4` y funciona la captura pero se puede mejorar
2. Imprementar UDP

Falta hacer lo de json, parámetros y así pero prefiero ir trabajandolo poco a poco

## Notas

Mandar un paquete UDP por el puerto 53 a el DNS de Google

```bash
dig @8.8.8.8 google.com
```
