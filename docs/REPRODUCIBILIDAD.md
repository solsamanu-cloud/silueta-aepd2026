# Reproducción y alcance de las tablas

Desde la raíz, sin radio, privilegios, tshark ni tcpdump:

```bash
.venv/bin/python -m silueta.reproduce --out results/reproduction
.venv/bin/python bin/verify-manifest.py
```

| Salida | Contenido recalculado |
|---|---|
| quality.csv | Recuentos útiles, cadencia, huecos incluyendo bordes, varianza global ψ por captura y serie |
| movement.csv | 37 tomas de cruces/controles, antenas y orientación; puntuaciones válidas, episodios y duración, salidas asociadas |
| CAPxxxx-variance.csv | Cada puntuación causal y estado del detector; NaN si no es evaluable |
| events.json | Instantes relativos de activación/cierre, salidas y reproducción del P99,5 inicial |
| respiration.csv | 22 tomas pautadas/controles: pico global y varianza tras retirar tendencia |
| respiration-100s.csv | Todos los máximos de los tres subtramos por toma |
| CAPxxxx-spectrum.csv | Los 901 valores del periodograma agregado |

La correspondencia exacta captura–condición está en `data/catalog.csv`.
Ejemplos: CAP0013 calibra el detector; CAP0011/12 son los recorridos S01;
CAP0016/17 S02; CAP0023/24 S04; CAP0030/31 omni; CAP0037/38 panel orientación B.
CAP0066/67 son las dos pautas de 10/min en P-R03; CAP0074/75 las de 12/min;
CAP0078/79 sus vacíos. No se confunde S04 con la sesión descartada S03 de cruces.

`data/reference-results.json` contiene únicamente cifras extraídas de los informes
originales, asociadas a códigos CAP. Se compara contra ellas al ejecutar el comando;
**no se usan para calcular las tablas**. Tolerancias: rtol=2e−6 y atol=2e−6 por
serialización decimal de los CSV; la calibración usa atol=1e−10. Los recuentos y
números de episodios deben coincidir. Un desacuerdo termina con error.

## Qué no puede regenerarse con esta distribución

La memoria incluye resultados que exceden los datos cuya publicación se autorizó.
Esta versión publica solo campañas controladas terminadas de C01–C05/AP01.

- Las capacidades de asociación y el protocolo histórico anterior al suplemento
  no se regeneran con los CSV de ψ. El suplemento controlado sí incluye RSSI,
  balizas y NDPA unicast de sus 42 capturas; véase ENSAYOS-CONTROLADOS.md.
- Las jornadas domésticas y el estudio del cliente aleatorio no se publican;
  por tanto, sus tablas, diarios y contrastes estadísticos no se regeneran aquí.
- El diagnóstico histórico de distancia entre cuerpos binarios tiene código,
  pero no datos binarios reales públicos. Los CSV angulares no los sustituyen.
- No se recuperan MAC, SSID, horas reales, fotografías ni planos mediante este proceso.

La numeración de capítulos cambia entre revisiones de la memoria; se identifica
cada resultado por campaña y método. **No se afirma que todas las tablas del
capítulo 6 sean reproducibles con este paquete.** Para una evaluación privada de
las restantes hacen falta los originales autorizados; sus huellas públicas permiten
comprobar integridad. No se han añadido datos domésticos para completar esa cobertura.

El suplemento se reproduce con `python -m silueta.controlled --out results/controlled`.
Incluye 30 capturas POS02, ocho fases del robot y seis ajustes de potencia.
Sus 254 comprobaciones independientes complementan las tablas anteriores.
