# Método reproducible de movimiento

Autores: Manuel Solana, Héctor Rodríguez y Francisco José Amo.

## Detector del recorrido naranja

1. Origen: primer paquete de la captura, no primer BFI. Intervalo útil [120,420) s.
2. Cada configuración/sentido se analiza por separado. Se usan todos los componentes ψ.
3. En cada instante t se calcula la media de sus varianzas poblacionales (ddof=0)
   en [t−6,t]. No se retira tendencia en este detector.
4. No hay puntuación antes de 126 s. Se exigen al menos cuatro informes y ningún
   hueco mayor de 2,8 s, incluyendo los bordes de la ventana. Los huecos no valen cero.
5. Calibración: percentil 99,5 de las puntuaciones válidas del vacío inicial S01,
   CAP0013, con interpolación lineal. Umbral congelado: **0,006820114055593958 rad²**
   (0,006820114 redondeado en la memoria). No se recalibra por sesión.
6. Dos puntuaciones consecutivas estrictamente mayores activan el detector al
   tiempo de la segunda; dos menores o iguales lo cierran. Un dato no evaluable
   cierra el episodio y reinicia los contadores. Un episodio abierto termina
   censurado en 420 s. No se retrotrae su inicio a la primera puntuación.
7. Salidas pautadas: 150, 200, 250, 300 y 350 s. Una salida se asocia a la primera
   **nueva** activación en [salida,salida+20). Estar activo antes no cuenta como una
   nueva detección. Los 20 s no representan duración de la marcha ni llegada medida.

`python -m silueta.reproduce` recalcula CAP0013, usa el umbral congelado y produce
puntuaciones por instante, episodios, duración acumulada y asociaciones por salida.
La precisión decimal limitada de los CSV puede cambiar los últimos decimales del
percentil; las verificaciones usan tolerancia explícita, no redondean decisiones.
La calibración S01 no constituye un control independiente. Las activaciones de
quietud E2 se conservan y las sesiones descartadas no se reincorporan.

La GUI muestra además valores descriptivos con pocas muestras para inspección;
los marca con calidad limitada. **Esos puntos no son puntuaciones válidas del
estimador de la memoria.** La media móvil visual no interviene en el detector.
Una línea de umbral en pantalla no equivale a aplicar la regla de dos puntuaciones.

## Respiración pautada: estimador distinto

`silueta/spectral.py` reproduce el método original sobre [120,420): ajuste por
mínimos cuadrados de constante y tendencia lineal por componente ψ, sustracción
antes de Lomb–Scargle, sin interpolación. Rejilla de **901 frecuencias de 0,05 a
0,35 Hz**, extremos incluidos. Se promedian los periodogramas **no normalizados**
de todos los componentes y se divide por la media de sus energías residuales / 2.
No es promedio de periodogramas normalizados individualmente ni GLS con tendencia
ajustada conjuntamente a cada frecuencia. Se informa el máximo global y todos
los subtramos [120,220), [220,320), [320,420), sin elegir componentes ni el pico
más cercano al metrónomo. La varianza informada aquí es la media del cuadrado del
residuo; no es la varianza causal de seis segundos del detector de movimiento.

`lib/respiration.py` conserva utilidades de una componente y ventanas de 120 s,
con la misma banda por defecto. Las tablas se regeneran mediante `silueta.reproduce`,
no mediante esas utilidades. Ninguno de estos máximos acredita origen fisiológico,
excluye aliasing ni es un contraste de significación estadística.

## Diagnóstico anterior: dependencia de la cadencia

`bin/09-dt-dependence.py etiqueta=/ruta/privada/captura.pcap` conserva el diagnóstico
original de distancias euclídea/coseno **entre cuerpos binarios de informes**, con
Spearman, ajuste lineal y comparaciones de cadencia. Requiere PCAP propios/autorizados;
no usa los CSV ψ, que no conservan los bytes ni el SNR del informe. No se debe
sustituir esa distancia por distancia entre ángulos y afirmar que es el mismo método.
Este diagnóstico exploratorio anterior no define el detector temporal de cruces.
