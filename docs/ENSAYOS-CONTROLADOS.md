# POS02 robot y potencia del AP

Este suplemento publica las campañas controladas terminadas que faltaban. No
incluye capturas domésticas continuas, horarios de sueño, diarios ni otras redes.
La relación exacta está en `data/controlled-tests.json` y `data/catalog.csv`.

| Capturas | Contenido | Intervalo útil |
|---|---|---|
| CAP0106–CAP0115 | POS02 S01 | [120,420) s |
| CAP0116–CAP0125 | POS02 S02 | [120,420) s |
| CAP0126–CAP0135 | POS02 S03 | [120,420) s |
| CAP0136–CAP0138 | Robot S01 | Cuatro fases de 300 s en tres archivos |
| CAP0139–CAP0141 | Robot S02 | Misma secuencia |
| CAP0142–CAP0144 | P01 panel fijo: alto, medio, bajo | [120,420) s |
| CAP0145–CAP0147 | AP a 1 m con antenas originales: bajo, medio, alto | Archivo completo de aproximadamente 300 s |

## Reproducción

```bash
python -m silueta.controlled --out results/controlled
```

Genera `pos02.csv`, `robot.csv`, `power.csv`, puntuaciones por muestra,
`events.json`, cinco gráficas PNG y `validation.json`. La comprobación falla si
no coinciden los 254 valores de `controlled-reference-results.json`, extraídos
de los análisis originales. Los estimadores usan los CSV, no esos resultados
de referencia. Tolerancias: rtol=2e−6, atol=2e−9, por redondeo de ángulos a nueve
cifras significativas. No se mezclan configuraciones. Los huecos quedan como
NaN y no se sustituyen por ceros. `--no-figures` omite solo las imágenes.

## POS02

Se mantiene el detector de P-R03, sin recalibrarlo: ventana causal de 6 s,
al menos cuatro informes, hueco máximo de 2,8 s incluyendo bordes, varianza
poblacional de ψ por componente y media entre componentes. El umbral es
0,006820114055593958 rad². Dos puntuaciones superiores consecutivas activan;
dos inferiores o iguales cierran; una ventana inválida reinicia el estado.
Se descartan los primeros seis segundos del intervalo útil como calentamiento.

Las salidas pautadas son 150, 200, 250, 300 y 350 s. Solo se asocia una **nueva**
activación en [salida,salida+20); una alarma que ya estaba abierta no cuenta
como otra detección. No se conocen cruces ni llegadas exactos. Las líneas de
salida se dibujan exclusivamente en recorridos, nunca en quietud o vacío.

Balance: 28/30 salidas principales con nueva activación; una en los seis
recorridos laterales y dos episodios en dieciocho controles estáticos, ambos
en el vacío final de S03. Las tres sesiones son repeticiones; no se presentan
como una precisión validada ni como localización exacta.

## Robot

Cada sesión contiene vacío inicial, preparación de dos minutos, primera limpieza,
vacío posterior y segunda limpieza. El robot pasa por la zona, pero no se conoce
el instante de entrada ni se garantiza una trayectoria idéntica entre ensayos.
Se descartan los seis primeros segundos de cada fase al comparar sus puntuaciones.

Se estudian por separado la varianza lineal de ψ y la circular de φ,
`1 - |media(exp(iφ))|`, promediadas entre componentes. Se calculan medianas,
P95, máximos y un control con cinco informes consecutivos en no más de ocho
segundos. El umbral humano se conserva como referencia: la diferencia de nivel
entre robot y vacío no requiere abrir una alarma de ese detector.

Las dos sesiones no sostienen un identificador universal de robot. La magnitud
y estabilidad de las diferencias dependen del recorrido y del canal. Se publican
ambas repeticiones y los controles, sin seleccionar únicamente la más favorable.

## Potencia

En P01, sin mover el panel, se reciben 211/212/207 BFI con ajuste alto/medio/bajo.
El RSSI mediano de sus tramas es −72 dBm en los tres casos. El del AP cambia
−64/−68/−71 dBm. Se observan 221/220/222 NDPA unicast dirigidos a C01; son
sondeos observados, no un denominador que permita afirmar captura completa.

A un metro, con antenas originales, las balizas del AP dan medianas de
−23/−27/−34 dBm en alto/medio/bajo. Son medidas recibidas por la sonda, no
potencias transmitidas calibradas ni EIRP. Las geometrías y antenas son distintas;
la gráfica compara cambios dentro de cada montaje, no amplitudes entre montajes.

Reducir potencia del AP no impide captar BFI emitidos por C01 en P01. Este ensayo
no mide el alcance máximo ni prueba equivalencia de los valores angulares o de
las inferencias posibles. Los PCAP completos siguen siendo privados.
