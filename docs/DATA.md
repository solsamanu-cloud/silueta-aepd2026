# Diccionario y alcance

Cada `data/captures/CAPxxxx.csv` corresponde a un PCAP privado de un ensayo
controlado terminado. Solo se exporta el enlace Cxx–AP01 elegido, en ambos sentidos.
Los paquetes ajenos que pudiera contener el PCAP original no se exportan.

| Campo | Significado |
|---|---|
| `t_rel_s` | Segundos desde el inicio definido por el ensayo, no desde la primera BFI; véase suplemento |
| `client`, `ap` | C01–C05 y AP01; el código indica el enlace, no necesariamente el transmisor |
| `direction` | `client_to_ap` o `ap_to_client` |
| `format`, `feedback` | HT/VHT/HE y SU/MU |
| `Nr`, `Nc`, `Ng` | Filas, columnas y agrupación efectiva, no el índice codificado |
| `bandwidth_mhz`, `codebook`, `bits_psi` | Configuración de la matriz y cuantificación |
| `subcarriers` | Número de subportadoras representadas en el informe |
| `series_id` | Huella de configuración y sentido; no contiene MAC, hora ni SSID |
| `psi_0000_rad`, … | Valores ψ descomprimidos en radianes, orden subportadora → columna de matriz → fila |

Dentro de una subportadora, para cada columna c se ordenan ψ por fila r=c+1…Nr.
Los campos vacíos al final de una fila indican componentes inexistentes para esa
configuración; **no son ceros**. Las series distintas se analizan por separado.
Los CSV sin informes decodificables contienen solo la cabecera. El catálogo
distingue informes observados, filas decodificadas e informes rechazados. No se
deduce ausencia de exposición de una tabla vacía. No se eliminan silenciosamente
reintentos del exportador; el análisis debe tratar tiempos duplicados por separado.

El catálogo contiene protocolo, condición, preparación y duración prevista, sin
calendario. `availability` compara estados de tráfico; `movement`, controles y
recorridos; `breathing-paced`, respiración pautada; `range`, alcance exterior.
`t0` = sin tráfico deliberado; `t1` = vídeo; `r0` = bloque de respiración;
`vacio` = control; `quieto-e1/e2` = quietud en extremos; `principal/recorrido` =
trayecto principal; `lateral` = trayecto lateral; `r01/r02/r03` = repetición;
`s01/s02/s04` = bloque experimental, sin fecha; `pr01/pr02/pr03` = configuración
geométrica. `omni` usa antenas originales; `panel-orientb` usa panel reorientado.
Los códigos de sesión no implican continuidad de tiempo entre capturas.

Se conserva toda la duración capturada, incluida preparación cuando corresponde.
La duración prevista se toma del protocolo. El origen es el primer paquete recibido,
que puede diferir ligeramente del instante de lanzamiento del comando. No se
publican coordenadas, horas, rutas originales, diarios, SSID ni direcciones. El
suplemento CAP0106–CAP0147 sí incluye RSSI del enlace propio y de balizas de AP01.

## Mapa privado de regeneración

Lista JSON con estos campos por ensayo (ejemplo completamente sintético):

```json
[
  {
    "capture_id": "CAP0001",
    "source": "/ruta/privada/original.pcap",
    "client_mac": "02:00:00:00:00:01",
    "ap_mac": "02:00:00:00:00:06",
    "client": "C01",
    "protocol": "movement",
    "condition": "vacio-r01",
    "preparation_s": 120,
    "duration_s": 420
  }
]
```

Ese mapa **no se publica**. El MANIFEST solo contiene el alias de captura,
SHA-256 del original, ruta relativa del CSV y SHA-256 del CSV. Los originales se
leyeron sin modificarlos; no hay PCAP reales, copias de PCAP ni muestras de bytes
extraídas de ellos en el repositorio. Las pruebas generan paquetes sintéticos
con MAC localmente administradas `02:00:00:00:00:xx`.

## Referencias de reproducción

`reference-results.json` contiene cifras de los informes originales, vinculadas solo
a CAPxxxx. Sirve para comprobar el cálculo, no como entrada del estimador. No
contiene MAC, horas reales ni rutas de los originales. Véase REPRODUCIBILIDAD.md.

## Suplemento CAP0106–CAP0147

Además de ψ, los CSV angulares incluyen `phi_XXXX_rad`, `bits_phi` y `rssi_dbm`.
φ se analiza con estadística circular; sus valores están en radianes. La cabecera
sin filas de CAP0145–CAP0147 indica capturas de balizas, no ausencia de señal.

`data/protocol/CAPxxxx.csv` contiene tiempo relativo, tipo (`beacon`, `bfi`,
`ndpa`), emisor/receptor seudonimizados, RSSI máximo de las cadenas radiotap,
indicador de reintento y tasa legacy cuando está disponible. No contiene cuerpos
binarios, direcciones ni contenido de usuario. Son solo balizas del AP propio,
BFI VHT C01→AP01 y NDPA unicast AP01→C01. No constituye un inventario del canal.

Cada archivo derivado tiene una fila en MANIFEST. Dos filas pueden compartir
CAP y hash del original: corresponden a ángulos y protocolo del mismo PCAP.
En total: 147 originales y 189 CSV derivados verificados. Los resultados de
referencia son comprobaciones independientes, no la entrada del estimador.

En POS02 y robot, el origen es el primer paquete del PCAP. En CAP0142–CAP0144,
es el lanzamiento del capturador portátil, para reproducir exactamente [120,420)
del protocolo original. El parámetro opcional `origin_epoch` queda solo en el
mapa privado; nunca se exporta. En las referencias a un metro se usa todo el
archivo: una captura nominal de 300 s puede terminar unas décimas después.

`controlled-tests.json` define fases relativas y códigos S01/S02/S03, sin fechas.
El caso mixto del robot contiene vacío [0,300), transición [300,420) y robot
[420,720). Los otros dos archivos por sesión contienen [120,420) útil.

Regeneración del suplemento desde un mapa privado (mismo esquema anterior):

```bash
.venv/bin/python -m silueta.controlled_export --private-map /ruta/privada/suplemento.json --out suplemento
```
