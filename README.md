# SILUETA

**Sensado Wi-Fi pasivo mediante informes de beamforming.** GUI con consentimiento local obligatorio · `v1.0-aepd2026` (publicación revisada).

Autores: **Manuel Solana, Héctor Rodríguez y Francisco José Amo**.

SILUETA decodifica informes comprimidos, calcula variaciones angulares y muestra
ψ y φ en una GUI local mientras llegan las muestras. Incluye análisis de CSV,
histórico navegable, recepción de varios enlaces autorizados en un mismo canal,
pruebas sintéticas y datos derivados de campañas controladas terminadas.

Es instrumentación experimental. Una variación del canal no identifica por sí sola
personas, presencia, actividad ni respiración. La disponibilidad y cadencia de los
informes dependen del AP, del cliente y del receptor. La referencia gráfica de
movimiento es orientativa y requiere calibración para cada montaje.

## Instalación

Backend Linux, Python 3.11 o posterior. GUI en cualquier navegador moderno.
Para radio: adaptador compatible con modo monitor, `iw`, `tcpdump`, `tshark` y
permisos locales. Se ha utilizado una ALFA AWUS036ACM; no es necesaria para la demo.

```bash
git clone https://github.com/solsamanu-cloud/silueta-aepd2026.git
cd silueta-aepd2026
git checkout v1.0-aepd2026
# Fedora:
sudo dnf install python3 python3-pip wireshark-cli tcpdump iw NetworkManager
# Ubuntu/Debian, alternativa:
# sudo apt install python3-venv tshark tcpdump iw network-manager
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

La integración completa de la GUI y la demo está verificada con **TShark 4.6.7**.
Instalar el paquete de Ubuntu LTS puede proporcionar 4.2.2 y no garantiza todos
los campos HT/HE utilizados. `python bin/check-dependencies.py` comprueba los campos
reales; la GUI informa antes de pedir permisos si es necesario actualizar.
Las pruebas externas se **omiten con motivo explícito** si falta tshark/tcpdump o
algún campo requerido. Una omisión no acredita que esa integración funcione.
Los análisis de CSV y las pruebas numéricas no necesitan esas herramientas.
No se modifica la regulación radio ni se instala firmware alterado.

## Primero: demo sin radio y pruebas

```bash
.venv/bin/python -m unittest discover -s tests -v
bash bin/demo.sh
```

Abre **http://127.0.0.1:8798/** y pulsa **Iniciar captura**. La banda amarilla indica
reproducción. Los paquetes se generan desde cero con direcciones sintéticas;
la oscilación de demostración es de 0,23 Hz y no procede de una persona.
La demo dura tres minutos. No necesita `sudo` ni usa la antena.

Las pruebas incluyen vectores angulares conocidos HT/VHT/HE, orden de matrices,
fragmentos, estadística circular, cambio de configuración, protección de radio,
persistencia, filtros libpcap y varianza que llega antes de cerrar la reproducción.
Ninguna prueba necesita PCAP privados ni transmite paquetes por radio.

## Captura real consentida

Primero abre `.venv/bin/python live/server.py --port 8798` y visita
**http://127.0.0.1:8798/authorization**. Declara tu AP, clientes e interfaz, y
marca expresamente el consentimiento. Guardar no inicia la radio. Para capturar,
cierra ese servidor de consulta, activa el modo monitor y ejecuta `bash bin/gui.sh`.
Ese lanzador solicita sudo en tu terminal; no introduzcas la contraseña en la web.
La alternativa CLI equivalente se muestra debajo. Esta distribución solo incluye la GUI con consentimiento. Una sola ALFA no puede
dedicarse a esta aplicación y a otra captura que resintonice la radio a la vez.

Consulta [protección desde el diseño](docs/PRIVACIDAD-DISENO.md) para el alcance
del filtro, las exclusiones de protocolo y las pruebas en el núcleo.

Configura **tu propio AP y únicamente los clientes autorizados**. Estas direcciones
son ejemplos sintéticos: sustitúyelas localmente. La declaración `local/authorization.json` se excluye de Git. No se necesita la contraseña Wi-Fi.

```bash
iw dev
.venv/bin/python bin/configure.py --interface wlan1 \
  --ap 02:00:00:00:00:06 --client C01=02:00:00:00:00:01 \
  --client C02=02:00:00:00:00:02 \
  --ssid "Nombre de tu red" --consent
sudo .venv/bin/python bin/monitor-mode.py
bash bin/gui.sh
```

La declaración local y el filtro de enlaces son obligatorios también desde la API y el servicio continuo.

El canal, ancho y centro se obtienen automáticamente de las balizas del AP
declarado en cada inicio. No se rellenan en la GUI ni en el configurador CLI.
El SSID permite comprobar el nombre esperado; el BSSID mantiene la identidad
exacta autorizada, incluso en redes con el mismo nombre. La búsqueda inicial
es pasiva y solo admite balizas de ese AP, después del consentimiento. Si no
se encuentra o anuncia un ancho no compatible (160/80+80 MHz), la captura se
bloquea sin usar un canal supuesto. «Actualizar» explora los canales permitidos conservando el histórico,
pero el filtro de adquisición solo acepta el AP y clientes configurados. Una radio
escucha un canal a la vez; un barrido interrumpe la medida continua de ese canal.
No puede escanear o resintonizar mientras el servicio protegido está capturando.

En la GUI: selecciona el enlace, inicia la captura, ajusta la media móvil, consulta
los valores con el cursor y desplázate por el histórico. «Detener y guardar» cierra
los archivos. El navegador puede cerrarse; en modo interactivo el terminal debe
seguir abierto y Linux despierto. Para restaurar la interfaz:

```bash
sudo .venv/bin/python bin/monitor-mode.py --restore-managed
```

## Despliegue y acceso

El servidor escucha exclusivamente en loopback. No se publica en Internet.
Desde otro ordenador, abre un túnel SSH con **tu alias de conexión**:

```bash
ssh -N -L 8798:127.0.0.1:8798 HOST_SSH
```

Después abre http://127.0.0.1:8798/ en ese ordenador. Si el puerto está ocupado,
reutiliza el servidor correcto o ejecuta `bash bin/gui.sh 8789` y cambia también
el puerto del túnel. El script no mata procesos ajenos.

Para monitorización multienlace independiente del terminal, tras configurar y
activar monitor:

```bash
bash bin/monitor.sh
systemctl status silueta-consent-monitor --no-pager
# Consulta sin tocar la radio (no necesita sudo):
.venv/bin/python live/server.py
# Cuando quieras parar, desde la raíz del repositorio:
touch state/continuous-monitor.stop
```

En **/services** puedes consultar la monitorización activa y todo su histórico.
El servicio recibe simultáneamente los enlaces autorizados del **mismo canal**,
guarda series independientes y rota el PCAP en partes de 256 MiB. Se detiene con
guardado cuando quedan menos de 10 GiB libres. No arranca automáticamente después
de reiniciar Linux. La web de consulta también puede ejecutarse como servicio
de usuario; su cierre no detiene `silueta-consent-monitor`.

## Relación entre módulos

| Entrada | Función y destino |
|---|---|
| `bin/configure.py` | Configuración local y lista explícita de enlaces autorizados |
| `bin/monitor-mode.py` | Modo monitor y sintonía, con protección de capturas existentes |
| `bin/gui.sh` → `live/server.py` | Adquisición incremental, API local y eventos SSE para la GUI |
| `bin/monitor.sh` → `bin/monitor.py` | Servicio multienlace, rotación, histórico SQLite y estado consultable |
| `live/feedback.py` + `live/engine.py` | Decodificador unificado usado por GUI y exportador; ventanas por formato/sentido |
| `lib/` | Utilidades de matrices, series y análisis espectral |
| `silueta.export` | PCAP privados + mapa privado → CSV seudonimizados + MANIFEST |
| `silueta.analyze` | CSV → detector y espectro detrendido agregado |
| `silueta.controlled` | CSV → tablas y gráficas de POS02, robot y potencia |
| `silueta.controlled_export` | Mapa privado → ángulos y metadatos mínimos del enlace propio |
| `silueta.synthetic` | Generador reproducible de paquetes de prueba; sin datos capturados |
| `live/static/` | GUI, media móvil, tooltips, archivo y vista de servicios |

ψ usa varianza lineal en rad²; φ usa varianza circular `1 − |media(exp(iφ))|`,
entre 0 y 1. La ventana causal es de 6 s. Se muestran todas las muestras y se
marca calidad limitada si hay pocas observaciones o huecos; una varianza cero
con una sola muestra no prueba quietud. No se mezclan matrices de distinta
configuración o sentido. La media móvil es solo una ayuda visual.

Se admiten informes comprimidos HT y VHT SU/MU, y HE con ángulos interpretables
por tshark, dentro de los formatos validados. EHT, HT no comprimido, informes
fragmentados y HE MU Ng16 no se convierten a ángulos. Un informe **HE** puede viajar
en un PPDU legacy; eso es distinto de recibir un **PPDU HE**, que la AWUS036ACM
802.11ac no demodula. Ausencia de informes observados no demuestra ausencia de
sondeo o de exposición.

## Datos publicados y reproducción

[Catálogo](data/catalog.csv) · [MANIFEST](data/MANIFEST.csv) ·
[Diccionario](docs/DATA.md). Solo campañas controladas terminadas C01–C05/AP01.
No incluye jornadas domésticas, clientes ajenos, ensayos descartados ni sesiones
activas. Los nombres públicos CAP0001, etc. no contienen fecha ni hora.

```bash
.venv/bin/python -m silueta.analyze data/captures/CAP0001.csv \
  --out results/example --start 0
.venv/bin/python bin/verify-manifest.py
```

Usa `--start` y `--end` con el intervalo útil del catálogo (por ejemplo 120 y 420).
`peaks.csv` contiene el máximo del periodograma agregado tras retirar tendencia
lineal por componente: **0,05–0,35 Hz, 901 frecuencias**. No promedia periodogramas
normalizados individualmente. Un pico no prueba respiración ni descarta aliasing.

Para recalcular las tablas controladas y contrastarlas con los resultados originales:

```bash
.venv/bin/python -m silueta.reproduce --out results/reproduction
```

El detector usa P99,5 = **0,006820114055593958 rad²**, dos puntuaciones consecutivas
y nuevas activaciones en los 20 s posteriores a cada salida pautada. Consulta
[el método exacto](docs/METODO-presencia.md) y [las tablas y límites de reproducción](docs/REPRODUCIBILIDAD.md).
El suplemento controlado permite además reproducir POS02, robot y potencia con CSV
de ángulos y protocolo. Las jornadas privadas y las tablas históricas de capacidades
no se regeneran con esta distribución.

## Campañas controladas incorporadas

La publicación reúne **147 PCAP privados representados por sus huellas**: los
105 ensayos anteriores y 42 adicionales. Son 30 capturas de POS02 en tres
sesiones, seis del robot (ocho fases útiles) y seis de potencia del AP (tres en
P01 y tres referencias a 1 metro). No se publican las noches ni jornadas domésticas.

```bash
.venv/bin/python -m silueta.controlled --out results/controlled
```

Genera tablas, episodios y cinco gráficas: recorridos y controles POS02, ψ y φ
del robot, y comparación de potencia. No requiere radio, TShark ni los originales.
Contrasta automáticamente 254 valores con los informes originales. Los datos,
ventanas y límites se explican en [el suplemento](docs/ENSAYOS-CONTROLADOS.md).

El ensayo de potencia conserva 211/212/207 BFI en P01 con nivel alto/medio/bajo;
el RSSI mediano de C01 es −72 dBm en las tres tomas. La señal del AP sí disminuye.
Esto demuestra recepción conservada en el punto probado, no alcance máximo idéntico.

Esta etiqueta y `main` se han sustituido para publicar la GUI consentida y completar los ensayos controlados. La publicación contiene un único commit. Si ya la
habías descargado, guarda tus cambios locales y actualiza la referencia de etiqueta:

```bash
git fetch origin +refs/tags/v1.0-aepd2026:refs/tags/v1.0-aepd2026
git checkout v1.0-aepd2026
```


Para regenerar desde PCAP propios, proporciona un mapa **privado fuera del repo**:

```bash
.venv/bin/python -m silueta.export --private-map /ruta/privada/mapa.json --out datos-derivados
.venv/bin/python bin/verify-manifest.py --private-map /ruta/privada/mapa.json
```

El esquema del mapa se documenta en [DATA.md](docs/DATA.md). El exportador aplica
el enlace indicado, elimina identificadores y desplaza el tiempo al primer
paquete de la captura. Nunca copia PCAP al destino.

El SHA-256 publicado es un compromiso de integridad: quien disponga posteriormente
del original puede verificar que coincide. **El hash por sí solo no demuestra la
fecha, la procedencia ni la existencia previa del archivo**, y no prueba quién
estaba presente. La comprobación del original requiere acceso privado al PCAP.

## Uso responsable y doble uso

Utiliza SILUETA solo en redes propias o expresamente autorizadas, con consentimiento
de las personas observadas y sin captar ni conservar tramas ajenas. Configura la
lista de enlaces antes de capturar y comprueba que el ensayo queda dentro de ese
ámbito. El filtro libpcap se aplica antes del almacenamiento y del análisis; no
impide que la antena reciba energía radioeléctrica de otras redes.

La misma técnica puede ayudar a evaluar exposición y también facilitar inferencias
no consentidas. No se incluyen diarios personales, redes de terceros, técnicas
de desautenticación, inyección, recuperación de claves ni descifrado de contenido.
Los metadatos y las series temporales pueden ser sensibles incluso sin MAC u hora
real: **seudonimizar no equivale a garantizar anonimato**. Limita acceso, finalidad
y conservación de los datos locales. No utilices resultados como diagnóstico
médico, identificación personal o prueba concluyente de ocupación.

## Licencia y referencias

Código y CSV incluidos: [MIT](LICENSE). Las dependencias conservan sus licencias;
Wireshark/tshark se instala por separado y no se redistribuye aquí. Las referencias
técnicas usadas para contrastar campos y fórmulas aparecen en el código y en la
GUI. No se incluyen documentos Word, fotografías ni material ajeno a esta versión.
