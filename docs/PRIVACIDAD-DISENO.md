# Adquisición limitada a enlaces declarados

Esta distribución de SILUETA implementa la limitación de adquisición propuesta en 8.6.
Integra el decodificador y los análisis de la versión anterior con autorización obligatoria.
No modifica la aplicación de laboratorio ni reutiliza sus configuraciones,
históricos, servicios o capturas. Puerto por defecto: **8798**.

## Antes de la captura

La GUI abre `/authorization` hasta que existe una declaración local válida:
interfaz, BSSID del AP propio, lista de clientes autorizados y confirmación
expresa de consentimiento. La casilla empieza desmarcada incluso al editar una
declaración anterior. El servidor exige el booleano `true`; un texto, una
petición incompleta o el antiguo `AUTHORIZED_CAPTURE=yes` no autorizan.
La alternativa CLI `bin/configure.py --consent` aplica la misma validación.

La declaración se guarda atómicamente en `local/authorization.json`, con permisos
0600 y directorio 0700. Incluye fecha local de aceptación en formato UTC, versión
del aviso y alcance. Se excluye de Git. No requiere contraseña Wi-Fi; el SSID es opcional para contrastar el nombre de la red.
Los manifiestos de captura guardan la declaración, su huella y el filtro efectivo
para poder auditar el alcance de cada sesión. También son privados.

## Antes del almacenamiento y del análisis

`live/policy.py` construye el filtro libpcap y los comandos de adquisición. Tanto
la captura interactiva como el barrido y el servicio continuo usan esa lista
cerrada. En Linux, tcpdump/libpcap aplica el BPF en el núcleo antes de entregar
paquetes por stdout; solo ese flujo filtrado se guarda y se envía a TShark.
No hay un reintento sin filtro si la expresión o el capturador fallan.

Se admiten:

- Gestión unicast entre AP y cliente autorizado, con BSSID del AP declarado.
- Datos del mismo par con dirección ToDS/FromDS de infraestructura correcta.
- Control con receptor y transmisor que identifican ese par autorizado.
- Balizas de difusión con transmisor y BSSID del AP propio.

Se excluyen otros clientes, otros AP, sondeos de difusión, datos multicast,
WDS y tramas de control sin dos direcciones atribuibles al par, como ACK/CTS.
También se excluyen NDPA de grupo: no se incorporan excepciones para obtener
más informes a costa de ampliar el ámbito. Por tanto, una ficha de protocolo
puede quedar incompleta y no equivale a una captura exhaustiva del canal.

El filtro identifica **extremos radio**. Una trama de datos autorizada puede
llevar direcciones de la red cableada en otros campos; no se afirma que todos
los bytes del PCAP estén anonimizados. Las balizas propias pueden contener el
SSID del AP. Los PCAP siguen siendo privados.

## Cambios y revocación

Capturas y barridos mantienen un bloqueo compartido de la declaración. La GUI
y el configurador CLI requieren un bloqueo exclusivo para modificarla o
revocarla. Debe detenerse primero la adquisición; no se cambia el filtro de una
sesión en marcha. Revocar bloquea nuevas adquisiciones, sin borrar el histórico.
La selección de cliente y los endpoints HTTP vuelven a validar el alcance.
El servidor escucha en loopback y protege las mutaciones con token y comprobación
de Host/Origin. No debe exponerse directamente en Internet.

## Alcance de la garantía

La radio recibe físicamente señales del canal: se limita su entrega a la
aplicación, no la propagación electromagnética. Las MAC no son autenticación
criptográfica y pueden suplantarse. El programa registra una declaración del
operador; no verifica propiedad ni sustituye obtener el consentimiento de las
personas. Una persona no participante puede modificar el canal de un enlace
autorizado. El control de enlaces reduce la adquisición, pero no garantiza por
sí solo que todo posible efecto de terceros quede fuera del sensado.

## Verificación reproducible

```bash
.venv/bin/python -m unittest discover -s tests -v
```

`tests/test_consent.py` verifica denegación por defecto, consentimiento explícito,
validación de direcciones, permisos, revocación, bloqueo concurrente y peticiones
API que intentan saltarse la GUI. Compila la expresión con libpcap y la instala
realmente con `SO_ATTACH_FILTER` en un socket de prueba de Linux. Envía tramas
radiotap sintéticas y comprueba aceptación o rechazo en el núcleo. Esta prueba
no usa antena, permisos elevados ni tramas de otras personas. Se omite con motivo
explícito cuando no hay Linux/libpcap; una omisión no valida esa integración.

La demo reproduce exclusivamente el fichero sintético generado por `bin/demo.sh`;
no habilita la radio ni crea consentimiento para capturas reales.

## Canal automático a partir de la red declarada

La GUI solo pide el nombre de la red (opcional), su BSSID, los clientes y la
interfaz. No pide frecuencia, ancho ni centro. Antes de cada captura, ya con
consentimiento, `live/autotune.py` busca pasivamente las balizas del BSSID
declarado en los canales que permite el controlador. Ese barrido usa un filtro
del núcleo todavía más restrictivo: solo las balizas propias; no guarda PCAP.
Lee los elementos DS/HT/VHT de operación, fija y verifica la sintonía y entonces
comienza la medida. Un SSID igual de otro BSSID no se acepta. Un SSID oculto
se identifica por el BSSID previamente declarado. Un nombre visible que no
coincida con el declarado bloquea el inicio.

El resultado se guarda como metadato privado en `local/radio-detected.json` y
en la ficha de la sesión. La caché solo sirve para presentación; cada nueva
captura vuelve a buscar una baliza. Sin detección válida no se usa el canal
provisional. Esta versión ajusta 20/40/80 MHz; ante 160/80+80 MHz informa de la
incompatibilidad. El servicio continuo usa también el canal detectado.
