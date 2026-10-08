# Validación del fork de consentimiento

Validación en Linux, 7 de octubre de 2026:

- 134 pruebas superadas, incluidas las pruebas de decodificación y análisis existentes.
- Detección automática de canal y ancho a partir de balizas sintéticas: 20, 40 y
  80 MHz, identificación por BSSID, contraste del SSID, cancelación y rechazo de
  formatos no compatibles. Integración comprobada con TShark y sin radio real.
- 17 casos de aceptación/rechazo de tramas sintéticas, con filtro compilado por
  libpcap y aplicado mediante SO_ATTACH_FILTER en el núcleo de Linux.
- API: rechazados inicio sin declaración, consentimiento falso y petición sin
  token. Rechazada revocación durante captura. Guardado y revocación en reposo correctos.
- Bloqueo de cambios de alcance durante adquisición, permisos privados y escritura atómica.
- Interfaz comprobada a 1440 y 390 píxeles: sin errores JavaScript ni desbordamiento
  horizontal, AP sin rellenar y consentimiento desmarcado.
- Sin usar radio, PCAP privados ni declarar consentimiento para equipos reales.

La prueba de socket evalúa el filtro en el núcleo con bytes radiotap sintéticos;
no es una prueba de recepción con una ALFA física. La recepción real depende del
controlador, los permisos y la sintonía de la interfaz. Se conserva la protección
contra resintonizar una interfaz que otra captura esté utilizando.
