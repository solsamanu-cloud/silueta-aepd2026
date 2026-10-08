# Auditoría de la publicación con consentimiento obligatorio

Alcance: código, GUI, documentación, pruebas sintéticas y datos derivados de
campañas controladas terminadas. Esta publicación sustituye `v1.0-aepd2026` por
petición expresa del autor. Se prepara desde cero, con un único commit público,
sin copiar el historial privado. La versión anterior se conserva en una copia
privada de recuperación. Git usa el correo noreply de GitHub antes del commit.

## Datos y reproducción

- **147 originales privados** representados por SHA-256: 105 ensayos anteriores
  y 42 adicionales (30 POS02, seis de robot y seis de potencia).
- **189 CSV derivados**: 147 de ángulos y 42 de protocolo mínimo. Los CSV sin
  informes se conservan con cabecera; no se inventan muestras ni varianzas.
- Solo los códigos C01–C05/AP01 y CAPxxxx, con tiempos relativos. No se publican
  MAC, SSID, BSSID, fechas de captura ni horas del diario.
- En el suplemento se añaden φ y RSSI para reproducir el robot y la comparación
  de potencia. El diccionario distingue lo disponible en cada conjunto.
- Los hashes del MANIFEST se verificaron contra los **189 CSV y 147 originales**.
- `silueta.reproduce` verifica **404 cifras** históricas (37 filas de movimiento
  y 22 espectros) y genera 148 filas de calidad al recorrer el catálogo ampliado.
- `silueta.controlled` verifica **254 cifras** independientes de POS02, robot y
  potencia y genera tablas y cinco gráficas. Ambos análisis usan solo CSV públicos.
- Ninguna jornada doméstica, noche, captura activa, ensayo descartado, cliente
  ajeno, PCAP, imagen, documento ofimático o base de datos privada se incluye.

## Pruebas y compatibilidad

- **139 pruebas, sin fallos ni omisiones**, en Linux con TShark **4.6.7**. Incluyen
  consentimiento obligatorio en GUI/API/servicio, filtro libpcap en el núcleo,
  búsqueda pasiva de balizas del AP autorizado, decodificación, conservación del
  histórico, estadística circular y ventanas con huecos.
- **139 pruebas, sin fallos, seis omitidas con motivo**, en Ubuntu 24.04 / Python
  3.12 / TShark **4.2.2**, en un contenedor independiente. Esa versión no admite
  la extracción `@wlan.mimo.csimatrices.cbf` requerida por ciertas integraciones.
  Se comprueba la sintaxis sobre paquetes sintéticos, además del registro de campos.
- Sin tshark ni tcpdump en PATH: **134 pruebas contabilizadas, sin errores, 11
  omisiones informadas**. La cifra cambia porque un bloque completo de parser se
  omite al descubrir los tests. Las pruebas numéricas siguen ejecutándose.
- Una prueba omitida no significa que esa integración haya sido validada. El
  README exige comprobar dependencias y distingue análisis CSV de captura real.
- No se hizo una nueva captura física durante la publicación: las pruebas de
  adquisición usan paquetes sintéticos y no interfieren con la instalación privada.

## Privacidad de los archivos publicados

1. **Gitleaks 8.30.1** sobre la carpeta nueva y el único commit público, con salida
   redactada. Sin secretos detectados. El informe detallado permanece privado.
2. Búsqueda de MAC con `([0-9a-f]{2}[:-]){5}[0-9a-f]{2}`, también en literales
   de bytes y sin separadores. Solo se admiten direcciones sintéticas
   `02:00:00:00:00:xx`, nula y broadcast en los vectores y validadores.
3. Búsqueda de identificadores de los originales, SSID y valores sensibles de la
   configuración local, usuario y rutas privadas, correos e IP de la LAN.
   Sin coincidencias privadas. Las IPv4 de texto son loopback y números de
   apartados técnicos; no direcciones de la instalación.
4. Revisión de todos los CSV para excluir marcas de tiempo absolutas. Los orígenes
   y recortes de cada protocolo están documentados; no se publican los diarios.
5. **ExifTool** sobre los archivos de publicación: sin metadatos incrustados de
   autor, comentarios sensibles o GPS. No hay medios ni documentos ofimáticos.
6. Autores explícitos autorizados: **Manuel Solana, Héctor Rodríguez y Francisco
   José Amo**, uniformes en README, AUTHORS, licencia MIT y GUI.

El mapa CAPxxxx → original y los registros de auditoría quedan fuera del
repositorio porque contienen rutas privadas. Eliminar identificadores y horas
reduce exposición, pero no garantiza anonimato de las series. La auditoría se
refiere a esta publicación, no a futuras modificaciones.

La GUI requiere una declaración local expresa antes de capturar; solo admite
los enlaces autorizados y las balizas del AP propio mediante filtro libpcap.
La declaración no se envía a GitHub ni se incluye en Git. El alcance y los límites
de esta protección se documentan en `PRIVACIDAD-DISENO.md`.
