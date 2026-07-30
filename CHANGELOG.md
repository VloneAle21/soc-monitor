# Registro de cambios

Todos los cambios relevantes del proyecto se documentan en este fichero.
El formato sigue [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/)
y el versionado se ajusta a [SemVer](https://semver.org/lang/es/).

## [2.1.0] — 2026-07-30

De «correcta» a «desplegable». La 2.0.0 arregló la lógica de detección; esta
versión cubre los huecos que impedían usarla de verdad en un servidor.

### Añadido

- **Soporte de IPv6.** Hasta ahora los regex eran sólo IPv4, así que un ataque
  desde `2001:db8::dead:beef` se descartaba **en silencio**: en cualquier
  máquina con IPv6 activado esos intentos sencillamente no existían. Se
  reconocen la forma comprimida, las direcciones IPv4 mapeadas
  (`::ffff:203.0.113.5`) y el identificador de zona (`fe80::1%eth0`).
  La validación la hace `ipaddress`, no un regex, así que las direcciones se
  guardan en forma canónica y `2001:0db8::0001` correlaciona con `2001:db8::1`.
- **Lista blanca `--excluir`**, con direcciones sueltas y redes CIDR de ambas
  familias. Sin ella, la VPN del equipo o el servidor de integración continua
  aparecen como atacantes. Los orígenes de confianza se descartan antes de
  llegar a los detectores, así que tampoco consumen memoria.
- **Entrada estándar.** `journalctl -u ssh -f | soc-monitor analizar -` ya
  funciona, leyendo línea a línea para que las alertas salgan en el momento.
  En distribuciones con systemd puro puede no existir `auth.log`.
- **Salida por webhook** (`--webhook`), compatible con Slack, Discord, Teams y
  receptores genéricos. Sólo acepta `http`/`https`, recorta los eventos de
  contexto y, si el destino está caído, registra un aviso sin interrumpir el
  análisis.
- **Unidad systemd** endurecida en `deploy/soc-monitor.service`.
- **Animación de terminal** en el README, generada por `tools/generar_demo.py`
  a partir de la salida real de la herramienta. La CI la regenera y falla si se
  ha quedado desfasada, de modo que la imagen no puede mentir.
- **Lint y formato con ruff**, comprobados en CI, más verificación de que el
  paquete se instala y el ejecutable arranca.
- 35 pruebas nuevas (87 en total).

### Decisión consciente

No se persiste el estado entre reinicios. Las ventanas duran entre 30 y 120
segundos, así que un reinicio cuesta como mucho dos minutos de contexto;
guardarlo supondría un fichero de estado con su corrupción y su migración a
cambio de muy poco.

## [2.0.0] — 2026-07-30

Revisión completa de la lógica de detección. Los recuentos que aparecían en las
alertas de la 1.0.0 no eran fiables, así que esta versión rompe compatibilidad
con el formato de salida anterior.

### Corregido

- **Los detectores contaban eventos ajenos.** Todos los eventos de una IP
  entraban en la ventana de todos los detectores, y sólo después se comprobaba
  el texto del último. Cuatro conexiones cerradas más un fallo de contraseña
  producían una alerta que anunciaba «5 intentos fallidos». Ahora el parser
  clasifica cada evento (`EventKind`) y cada detector filtra con `matches()`
  **antes** de almacenar, de modo que el número que aparece en la alerta es
  exactamente el número de eventos relevantes.
- **El silenciamiento de alertas no caducaba.** El registro de parejas
  (detector, IP) era permanente: una IP que atacaba a las 10:00 no volvía a
  generar alerta nunca más. Ahora caduca a los 300 s, configurable con
  `--enfriamiento`.
- **`PortScanDetector` ignoraba su propia ventana temporal.** El conjunto de
  puertos crecía sin límite y nunca se purgaba: fuga de memoria y puertos de
  hace horas contados como parte del barrido actual. Sustituido por una serie
  temporal podada con la misma ventana que el resto del detector.
- **El seguimiento en tiempo real no soportaba la rotación de logs.** Tras un
  `logrotate` el proceso seguía leyendo el fichero antiguo y dejaba de ver
  eventos sin dar ningún aviso. Ahora se detecta el cambio de inodo y el
  truncado, y el fichero se reabre solo.
- **`analizar` sin argumentos abortaba con un `TypeError`.** Ahora muestra un
  mensaje de uso claro y devuelve el código de salida 2.
- **Marcas de tiempo.** El año se deduce correctamente en el cambio de año
  (una línea de diciembre leída el 1 de enero ya no se fecha en el futuro) y
  las marcas se interpretan en hora local, que es lo que escribe `syslog`, con
  `--utc` disponible para forzar UTC.
- **Líneas desordenadas o con relojes distintos** ya no reabren una ventana
  cerrada ni provocan diferencias de tiempo negativas.
- **`SOCEngine(sinks=[])`** respeta la lista vacía en lugar de reponer la
  salida por consola por defecto.
- **Eventos sin IP de origen** se descartan en vez de agruparse bajo un
  `0.0.0.0` ficticio que mezclaba orígenes distintos.
- **Los códigos de color** ya no se escriben al redirigir la salida a un
  fichero; se respeta además la variable de entorno `NO_COLOR`.

### Añadido

- Recolección de estado inactivo por IP: el consumo de memoria se mantiene
  acotado en ejecuciones prolongadas.
- Filtro `--gravedad-minima` para descartar alertas por debajo de un nivel.
- Opciones `--desde-inicio`, `--sin-color`, `--utc`, `--enfriamiento` y
  `--verboso`.
- Reconocimiento de las líneas `Invalid user …` de sshd (intentos previos a la
  autenticación) y de la autenticación por clave pública.
- La tormenta de fallos sube a gravedad **alta** cuando afecta a más de un
  servicio, y las alertas detallan usuarios y servicios implicados.
- Interfaz en español (`analizar`, `detectores`), manteniendo los alias en
  inglés (`run`, `list`) por compatibilidad.
- Integración continua en GitHub Actions sobre Python 3.10–3.13.
- Empaquetado con `pyproject.toml` y ejecutable `soc-monitor`.
- Batería de pruebas ampliada de 11 a 52 casos, con regresiones específicas
  para cada fallo de esta lista.

### Modificado

- `Alert.timestamp` pasa a ser la marca del evento que dispara la alerta, no la
  hora del reloj, para que el análisis de logs históricos sea coherente.
- Las gravedades se expresan en español (`baja`, `media`, `alta`, `critica`).
  `Severity.coerce()` sigue aceptando los nombres en inglés.
- Nombres de los detectores: `ssh_fuerza_bruta`, `escaneo_puertos` y
  `tormenta_autenticacion`.

## [1.0.0] — 2026-07-29

- Primera versión pública: parser de syslog, tres detectores, salidas por
  consola, JSONL y CSV, y modo de demostración.
