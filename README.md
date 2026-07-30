<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0d1117,50:1f6feb,100:0d1117&height=180&section=header&text=SOC%20Monitor&fontSize=45&fontColor=ffffff&fontAlignY=35&desc=Centro%20de%20Operaciones%20de%20Seguridad%20ligero%20en%20Python&descSize=15&descColor=c9d1d9&descAlignY=58&animation=fadeIn" width="100%" alt="banner"/>

<br/>

[![tests](https://github.com/VloneAle21/soc-monitor/actions/workflows/tests.yml/badge.svg)](https://github.com/VloneAle21/soc-monitor/actions/workflows/tests.yml)
[![Python](https://img.shields.io/badge/Python-3.10%20%E2%80%93%203.13-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Licencia MIT](https://img.shields.io/badge/Licencia-MIT-1f6feb?style=flat-square&logo=opensourceinitiative&logoColor=white)](LICENSE)
[![Sin dependencias](https://img.shields.io/badge/Dependencias-Ninguna-00d4aa?style=flat-square&logo=python&logoColor=white)](requirements.txt)
[![Estrellas](https://img.shields.io/github/stars/VloneAle21/soc-monitor?style=flat-square&logo=github&color=yellow)](https://github.com/VloneAle21/soc-monitor/stargazers)

**Detección de fuerza bruta, escaneo de puertos y fallos de autenticación sobre `syslog` / `auth.log`.**
Un solo fichero, cero dependencias, pensado para leerse y ampliarse.

</div>

---

## Qué es

**SOC Monitor** analiza logs de autenticación en busca de los patrones de ataque
que un analista de *blue team* revisa a diario, y levanta alertas cuando alguno
cruza un umbral dentro de una ventana de tiempo:

| Detector | Qué busca | Ventana | Umbral | Gravedad |
|---|---|---:|---:|---|
| `ssh_fuerza_bruta` | Fallos de autenticación SSH repetidos desde un mismo origen | 60 s | 5 | alta |
| `escaneo_puertos` | Conexiones a muchos puertos distintos desde un mismo origen | 30 s | 10 | media |
| `tormenta_autenticacion` | Fallos de autenticación agrupados entre varios servicios | 120 s | 8 | media / alta |

Funciona sobre `/var/log/auth.log`, `/var/log/secure` o cualquier fichero que
siga el formato `syslog`. No necesita nada más que Python.

> Proyecto de **[Alejandro R. (@VloneAle21)](https://github.com/VloneAle21)** — ciberseguridad, IA y automatización.

---

## Empezar

```bash
git clone https://github.com/VloneAle21/soc-monitor.git
cd soc-monitor

# Escenario de ataque simulado, sin necesidad de logs reales
python soc_monitor.py analizar --demo

# Analizar un log real
python soc_monitor.py analizar /var/log/auth.log

# Vigilar un log en tiempo real (aguanta la rotación de logrotate)
python soc_monitor.py analizar /var/log/auth.log --seguir

# Guardar las alertas mientras se ven por consola
python soc_monitor.py analizar auth.log --json alertas.jsonl --csv alertas.csv
```

Instalación opcional como comando del sistema:

```bash
pip install .
soc-monitor analizar --demo
```

### Salida

```
[29/07 12:00:08] [ALTA    ] Fuerza bruta SSH desde 203.0.113.5
          ↳ 5 intentos fallidos de autenticación SSH desde 203.0.113.5 en 60s (usuarios probados: admin, root, test)
          ↳ origen: 203.0.113.5 · detector: ssh_fuerza_bruta
[29/07 12:00:29] [MEDIA   ] Escaneo de puertos desde 203.0.113.5
          ↳ 10 conexiones a 10 puertos distintos (52001, 52002, 52003, 52004, 52005, …) en 30s
          ↳ origen: 203.0.113.5 · detector: escaneo_puertos
[29/07 12:01:10] [ALTA    ] Tormenta de fallos de autenticación desde 203.0.113.5
          ↳ 8 fallos de autenticación desde 203.0.113.5 en 120s (servicios afectados: dovecot, sshd)
          ↳ origen: 203.0.113.5 · detector: tormenta_autenticacion

— análisis completado · líneas=28 · eventos=25 · alertas=3 · silenciadas=5
```

Los recuentos son literales: si la alerta dice **8 fallos**, hay exactamente 8
fallos de autenticación en la ventana. El tráfico legítimo intercalado —el
`Accepted password` de `198.51.100.7` en el log de ejemplo— no suma.

---

## Uso

```
soc-monitor [-h] [--version] [-v] {analizar,detectores} ...

  analizar     Analiza un fichero de log o un flujo en tiempo real
  detectores   Lista los detectores disponibles
```

Los subcomandos mantienen los alias en inglés `run` y `list`.

### Opciones de `analizar`

| Opción | Descripción |
|---|---|
| `fichero` | Ruta del log a analizar |
| `-s`, `--seguir` | Sigue el fichero en tiempo real, con soporte de rotación |
| `--desde-inicio` | Junto a `--seguir`, procesa también lo ya escrito |
| `--demo` | Ejecuta el escenario de ataque de ejemplo |
| `--json RUTA` | Añade las alertas a un fichero JSONL |
| `--csv RUTA` | Añade las alertas a un fichero CSV |
| `-q`, `--silencioso` | Sin salida por consola, para tareas programadas |
| `--sin-color` | Desactiva los colores (también se respeta `NO_COLOR`) |
| `--gravedad-minima` | Descarta alertas por debajo del nivel indicado |
| `--enfriamiento SEG` | Silencia cada pareja (detector, IP) N segundos tras alertar. `0` lo desactiva |
| `--utc` | Interpreta las marcas del log como UTC en vez de hora local |

Ejemplo típico en producción: sólo lo grave, sin ruido y persistido a disco.

```bash
soc-monitor analizar /var/log/auth.log --seguir \
    --gravedad-minima alta --enfriamiento 900 \
    --json /var/log/soc/alertas.jsonl --silencioso
```

---

## Arquitectura

```
                ┌──────────┐   ┌────────────┐   ┌────────┐   ┌────────┐
líneas de log → │  Parser  │ → │ Detectores │ → │ Motor  │ → │ Salidas│
                └──────────┘   └────────────┘   └────────┘   └────────┘
                clasifica       ventana por IP   silencia     consola
                y normaliza     y umbrales       y filtra     JSONL / CSV
```

- **Parser** — normaliza cada línea en un `Event(timestamp, source_ip, username, kind, port, facility)`.
  La clave está en `kind`: el tipo de evento (`fallo_autenticacion`,
  `autenticacion_correcta`, `conexion`, `otro`) se decide **una sola vez**, y
  los detectores filtran por él en lugar de rebuscar palabras en el texto. Eso
  hace que la lógica de detección no dependa del idioma del log.
- **Detectores** — cada uno guarda una ventana deslizante por IP con **sólo los
  eventos que le competen**, y libera las IPs inactivas para no crecer sin
  límite.
- **Motor** — coordina el flujo, filtra por gravedad y silencia alertas
  repetidas durante un periodo que **caduca**, de modo que un atacante que
  vuelve más tarde se vuelve a detectar.
- **Salidas** — `StdoutSink` (con color sólo si hay terminal), `JSONSink` y
  `CSVSink`.

### Escribir un detector propio

```python
from soc_monitor import Detector, Event, Alert, EventKind, Severity, SOCEngine, StdoutSink

class WebShellDetector(Detector):
    name = "web_shell"
    description = "Peticiones sospechosas a ficheros subidos"
    window_seconds = 300
    threshold = 3
    severity = Severity.CRITICAL

    def matches(self, event: Event) -> bool:
        # Sólo entran en la ventana los eventos que te interesan.
        return event.kind is EventKind.OTHER and ".php" in event.raw

    def _evaluate(self, event: Event, ahora) -> Alert | None:
        ventana = self._buckets[event.source_ip]
        if len(ventana) < self.threshold:
            return None
        return Alert(
            detector=self.name,
            severity=self.severity,
            title=f"Posible web shell desde {event.source_ip}",
            description=f"{len(ventana)} peticiones sospechosas en {self.window_seconds}s",
            source_ip=event.source_ip,
            events=list(ventana),
            timestamp=event.timestamp,
        )

engine = SOCEngine(detectors=[WebShellDetector()], sinks=[StdoutSink()])
engine.process(open("/var/log/auth.log"))
```

Separar `matches()` de `_evaluate()` es lo que garantiza que el recuento de la
alerta sea real: lo que no pasa el filtro, no ocupa sitio en la ventana.

---

## Formato de las alertas

Cada línea del fichero JSONL es una alerta completa, lista para ingerir en un
SIEM. Las claves están en inglés a propósito, para que encajen con los esquemas
habituales (ECS, Splunk, OpenSearch); los valores van en español.

```json
{
  "timestamp": "2026-07-29T12:00:08+02:00",
  "detector": "ssh_fuerza_bruta",
  "severity": "alta",
  "title": "Fuerza bruta SSH desde 203.0.113.5",
  "description": "5 intentos fallidos de autenticación SSH desde 203.0.113.5 en 60s (usuarios probados: admin, root, test)",
  "source_ip": "203.0.113.5",
  "events": [
    {
      "timestamp": "2026-07-29T12:00:00+02:00",
      "source_ip": "203.0.113.5",
      "username": "root",
      "kind": "fallo_autenticacion",
      "port": 51001,
      "facility": "sshd",
      "message": "Fallo de autenticación SSH para el usuario «root»"
    }
  ]
}
```

`timestamp` es la marca del evento que dispara la alerta, no la hora del reloj:
analizar un log de la semana pasada produce alertas fechadas la semana pasada.

---

## Pruebas

```bash
pip install -r requirements-dev.txt
python -m pytest -v
```

```
52 passed
```

La batería cubre el parser, las marcas de tiempo, los tres detectores, el motor,
las tres salidas y la CLI. La clase `TestRegresiones` fija además cada uno de
los fallos corregidos en la 2.0.0, para que no vuelvan.

---

## Estructura del proyecto

```
soc-monitor/
├── soc_monitor.py            # Toda la herramienta, en un solo fichero
├── test_soc_monitor.py       # 52 pruebas con pytest
├── sample_auth.log           # Log de ejemplo con ataque y tráfico legítimo
├── pyproject.toml            # Empaquetado y configuración de pytest
├── requirements.txt          # Vacío: sólo librería estándar
├── requirements-dev.txt      # pytest
├── CHANGELOG.md              # Registro de cambios
└── .github/workflows/        # Integración continua (Python 3.10 – 3.13)
```

---

## Para qué sirve, y para qué no

**Encaja bien en:**

- Laboratorio propio o práctica de *blue team*: convertir tu `auth.log` en alertas.
- CTF y formación: enseñar lógica de detección sobre tráfico controlado.
- Máquinas pequeñas donde un SIEM completo no cabe ni compensa.
- Aprender: el código está comentado y pensado para leerse de arriba abajo.

**Limitaciones que conviene conocer:**

- Correlaciona **por IP de origen**. Los eventos sin IP —un `sudo` fallido en
  consola local, por ejemplo— se descartan, porque agruparlos bajo una IP
  inventada mezclaría orígenes distintos.
- La detección de escaneo se basa en lo que `sshd` registra, no en tráfico de
  red. Para un barrido de puertos real, un IDS a nivel de paquete (Suricata,
  Zeek) ve mucho más.
- Es una herramienta de detección, no de respuesta: no bloquea ni banea nada.
  Para eso, `fail2ban`.
- Los umbrales por defecto son un punto de partida razonable, no una verdad
  universal. Ajústalos a tu tráfico o generarás ruido.

---

## Contribuir

Las aportaciones son bienvenidas, sobre todo detectores nuevos: movimiento
lateral, geolocalización anómala, exfiltración, web shells…

```bash
git checkout -b feat/mi-detector
# …código y pruebas…
python -m pytest -v
git commit -m "feat: añade detector de movimiento lateral"
```

Todo detector nuevo debería traer sus pruebas: al menos una que confirme que
salta cuando debe, y otra que confirme que **no** salta con tráfico legítimo.
La segunda es la que de verdad cuesta y la que evita los falsos positivos.

---

## Licencia

Publicado bajo licencia **MIT**. Ver [LICENSE](LICENSE).

<div align="center">
<br/>

**Si te ha resultado útil, una estrella ayuda.**

Hecho con 🛡️ por **[Alejandro R.](https://github.com/VloneAle21)**

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0d1117,50:1f6feb,100:0d1117&height=100&section=footer&text=&fontSize=0&animation=fadeIn" width="100%" alt="footer"/>

</div>
