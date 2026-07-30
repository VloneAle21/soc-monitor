"""SOC Monitor — Centro de Operaciones de Seguridad ligero en Python.

Herramienta de un solo fichero que analiza logs tipo `syslog` / `auth.log`
y levanta alertas cuando detecta patrones de ataque habituales:

  * Fuerza bruta SSH — muchos fallos de autenticación desde una misma IP
  * Escaneo de puertos — conexiones a muchos puertos distintos desde un origen
  * Tormenta de fallos de autenticación — fallos correlacionados entre servicios

El diseño es deliberadamente sencillo y ampliable: un parser normaliza cada
línea en un `Event`, los detectores mantienen ventanas deslizantes por IP y
emiten `Alert`s, y los sinks se encargan de la salida (consola, JSONL, CSV).

Nota sobre el idioma: los identificadores del código están en inglés (convención
de Python y de la mayoría de librerías), mientras que toda la documentación,
los mensajes y la salida al usuario están en español.

Autor: Alejandro R. (@VloneAle21)
Licencia: MIT
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import re
import signal
import sys
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Callable, Iterable, Optional

LOG = logging.getLogger("soc-monitor")

__version__ = "2.0.0"
__author__ = "Alejandro R. (@VloneAle21)"

#: Segundos que una misma pareja (detector, IP) permanece silenciada tras alertar.
COOLDOWN_SECONDS = 300

#: Zona horaria local del sistema. `syslog` escribe en hora local, no en UTC.
LOCAL_TZ = datetime.now().astimezone().tzinfo or timezone.utc


# ---------------------------------------------------------------------------
# Modelo de datos
# ---------------------------------------------------------------------------


class EventKind(str, Enum):
    """Clasificación semántica de un evento.

    El parser decide el tipo una sola vez; los detectores filtran por este
    campo en lugar de volver a buscar palabras dentro del texto. Así el
    idioma del log no afecta a la lógica de detección.
    """

    AUTH_FAILURE = "fallo_autenticacion"
    AUTH_SUCCESS = "autenticacion_correcta"
    CONNECTION = "conexion"
    OTHER = "otro"


class Severity(str, Enum):
    """Nivel de gravedad de una alerta, ordenable mediante `rank`."""

    INFO = "info"
    LOW = "baja"
    MEDIUM = "media"
    HIGH = "alta"
    CRITICAL = "critica"

    @property
    def rank(self) -> int:
        """Posición en la escala de gravedad (0 = info, 4 = crítica)."""
        return _SEVERITY_RANK[self]

    @classmethod
    def coerce(cls, value: "Severity | str") -> "Severity":
        """Convierte una cadena en `Severity`, aceptando también el inglés."""
        if isinstance(value, cls):
            return value
        clave = str(value).strip().lower()
        equivalencias = {
            "low": cls.LOW,
            "medium": cls.MEDIUM,
            "high": cls.HIGH,
            "critical": cls.CRITICAL,
            "crítica": cls.CRITICAL,
        }
        if clave in equivalencias:
            return equivalencias[clave]
        return cls(clave)


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


@dataclass(slots=True)
class Event:
    """Evento de seguridad ya normalizado a partir de una línea de log."""

    timestamp: datetime
    source_ip: str
    username: Optional[str] = None
    message: str = ""
    raw: str = ""
    kind: EventKind = EventKind.OTHER
    port: Optional[int] = None
    facility: str = "auth"

    def to_dict(self) -> dict:
        """Representación serializable del evento."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "source_ip": self.source_ip,
            "username": self.username,
            "kind": self.kind.value,
            "port": self.port,
            "facility": self.facility,
            "message": self.message,
        }


@dataclass(slots=True)
class Alert:
    """Alerta emitida por un detector al superarse un umbral.

    `timestamp` es la marca de tiempo del evento que dispara la alerta (no la
    hora del reloj), de modo que analizar un log histórico produce alertas con
    fechas coherentes con el propio log.
    """

    detector: str
    severity: Severity
    title: str
    description: str
    source_ip: str
    events: list[Event] = field(default_factory=list)
    timestamp: datetime = field(default_factory=lambda: datetime.now(LOCAL_TZ))

    def __post_init__(self) -> None:
        self.severity = Severity.coerce(self.severity)

    @property
    def rank(self) -> int:
        """Gravedad numérica, útil para ordenar o filtrar alertas."""
        return self.severity.rank

    def to_dict(self) -> dict:
        """Representación serializable de la alerta."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "detector": self.detector,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "source_ip": self.source_ip,
            "events": [e.to_dict() for e in self.events],
        }


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


# Formato syslog clásico: "Jul 29 12:34:56 host proceso[pid]: mensaje"
SYSLOG_RE = re.compile(
    r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>[\w\-./]+)(?:\[\d+\])?:\s+(?P<msg>.*)$"
)

# sshd: contraseña incorrecta
SSH_FAIL_RE = re.compile(
    r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)
# sshd: intento contra un usuario inexistente (fase previa a la autenticación)
SSH_INVALID_USER_RE = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)
# sshd: autenticación correcta
SSH_OK_RE = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) "
    r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)
# sshd: conexión cerrada, reiniciada o entrante
SSH_CONN_RE = re.compile(
    r"(?:Connection (?:closed|reset)|Received disconnect) (?:by|from) "
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)
# Fallo de autenticación genérico en cualquier otro servicio (sudo, PAM, dovecot…)
GENERIC_FAIL_RE = re.compile(
    r"authentication failure|auth(?:entication)? failed|failed password|"
    r"invalid user|access denied|permission denied|login failed|incorrect password",
    re.I,
)
# Extractor de IP de reserva
IP_RE = re.compile(r"\b(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\b")
# Puerto de origen ("… port 51001 ssh2")
PORT_RE = re.compile(r"\bport\s+(?P<port>\d{1,5})\b", re.I)

MONTHS = {
    m: i
    for i, m in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
         "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"],
        start=1,
    )
}


def _extract_port(text: str) -> Optional[int]:
    """Devuelve el puerto que aparezca en el texto, o `None`."""
    m = PORT_RE.search(text)
    if not m:
        return None
    port = int(m["port"])
    return port if 0 < port <= 65535 else None


def _resolve_year(month: int, day: int, reference: datetime) -> int:
    """Deduce el año de una marca syslog, que no lo incluye.

    Se asume el año de `reference`; si la fecha resultante cayera más de un día
    en el futuro, se entiende que la línea pertenece al año anterior. Esto evita
    que los logs del cambio de año (31 de diciembre → 1 de enero) se fechen mal
    y rompan las ventanas temporales de los detectores.
    """
    for year in (reference.year, reference.year - 1):
        try:
            candidato = datetime(year, month, day, tzinfo=reference.tzinfo)
        except ValueError:  # 29 de febrero en un año no bisiesto
            continue
        if candidato <= reference + timedelta(days=1):
            return year
    return reference.year


class SyslogParser:
    """Convierte líneas de log en `Event` normalizados.

    Es invocable, así que puede pasarse directamente al motor como parser.
    """

    def __init__(self, tz: timezone | None = None, reference: datetime | None = None) -> None:
        #: Zona horaria en la que están escritas las marcas del log.
        self.tz = tz or LOCAL_TZ
        #: Momento de referencia para deducir el año (útil en los tests).
        self.reference = reference

    def __call__(self, line: str) -> Optional[Event]:
        """Analiza una línea y devuelve el evento, o `None` si no es útil."""
        line = line.rstrip("\n")
        if not line.strip():
            return None

        m = SYSLOG_RE.match(line)
        if not m:
            return self._parse_unstructured(line)

        proceso = m["proc"]
        mensaje = m["msg"]
        kind, usuario, ip, texto = self._classify(proceso, mensaje)

        if ip is None:
            encontrada = IP_RE.search(mensaje)
            ip = encontrada["ip"] if encontrada else None

        # Sin IP de origen no se puede correlacionar: el evento se descarta en
        # lugar de agruparlo bajo una IP ficticia junto a eventos ajenos.
        if ip is None:
            return None

        return Event(
            timestamp=self._timestamp(m["mon"], m["day"], m["time"]),
            source_ip=ip,
            username=usuario,
            message=texto,
            raw=line,
            kind=kind,
            port=_extract_port(mensaje),
            facility=proceso,
        )

    # -- internos -----------------------------------------------------------

    def _timestamp(self, mon: str, day: str, hora: str) -> datetime:
        referencia = self.reference or datetime.now(self.tz)
        mes, dia = MONTHS[mon], int(day)
        h, mi, s = (int(x) for x in hora.split(":"))
        anio = _resolve_year(mes, dia, referencia)
        return datetime(anio, mes, dia, h, mi, s, tzinfo=self.tz)

    def _classify(
        self, proceso: str, mensaje: str
    ) -> tuple[EventKind, Optional[str], Optional[str], str]:
        """Determina tipo, usuario, IP y texto legible de un mensaje."""
        if "sshd" in proceso.lower():
            fallo = SSH_FAIL_RE.search(mensaje)
            if fallo:
                return (
                    EventKind.AUTH_FAILURE,
                    fallo["user"],
                    fallo["ip"],
                    f"Fallo de autenticación SSH para el usuario «{fallo['user']}»",
                )

            invalido = SSH_INVALID_USER_RE.search(mensaje)
            if invalido:
                return (
                    EventKind.AUTH_FAILURE,
                    invalido["user"],
                    invalido["ip"],
                    f"Intento SSH contra el usuario inexistente «{invalido['user']}»",
                )

            correcto = SSH_OK_RE.search(mensaje)
            if correcto:
                return (
                    EventKind.AUTH_SUCCESS,
                    correcto["user"],
                    correcto["ip"],
                    f"Autenticación SSH correcta para el usuario «{correcto['user']}»",
                )

            conexion = SSH_CONN_RE.search(mensaje)
            if conexion:
                return (
                    EventKind.CONNECTION,
                    None,
                    conexion["ip"],
                    f"Conexión SSH cerrada desde {conexion['ip']}",
                )

        if GENERIC_FAIL_RE.search(mensaje):
            return (EventKind.AUTH_FAILURE, None, None, f"Fallo de autenticación en {proceso}")

        return (EventKind.OTHER, None, None, mensaje)

    def _parse_unstructured(self, line: str) -> Optional[Event]:
        """Rescata una IP de una línea que no sigue el formato syslog.

        Al no haber marca de tiempo fiable se usa la hora actual, y el evento
        se marca como `OTHER` salvo que el texto delate un fallo de acceso.
        """
        encontrada = IP_RE.search(line)
        if not encontrada:
            return None
        kind = EventKind.AUTH_FAILURE if GENERIC_FAIL_RE.search(line) else EventKind.OTHER
        return Event(
            timestamp=datetime.now(self.tz),
            source_ip=encontrada["ip"],
            username=None,
            message=line,
            raw=line,
            kind=kind,
            port=_extract_port(line),
            facility="desconocido",
        )


#: Parser por defecto, listo para usar.
parse_syslog = SyslogParser()


# ---------------------------------------------------------------------------
# Detectores
# ---------------------------------------------------------------------------


class Detector:
    """Clase base de los detectores con estado.

    Cada detector mantiene una ventana deslizante por IP de origen y sólo
    almacena los eventos que le incumben, decidido por `matches()`. Gracias a
    eso el recuento que aparece en la alerta es exacto: si el detector habla de
    «7 intentos fallidos», hay exactamente 7 fallos en la ventana.

    Para escribir un detector propio basta con heredar y redefinir `matches()`
    y `_evaluate()`.
    """

    #: Identificador corto que aparece en las alertas.
    name: str = "base"
    #: Descripción de una línea, mostrada por el subcomando `detectores`.
    description: str = ""
    #: Amplitud de la ventana deslizante, en segundos.
    window_seconds: int = 60
    #: Número de eventos dentro de la ventana que dispara la alerta.
    threshold: int = 5
    #: Gravedad de las alertas que emite.
    severity: Severity = Severity.MEDIUM

    #: Cada cuántos eventos se liberan las IPs inactivas.
    _GC_EVERY = 1000

    def __init__(
        self, window_seconds: int | None = None, threshold: int | None = None
    ) -> None:
        if window_seconds is not None:
            self.window_seconds = window_seconds
        if threshold is not None:
            self.threshold = threshold
        self._buckets: dict[str, deque[Event]] = defaultdict(deque)
        self._clock: dict[str, datetime] = {}
        self._latest: Optional[datetime] = None
        self._seen = 0

    # -- API pública --------------------------------------------------------

    def matches(self, event: Event) -> bool:
        """Indica si el evento es relevante para este detector.

        Sólo los eventos que superan este filtro entran en la ventana.
        """
        return True

    def feed(self, event: Event) -> Optional[Alert]:
        """Incorpora un evento y devuelve una alerta si se cruza el umbral."""
        if not self.matches(event):
            return None

        ip = event.source_ip
        anterior = self._clock.get(ip)

        # Líneas desordenadas o con relojes distintos: si el evento es más
        # antiguo que la ventana ya cubierta para esa IP, queda fuera.
        if anterior is not None and (anterior - event.timestamp).total_seconds() > self.window_seconds:
            return None

        ahora = event.timestamp if anterior is None or event.timestamp > anterior else anterior
        self._clock[ip] = ahora
        if self._latest is None or ahora > self._latest:
            self._latest = ahora

        self._buckets[ip].append(event)
        self._prune(ip, ahora)
        self._collect_garbage()
        return self._evaluate(event, ahora)

    def window(self, ip: str) -> list[Event]:
        """Eventos que este detector conserva ahora mismo para esa IP."""
        return list(self._buckets.get(ip, ()))

    # -- internos -----------------------------------------------------------

    def _prune(self, ip: str, ahora: datetime) -> None:
        """Elimina de la ventana los eventos que han quedado atrás."""
        bucket = self._buckets[ip]
        while bucket and (ahora - bucket[0].timestamp).total_seconds() > self.window_seconds:
            bucket.popleft()

    def _collect_garbage(self) -> None:
        """Libera las IPs que llevan más de una ventana sin actividad.

        Sin esto el consumo de memoria crecería sin límite en un proceso que
        vigila un log durante días.
        """
        self._seen += 1
        if self._seen % self._GC_EVERY or self._latest is None:
            return
        limite = self._latest - timedelta(seconds=self.window_seconds)
        caducadas = [ip for ip, visto in self._clock.items() if visto < limite]
        for ip in caducadas:
            self._buckets.pop(ip, None)
            self._clock.pop(ip, None)
            self._forget(ip)

    def _forget(self, ip: str) -> None:
        """Punto de extensión para que las subclases liberen su estado propio."""

    def _evaluate(self, event: Event, ahora: datetime) -> Optional[Alert]:
        """Decide si el estado actual justifica una alerta."""
        return None


class SSHBruteForceDetector(Detector):
    """Fuerza bruta SSH: muchos fallos de autenticación desde una misma IP."""

    name = "ssh_fuerza_bruta"
    description = "Intentos repetidos de autenticación SSH fallida desde un mismo origen"
    window_seconds = 60
    threshold = 5
    severity = Severity.HIGH

    def matches(self, event: Event) -> bool:
        return event.kind is EventKind.AUTH_FAILURE and "sshd" in event.facility.lower()

    def _evaluate(self, event: Event, ahora: datetime) -> Optional[Alert]:
        bucket = self._buckets[event.source_ip]
        if len(bucket) < self.threshold:
            return None

        usuarios = sorted({e.username for e in bucket if e.username})
        detalle = ", ".join(usuarios) if usuarios else "sin identificar"
        return Alert(
            detector=self.name,
            severity=self.severity,
            title=f"Fuerza bruta SSH desde {event.source_ip}",
            description=(
                f"{len(bucket)} intentos fallidos de autenticación SSH desde "
                f"{event.source_ip} en {self.window_seconds}s "
                f"(usuarios probados: {detalle})"
            ),
            source_ip=event.source_ip,
            events=list(bucket),
            timestamp=event.timestamp,
        )


class PortScanDetector(Detector):
    """Escaneo de puertos: conexiones a muchos puertos distintos desde un origen."""

    name = "escaneo_puertos"
    description = "Conexiones a un número elevado de puertos distintos desde un mismo origen"
    window_seconds = 30
    threshold = 10
    severity = Severity.MEDIUM

    #: Puertos distintos mínimos para considerar que hay barrido.
    min_distinct_ports = 3

    def __init__(self, window_seconds=None, threshold=None, min_distinct_ports=None) -> None:
        super().__init__(window_seconds, threshold)
        if min_distinct_ports is not None:
            self.min_distinct_ports = min_distinct_ports
        # Serie temporal de puertos, podada con la misma ventana que el bucket.
        self._ports: dict[str, deque[tuple[datetime, int]]] = defaultdict(deque)

    def matches(self, event: Event) -> bool:
        return event.kind is EventKind.CONNECTION and event.port is not None

    def _forget(self, ip: str) -> None:
        self._ports.pop(ip, None)

    def _evaluate(self, event: Event, ahora: datetime) -> Optional[Alert]:
        serie = self._ports[event.source_ip]
        serie.append((event.timestamp, event.port))  # type: ignore[arg-type]
        while serie and (ahora - serie[0][0]).total_seconds() > self.window_seconds:
            serie.popleft()

        distintos = sorted({puerto for _, puerto in serie})
        bucket = self._buckets[event.source_ip]
        if len(bucket) < self.threshold or len(distintos) < self.min_distinct_ports:
            return None

        muestra = ", ".join(str(p) for p in distintos[:8])
        if len(distintos) > 8:
            muestra += ", …"
        return Alert(
            detector=self.name,
            severity=self.severity,
            title=f"Escaneo de puertos desde {event.source_ip}",
            description=(
                f"{len(bucket)} conexiones a {len(distintos)} puertos distintos "
                f"({muestra}) en {self.window_seconds}s"
            ),
            source_ip=event.source_ip,
            events=list(bucket),
            timestamp=event.timestamp,
        )


class AuthFailStormDetector(Detector):
    """Tormenta de fallos de autenticación de un mismo origen contra varios servicios."""

    name = "tormenta_autenticacion"
    description = "Fallos de autenticación agrupados en el tiempo entre distintos servicios"
    window_seconds = 120
    threshold = 8
    severity = Severity.MEDIUM

    def matches(self, event: Event) -> bool:
        return event.kind is EventKind.AUTH_FAILURE

    def _evaluate(self, event: Event, ahora: datetime) -> Optional[Alert]:
        bucket = self._buckets[event.source_ip]
        if len(bucket) < self.threshold:
            return None

        servicios = sorted({e.facility for e in bucket})
        return Alert(
            detector=self.name,
            severity=Severity.HIGH if len(servicios) > 1 else self.severity,
            title=f"Tormenta de fallos de autenticación desde {event.source_ip}",
            description=(
                f"{len(bucket)} fallos de autenticación desde {event.source_ip} "
                f"en {self.window_seconds}s "
                f"(servicios afectados: {', '.join(servicios)})"
            ),
            source_ip=event.source_ip,
            events=list(bucket),
            timestamp=event.timestamp,
        )


#: Detectores activados por defecto.
DETECTORS: list[Callable[[], Detector]] = [
    SSHBruteForceDetector,
    PortScanDetector,
    AuthFailStormDetector,
]


# ---------------------------------------------------------------------------
# Sinks (salidas)
# ---------------------------------------------------------------------------


class AlertSink:
    """Interfaz común de las salidas de alertas."""

    def emit(self, alert: Alert) -> None:  # pragma: no cover - interfaz
        raise NotImplementedError

    def close(self) -> None:  # pragma: no cover - interfaz
        """Cierra los recursos abiertos. Idempotente."""


class JSONSink(AlertSink):
    """Escribe una alerta por línea en formato JSONL (ideal para un SIEM)."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fp = self.path.open("a", encoding="utf-8")

    def emit(self, alert: Alert) -> None:
        self._fp.write(json.dumps(alert.to_dict(), default=str, ensure_ascii=False) + "\n")
        self._fp.flush()

    def close(self) -> None:
        if not self._fp.closed:
            self._fp.close()


class CSVSink(AlertSink):
    """Vuelca las alertas en CSV, escribiendo la cabecera sólo la primera vez."""

    CABECERA = ["timestamp", "detector", "severity", "source_ip", "title", "description"]

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        estaba_vacio = not self.path.exists() or self.path.stat().st_size == 0
        self._fp = self.path.open("a", encoding="utf-8", newline="")
        self._writer = csv.writer(self._fp)
        if estaba_vacio:
            self._writer.writerow(self.CABECERA)

    def emit(self, alert: Alert) -> None:
        self._writer.writerow(
            [
                alert.timestamp.isoformat(),
                alert.detector,
                alert.severity.value,
                alert.source_ip,
                alert.title,
                alert.description,
            ]
        )
        self._fp.flush()

    def close(self) -> None:
        if not self._fp.closed:
            self._fp.close()


class StdoutSink(AlertSink):
    """Salida por consola, con color sólo cuando el destino es un terminal."""

    COLORES = {
        Severity.INFO: "\033[36m",
        Severity.LOW: "\033[32m",
        Severity.MEDIUM: "\033[33m",
        Severity.HIGH: "\033[31m",
        Severity.CRITICAL: "\033[35m",
    }
    RESET = "\033[0m"

    def __init__(self, stream=None, color: bool | None = None) -> None:
        self.stream = stream if stream is not None else sys.stdout
        self.color = self._autodetect() if color is None else color

    def _autodetect(self) -> bool:
        """Desactiva el color al redirigir a fichero o si se define NO_COLOR."""
        if os.environ.get("NO_COLOR") is not None:
            return False
        if os.environ.get("TERM", "") == "dumb":
            return False
        return bool(getattr(self.stream, "isatty", lambda: False)())

    def emit(self, alert: Alert) -> None:
        color = self.COLORES.get(alert.severity, "") if self.color else ""
        reset = self.RESET if self.color else ""
        gravedad = alert.severity.value.upper().ljust(8)
        hora = alert.timestamp.strftime("%d/%m %H:%M:%S")
        print(
            f"{color}[{hora}] [{gravedad}] {alert.title}{reset}\n"
            f"          ↳ {alert.description}\n"
            f"          ↳ origen: {alert.source_ip} · detector: {alert.detector}",
            file=self.stream,
        )


# ---------------------------------------------------------------------------
# Motor
# ---------------------------------------------------------------------------


class SOCEngine:
    """Coordina parser, detectores y sinks sobre un flujo de log."""

    #: Cada cuántas alertas se limpia el registro de silenciamientos.
    _GC_EVERY = 500

    def __init__(
        self,
        detectors: Iterable[Detector] | None = None,
        sinks: Iterable[AlertSink] | None = None,
        parser: Callable[[str], Optional[Event]] | None = None,
        cooldown_seconds: int = COOLDOWN_SECONDS,
        min_severity: Severity | str = Severity.INFO,
    ) -> None:
        self.detectors: list[Detector] = (
            list(detectors) if detectors is not None else [d() for d in DETECTORS]
        )
        # Una lista vacía significa «sin salidas», no «usa la de por defecto».
        self.sinks: list[AlertSink] = list(sinks) if sinks is not None else [StdoutSink()]
        self.parser = parser or parse_syslog
        #: Segundos de silencio por (detector, IP). 0 desactiva el silenciamiento.
        self.cooldown_seconds = cooldown_seconds
        self.min_severity = Severity.coerce(min_severity)
        self.stats = {"lines": 0, "events": 0, "alerts": 0, "suppressed": 0}
        self._fired: dict[tuple[str, str], datetime] = {}

    # -- procesamiento ------------------------------------------------------

    def _process_line(self, line: str) -> list[Alert]:
        self.stats["lines"] += 1
        event = self.parser(line)
        if event is None:
            return []
        self.stats["events"] += 1

        emitidas: list[Alert] = []
        for detector in self.detectors:
            alert = detector.feed(event)
            if alert is None:
                continue
            if alert.rank < self.min_severity.rank:
                continue
            if self._silenced(alert):
                self.stats["suppressed"] += 1
                continue
            self._fired[(alert.detector, alert.source_ip)] = alert.timestamp
            self.stats["alerts"] += 1
            emitidas.append(alert)
            self._publish(alert)

        if emitidas and self.stats["alerts"] % self._GC_EVERY == 0:
            self._collect_garbage(event.timestamp)
        return emitidas

    def _silenced(self, alert: Alert) -> bool:
        """Indica si esa pareja (detector, IP) sigue dentro del periodo de silencio.

        El silenciamiento caduca: a diferencia de un registro permanente, una IP
        que vuelve a atacar más tarde vuelve a generar alerta.
        """
        if self.cooldown_seconds <= 0:
            return False
        anterior = self._fired.get((alert.detector, alert.source_ip))
        if anterior is None:
            return False
        return abs((alert.timestamp - anterior).total_seconds()) < self.cooldown_seconds

    def _publish(self, alert: Alert) -> None:
        for sink in self.sinks:
            try:
                sink.emit(alert)
            except Exception:  # una salida rota nunca debe tumbar el motor
                LOG.exception("la salida %s ha fallado", type(sink).__name__)

    def _collect_garbage(self, ahora: datetime) -> None:
        """Descarta silenciamientos ya caducados para acotar la memoria."""
        if self.cooldown_seconds <= 0:
            self._fired.clear()
            return
        limite = ahora - timedelta(seconds=self.cooldown_seconds)
        for clave in [c for c, visto in self._fired.items() if visto < limite]:
            self._fired.pop(clave, None)

    # -- API pública --------------------------------------------------------

    def process(self, lines: Iterable[str]) -> int:
        """Procesa un iterable de líneas y devuelve el número de alertas."""
        return sum(len(self._process_line(line)) for line in lines)

    def follow(self, path: Path, poll_interval: float = 0.25, from_start: bool = False) -> None:
        """Sigue un fichero en tiempo real, al estilo de `tail -F`.

        Detecta la rotación (logrotate cambia el inodo) y el truncado del
        fichero, y vuelve a abrirlo. Sin esto el proceso seguiría leyendo el
        fichero antiguo y dejaría de ver eventos en silencio.
        """
        path = Path(path)
        fp = None
        identidad: tuple[int, int] | None = None
        try:
            while True:
                if fp is None:
                    try:
                        fp = path.open("r", encoding="utf-8", errors="replace")
                    except FileNotFoundError:
                        time.sleep(poll_interval)
                        continue
                    estado = os.fstat(fp.fileno())
                    identidad = (estado.st_dev, estado.st_ino)
                    if not from_start:
                        fp.seek(0, os.SEEK_END)

                linea = fp.readline()
                if linea:
                    self._process_line(linea)
                    continue

                if self._rotated(path, fp, identidad):
                    LOG.info("el fichero %s ha rotado, reabriendo", path)
                    fp.close()
                    fp = None
                    from_start = True  # el fichero nuevo se lee desde el principio
                    continue

                time.sleep(poll_interval)
        finally:
            if fp is not None:
                fp.close()

    @staticmethod
    def _rotated(path: Path, fp, identidad: tuple[int, int] | None) -> bool:
        """Comprueba si el fichero ha sido rotado o truncado."""
        try:
            estado = path.stat()
        except FileNotFoundError:
            return True
        if identidad is not None and (estado.st_dev, estado.st_ino) != identidad:
            return True
        return estado.st_size < fp.tell()

    def close(self) -> None:
        """Cierra todas las salidas."""
        for sink in self.sinks:
            try:
                sink.close()
            except Exception:  # pragma: no cover - cierre best effort
                LOG.exception("no se pudo cerrar la salida %s", type(sink).__name__)

    def reset_cooldown(self) -> None:
        """Olvida los silenciamientos activos."""
        self._fired.clear()

    def summary(self) -> str:
        """Resumen de una línea con las estadísticas del análisis."""
        s = self.stats
        return (
            f"líneas={s['lines']} · eventos={s['events']} · "
            f"alertas={s['alerts']} · silenciadas={s['suppressed']}"
        )


# ---------------------------------------------------------------------------
# Escenario de demostración (--demo)
# ---------------------------------------------------------------------------


def demo_lines() -> Iterable[str]:
    """Genera un ataque sintético para probar la herramienta sin logs reales.

    Incluye tráfico legítimo a propósito: sirve para comprobar que la actividad
    normal no dispara alertas.
    """
    ATACANTE = "203.0.113.5"
    LEGITIMA = "198.51.100.7"
    escenario: list[str] = []

    def sshd(segundos: int, mensaje: str) -> str:
        return f"Jul 29 12:{segundos // 60:02d}:{segundos % 60:02d} srv01 sshd[1234]: {mensaje}"

    # 1) Fuerza bruta SSH contra varios usuarios.
    usuarios = ["root", "admin", "test", "root", "oracle", "postgres", "root"]
    for i, usuario in enumerate(usuarios):
        invalido = "invalid user " if usuario not in ("root", "admin") else ""
        escenario.append(
            sshd(i * 2, f"Failed password for {invalido}{usuario} from {ATACANTE} port 51{i:03d} ssh2")
        )

    # 2) Tráfico legítimo intercalado: no debe generar ninguna alerta.
    escenario.append(sshd(14, f"Accepted password for admin from {LEGITIMA} port 51022 ssh2"))
    escenario.append(sshd(16, f"Connection closed by {LEGITIMA} port 51022"))

    # 3) Barrido de puertos desde la misma IP atacante.
    for i in range(12):
        escenario.append(sshd(20 + i, f"Connection closed by {ATACANTE} port 52{i:03d}"))

    # 4) El ataque se extiende a otros servicios.
    escenario.append(
        f"Jul 29 12:01:10 srv01 dovecot: auth-worker: pam(auth,{ATACANTE}): authentication failure"
    )
    escenario.append(
        f"Jul 29 12:01:12 srv01 dovecot: auth-worker: pam(auth,{ATACANTE}): authentication failure"
    )

    for linea in escenario:
        yield linea + "\n"


# ---------------------------------------------------------------------------
# Interfaz de línea de comandos
# ---------------------------------------------------------------------------


BANNER = "🛡️  SOC Monitor — detección de fuerza bruta, escaneo de puertos y fallos de autenticación."


def _build_sinks(args: argparse.Namespace) -> list[AlertSink]:
    """Construye las salidas a partir de los argumentos de la CLI."""
    sinks: list[AlertSink] = []
    if args.json:
        sinks.append(JSONSink(Path(args.json)))
    if args.csv:
        sinks.append(CSVSink(Path(args.csv)))
    if not args.silencioso:
        sinks.append(StdoutSink(color=False if args.sin_color else None))
    return sinks


def cmd_analizar(args: argparse.Namespace) -> int:
    """Subcomando `analizar`: procesa un fichero de log o el escenario de demo."""
    if not args.demo and not args.fichero:
        args._parser.error("indica la ruta de un fichero de log o usa --demo")

    parser = SyslogParser(tz=timezone.utc if args.utc else None)
    engine = SOCEngine(
        sinks=_build_sinks(args),
        parser=parser,
        cooldown_seconds=args.enfriamiento,
        min_severity=args.gravedad_minima,
    )

    def _apagar(signum, _frame):
        LOG.info("cerrando (señal %s)", signum)
        engine.close()
        sys.exit(0)

    signal.signal(signal.SIGINT, _apagar)
    try:
        signal.signal(signal.SIGTERM, _apagar)
    except (AttributeError, ValueError):  # Windows o hilo secundario
        pass

    try:
        if args.demo:
            engine.process(demo_lines())
            print(f"\n— fin del escenario de demostración · {engine.summary()}")
            return 0

        ruta = Path(args.fichero)
        if args.seguir:
            print(f"📡 Siguiendo {ruta} en tiempo real…  (Ctrl+C para parar)\n")
            engine.follow(ruta, from_start=args.desde_inicio)
            return 0

        if not ruta.is_file():
            print(f"error: no se encuentra el fichero «{ruta}»", file=sys.stderr)
            return 2

        with ruta.open("r", encoding="utf-8", errors="replace") as fp:
            engine.process(fp)
        print(f"\n— análisis completado · {engine.summary()}")
        return 0
    finally:
        engine.close()


def cmd_detectores(args: argparse.Namespace) -> int:
    """Subcomando `detectores`: lista los detectores disponibles."""
    print("Detectores disponibles:\n")
    for fabrica in DETECTORS:
        d = fabrica()
        print(f"  • {d.name}")
        print(f"      {d.description}")
        print(
            f"      ventana={d.window_seconds}s · umbral={d.threshold} "
            f"· gravedad={d.severity.value}\n"
        )
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Define la interfaz de línea de comandos."""
    p = argparse.ArgumentParser(prog="soc-monitor", description=BANNER)
    p.add_argument("--version", action="version", version=f"soc-monitor {__version__}")
    p.add_argument("-v", "--verboso", action="store_true", help="Muestra trazas de diagnóstico")
    sub = p.add_subparsers(dest="comando", metavar="{analizar,detectores}")

    analizar = sub.add_parser(
        "analizar",
        aliases=["run"],
        help="Analiza un fichero de log o un flujo en tiempo real",
        description="Analiza un log tipo syslog/auth.log y emite alertas.",
    )
    analizar.add_argument("fichero", nargs="?", help="Ruta del fichero de log a analizar")
    analizar.add_argument(
        "-s", "--seguir", "-f", "--follow", action="store_true",
        help="Sigue el fichero en tiempo real (soporta rotación de logs)",
    )
    analizar.add_argument(
        "--desde-inicio", action="store_true",
        help="Con --seguir, procesa también el contenido ya existente",
    )
    analizar.add_argument("--demo", action="store_true", help="Ejecuta un escenario de ataque de ejemplo")
    analizar.add_argument("--json", metavar="RUTA", help="Añade las alertas a un fichero JSONL")
    analizar.add_argument("--csv", metavar="RUTA", help="Añade las alertas a un fichero CSV")
    analizar.add_argument(
        "-q", "--silencioso", "--quiet", action="store_true",
        help="No escribe nada por consola (útil en tareas programadas)",
    )
    analizar.add_argument("--sin-color", action="store_true", help="Desactiva los colores")
    analizar.add_argument(
        "--gravedad-minima", default="info",
        choices=[s.value for s in Severity],
        help="Descarta las alertas por debajo de esta gravedad (por defecto: info)",
    )
    analizar.add_argument(
        "--enfriamiento", type=int, default=COOLDOWN_SECONDS, metavar="SEGUNDOS",
        help=(
            "Silencia cada pareja (detector, IP) durante N segundos tras alertar. "
            f"0 lo desactiva (por defecto: {COOLDOWN_SECONDS})"
        ),
    )
    analizar.add_argument("--utc", action="store_true", help="Interpreta las marcas del log como UTC")
    analizar.set_defaults(func=cmd_analizar, _parser=analizar)

    detectores = sub.add_parser(
        "detectores", aliases=["list"], help="Lista los detectores disponibles"
    )
    detectores.set_defaults(func=cmd_detectores, _parser=detectores)
    return p


def main(argv: list[str] | None = None) -> int:
    """Punto de entrada del programa."""
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if getattr(args, "verboso", False) else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )
    if not getattr(args, "func", None):
        parser.print_help()
        return 0
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
