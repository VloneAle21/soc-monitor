"""Batería de pruebas de SOC Monitor.

Ejecutar con:  python -m pytest -v

Incluye pruebas de regresión explícitas para los fallos corregidos en la
versión 2.0.0; están agrupadas al final bajo la clase `TestRegresiones`.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

HERE = Path(__file__).parent
spec = importlib.util.spec_from_file_location("soc_monitor", HERE / "soc_monitor.py")
soc = importlib.util.module_from_spec(spec)
sys.modules["soc_monitor"] = soc
spec.loader.exec_module(soc)

UTC = timezone.utc
BASE = datetime(2026, 7, 29, 12, 0, 0, tzinfo=UTC)
ATACANTE = "203.0.113.5"


# ---------------------------------------------------------------------------
# Utilidades
# ---------------------------------------------------------------------------


@pytest.fixture
def parser():
    """Parser fijado en UTC y con una referencia estable para el año."""
    return soc.SyslogParser(tz=UTC, reference=datetime(2026, 8, 1, tzinfo=UTC))


@pytest.fixture
def servidor_webhook():
    """Levanta un receptor HTTP local y devuelve (url, lista de alertas recibidas)."""
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    recibidas: list[dict] = []

    class Receptor(BaseHTTPRequestHandler):
        def do_POST(self):
            cuerpo = self.rfile.read(int(self.headers["Content-Length"]))
            recibidas.append(json.loads(cuerpo))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *_):  # silencia el log del servidor de pruebas
            pass

    servidor = HTTPServer(("127.0.0.1", 0), Receptor)
    hilo = threading.Thread(target=servidor.serve_forever, daemon=True)
    hilo.start()
    try:
        yield f"http://127.0.0.1:{servidor.server_port}/hook", recibidas
    finally:
        servidor.shutdown()
        servidor.server_close()


def evento(
    segundos: int = 0,
    ip: str = ATACANTE,
    kind: soc.EventKind = soc.EventKind.AUTH_FAILURE,
    usuario: str | None = "root",
    puerto: int | None = None,
    servicio: str = "sshd",
) -> soc.Event:
    """Construye un evento sintético listo para alimentar a un detector."""
    return soc.Event(
        timestamp=BASE + timedelta(seconds=segundos),
        source_ip=ip,
        username=usuario,
        message="evento de prueba",
        raw="linea de prueba",
        kind=kind,
        port=puerto,
        facility=servicio,
    )


def alimentar(detector: soc.Detector, eventos) -> list[soc.Alert]:
    """Pasa varios eventos al detector y devuelve las alertas emitidas."""
    return [a for a in (detector.feed(e) for e in eventos) if a is not None]


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


class TestParser:
    def test_contrasena_incorrecta_ssh(self, parser):
        ev = parser(
            "Jul 29 12:00:00 srv01 sshd[1234]: Failed password for root "
            "from 203.0.113.5 port 51001 ssh2"
        )
        assert ev is not None
        assert ev.source_ip == ATACANTE
        assert ev.username == "root"
        assert ev.kind is soc.EventKind.AUTH_FAILURE
        assert ev.port == 51001
        assert ev.facility == "sshd"

    def test_usuario_inexistente(self, parser):
        ev = parser(
            "Jul 29 12:00:01 srv01 sshd[1234]: Failed password for invalid user admin "
            "from 203.0.113.5 port 51002 ssh2"
        )
        assert ev.username == "admin"
        assert ev.kind is soc.EventKind.AUTH_FAILURE

    def test_invalid_user_previo_a_la_autenticacion(self, parser):
        ev = parser(
            "Jul 29 12:00:01 srv01 sshd[1234]: Invalid user oracle from 203.0.113.5 port 51002"
        )
        assert ev.username == "oracle"
        assert ev.kind is soc.EventKind.AUTH_FAILURE

    def test_autenticacion_correcta(self, parser):
        ev = parser(
            "Jul 29 12:00:14 srv01 sshd[1234]: Accepted password for admin "
            "from 198.51.100.7 port 51022 ssh2"
        )
        assert ev.username == "admin"
        assert ev.source_ip == "198.51.100.7"
        assert ev.kind is soc.EventKind.AUTH_SUCCESS

    def test_conexion_cerrada(self, parser):
        ev = parser("Jul 29 12:00:20 srv01 sshd[1234]: Connection closed by 203.0.113.5 port 52001")
        assert ev.kind is soc.EventKind.CONNECTION
        assert ev.port == 52001

    @pytest.mark.parametrize(
        "mensaje, usuario",
        [
            (
                "Connection closed by authenticating user root 203.0.113.5 port 51001 [preauth]",
                "root",
            ),
            ("Connection closed by invalid user admin 203.0.113.5 port 51002 [preauth]", "admin"),
            ("Connection reset by 203.0.113.5 port 51003 [preauth]", None),
            ("Received disconnect from 203.0.113.5 port 51004:11: Bye", None),
        ],
    )
    def test_formas_de_cierre_de_conexion_de_sshd(self, parser, mensaje, usuario):
        # sshd intercala el usuario antes de la dirección en varias de sus
        # variantes; la IP debe salir bien en todas y el texto no debe decir "None".
        ev = parser(f"Jul 29 12:00:00 srv01 sshd[1234]: {mensaje}")
        assert ev.source_ip == ATACANTE
        assert ev.kind is soc.EventKind.CONNECTION
        assert ev.username == usuario
        assert "None" not in ev.message

    def test_fallo_generico_en_otro_servicio(self, parser):
        ev = parser(
            "Jul 29 12:01:10 srv01 dovecot: auth-worker: pam(auth,203.0.113.5): "
            "authentication failure"
        )
        assert ev.kind is soc.EventKind.AUTH_FAILURE
        assert ev.facility == "dovecot"
        assert ev.source_ip == ATACANTE

    def test_linea_vacia_devuelve_none(self, parser):
        assert parser("\n") is None
        assert parser("") is None
        assert parser("   ") is None

    def test_linea_sin_ip_se_descarta(self, parser):
        # Sin IP no se puede correlacionar, así que no se inventa un 0.0.0.0
        # que mezclaría eventos de orígenes distintos en un mismo grupo.
        ev = parser("Jul 29 12:01:00 srv01 sudo: admin : TTY=pts/0 ; authentication failure")
        assert ev is None

    def test_linea_no_estructurada_rescata_la_ip(self, parser):
        ev = parser("log de una app: conexion desde 10.0.0.99 rechazada")
        assert ev is not None
        assert ev.source_ip == "10.0.0.99"

    def test_puerto_fuera_de_rango_se_ignora(self):
        assert soc._extract_port("port 99999") is None
        assert soc._extract_port("port 22") == 22
        assert soc._extract_port("sin puerto") is None


class TestIPv6:
    """Los ataques por IPv6 deben verse igual que los de IPv4."""

    @pytest.mark.parametrize(
        "linea, esperada",
        [
            (
                "Jul 29 12:00:00 srv01 sshd[1234]: Failed password for root "
                "from 2001:db8::dead:beef port 51001 ssh2",
                "2001:db8::dead:beef",
            ),
            (
                "Jul 29 12:00:00 srv01 sshd[1234]: Failed password for root from ::1 port 22 ssh2",
                "::1",
            ),
            (
                "Jul 29 12:00:00 srv01 sshd[1234]: Failed password for root "
                "from ::ffff:203.0.113.5 port 22 ssh2",
                "::ffff:203.0.113.5",
            ),
            # El identificador de zona se descarta al normalizar.
            (
                "Jul 29 12:00:00 srv01 sshd[1234]: Failed password for root "
                "from fe80::1%eth0 port 22 ssh2",
                "fe80::1",
            ),
            # Forma extendida: se guarda en forma canónica comprimida.
            (
                "Jul 29 12:00:00 srv01 sshd[1234]: Failed password for root "
                "from 2001:0db8:0000:0000:0000:0000:0000:0001 port 22 ssh2",
                "2001:db8::1",
            ),
        ],
    )
    def test_direcciones_ipv6_en_sshd(self, parser, linea, esperada):
        ev = parser(linea)
        assert ev is not None
        assert ev.source_ip == esperada
        assert ev.kind is soc.EventKind.AUTH_FAILURE

    def test_ipv6_en_servicio_generico(self, parser):
        ev = parser(
            "Jul 29 12:01:10 srv01 dovecot: auth-worker: "
            "pam(auth,2a00:1450:4003:80c::200e): authentication failure"
        )
        assert ev.source_ip == "2a00:1450:4003:80c::200e"
        assert ev.kind is soc.EventKind.AUTH_FAILURE

    def test_conexion_ipv6_conserva_el_puerto(self, parser):
        ev = parser("Jul 29 12:00:20 srv01 sshd[1234]: Connection closed by 2001:db8::5 port 52001")
        assert ev.source_ip == "2001:db8::5"
        assert ev.port == 52001
        assert ev.kind is soc.EventKind.CONNECTION

    def test_fuerza_bruta_completa_por_ipv6(self):
        motor = soc.SOCEngine(sinks=[])
        lineas = [
            f"Jul 29 12:00:{i:02d} srv01 sshd[1234]: Failed password for root "
            f"from 2001:db8::bad port 51{i:03d} ssh2\n"
            for i in range(6)
        ]
        assert motor.process(lineas) == 1

    def test_una_hora_no_se_confunde_con_una_ip(self, parser):
        # "12:00:00" tiene forma de IPv6 a ojos de un regex ingenuo.
        assert soc._find_ip("Jul 29 12:00:00 texto sin direccion") is None
        assert parser("Jul 29 12:00:00 srv01 sshd[1234]: Server listening on 0.0.0.0") is not None

    @pytest.mark.parametrize(
        "texto, esperada",
        [
            ("203.0.113.5", "203.0.113.5"),
            ("[2001:db8::1]", "2001:db8::1"),
            ("10.0.0.99.", "10.0.0.99"),  # arrastra el punto de la frase
            ("no-es-una-ip", None),
            ("999.999.999.999", None),
            # Una MAC de ocho grupos es una IPv6 válida a ojos de `ipaddress`.
            ("ab:cd:ef:12:34:56:78:90", None),
            ("ab:cd:ef:12:34:56", None),
            ("", None),
            (None, None),
        ],
    )
    def test_validacion_de_direcciones(self, texto, esperada):
        assert soc._parse_ip(texto) == esperada


class TestListaBlanca:
    def test_direccion_suelta(self):
        lista = soc.Allowlist(["10.0.0.5"])
        assert "10.0.0.5" in lista
        assert "10.0.0.6" not in lista

    def test_red_cidr(self):
        lista = soc.Allowlist(["192.168.0.0/16"])
        assert "192.168.44.7" in lista
        assert "192.169.0.1" not in lista

    def test_cidr_ipv6(self):
        lista = soc.Allowlist(["2001:db8::/32"])
        assert "2001:db8::dead" in lista
        assert "2001:db9::dead" not in lista

    def test_familias_mezcladas_no_se_cruzan(self):
        lista = soc.Allowlist(["10.0.0.0/8", "2001:db8::/32"])
        assert "10.1.2.3" in lista
        assert "2001:db8::1" in lista
        assert "203.0.113.5" not in lista

    def test_varias_entradas_separadas_por_comas(self):
        lista = soc.Allowlist(["10.0.0.0/8, 172.16.0.0/12"])
        assert len(lista) == 2
        assert "172.16.5.5" in lista

    def test_entrada_invalida_falla_pronto(self):
        with pytest.raises(ValueError):
            soc.Allowlist(["no-es-una-red"])

    def test_lista_vacia_no_excluye_nada(self):
        assert not soc.Allowlist([])
        assert "10.0.0.1" not in soc.Allowlist([])

    def test_el_motor_no_alerta_de_un_origen_de_confianza(self):
        motor = soc.SOCEngine(sinks=[], allowlist=["203.0.113.0/24"])
        assert motor.process(soc.demo_lines()) == 0
        assert motor.stats["allowed"] > 0

    def test_el_origen_de_confianza_no_ocupa_memoria(self):
        motor = soc.SOCEngine(sinks=[], allowlist=["203.0.113.0/24"])
        motor.process(soc.demo_lines())
        # Ni siquiera llega a los detectores, así que no hay ventana para esa IP.
        for detector in motor.detectors:
            assert detector.window("203.0.113.5") == []


class TestMarcasDeTiempo:
    def test_zona_horaria_configurable(self):
        p = soc.SyslogParser(tz=UTC, reference=datetime(2026, 8, 1, tzinfo=UTC))
        ev = p("Jul 29 12:00:00 srv01 sshd[1234]: Connection closed by 10.0.0.1 port 22")
        assert ev.timestamp.tzinfo == UTC
        assert ev.timestamp.hour == 12

    def test_ano_deducido_hacia_atras_en_el_cambio_de_ano(self):
        # El 1 de enero, una línea de diciembre pertenece al año anterior.
        referencia = datetime(2026, 1, 1, 0, 30, tzinfo=UTC)
        p = soc.SyslogParser(tz=UTC, reference=referencia)
        ev = p("Dec 31 23:59:00 srv01 sshd[1234]: Connection closed by 10.0.0.1 port 22")
        assert ev.timestamp.year == 2025
        # Y la marca queda en el pasado, como debe ser.
        assert ev.timestamp < referencia

    def test_ano_en_curso_para_fechas_pasadas(self):
        p = soc.SyslogParser(tz=UTC, reference=datetime(2026, 8, 1, tzinfo=UTC))
        ev = p("Jul 29 12:00:00 srv01 sshd[1234]: Connection closed by 10.0.0.1 port 22")
        assert ev.timestamp.year == 2026


# ---------------------------------------------------------------------------
# Modelo de datos
# ---------------------------------------------------------------------------


class TestModelo:
    def test_orden_de_gravedades(self):
        assert soc.Severity.INFO.rank < soc.Severity.LOW.rank < soc.Severity.MEDIUM.rank
        assert soc.Severity.MEDIUM.rank < soc.Severity.HIGH.rank < soc.Severity.CRITICAL.rank

    def test_gravedad_admite_cadenas_en_ingles_y_espanol(self):
        assert soc.Severity.coerce("high") is soc.Severity.HIGH
        assert soc.Severity.coerce("alta") is soc.Severity.HIGH
        assert soc.Severity.coerce(soc.Severity.LOW) is soc.Severity.LOW

    def test_alerta_normaliza_la_gravedad(self):
        alerta = soc.Alert("d", "high", "titulo", "descripcion", ATACANTE)
        assert alerta.severity is soc.Severity.HIGH
        assert alerta.rank == 3

    def test_alerta_serializable(self):
        alerta = soc.Alert("d", soc.Severity.HIGH, "t", "desc", ATACANTE, events=[evento()])
        datos = json.loads(json.dumps(alerta.to_dict()))
        assert datos["severity"] == "alta"
        assert datos["source_ip"] == ATACANTE
        assert len(datos["events"]) == 1


# ---------------------------------------------------------------------------
# Detectores
# ---------------------------------------------------------------------------


class TestFuerzaBruta:
    def test_salta_al_alcanzar_el_umbral(self):
        det = soc.SSHBruteForceDetector(threshold=5)
        alertas = alimentar(det, [evento(segundos=i) for i in range(5)])
        assert len(alertas) == 1
        assert alertas[0].severity is soc.Severity.HIGH
        assert ATACANTE in alertas[0].title

    def test_no_salta_por_debajo_del_umbral(self):
        det = soc.SSHBruteForceDetector(threshold=10)
        assert alimentar(det, [evento(segundos=i) for i in range(4)]) == []

    def test_ignora_eventos_que_no_son_fallos_ssh(self):
        det = soc.SSHBruteForceDetector(threshold=3)
        otros = [
            evento(segundos=0, kind=soc.EventKind.AUTH_SUCCESS),
            evento(segundos=1, kind=soc.EventKind.CONNECTION),
            evento(segundos=2, kind=soc.EventKind.OTHER),
            # Fallo de autenticación, pero de otro servicio.
            evento(segundos=3, servicio="dovecot"),
        ]
        assert alimentar(det, otros) == []

    def test_ips_distintas_no_se_suman(self):
        det = soc.SSHBruteForceDetector(threshold=5)
        eventos = [evento(segundos=i, ip=f"10.0.0.{i}") for i in range(10)]
        assert alimentar(det, eventos) == []

    def test_eventos_fuera_de_ventana_no_acumulan(self):
        det = soc.SSHBruteForceDetector(window_seconds=60, threshold=5)
        # Un fallo cada dos minutos jamás debe considerarse fuerza bruta.
        eventos = [evento(segundos=i * 120) for i in range(10)]
        assert alimentar(det, eventos) == []

    def test_la_alerta_lista_los_usuarios_probados(self):
        det = soc.SSHBruteForceDetector(threshold=3)
        eventos = [evento(segundos=i, usuario=u) for i, u in enumerate(["root", "admin", "test"])]
        alerta = alimentar(det, eventos)[0]
        assert "admin, root, test" in alerta.description


class TestEscaneoPuertos:
    def _conexion(self, i: int) -> soc.Event:
        return evento(segundos=i, kind=soc.EventKind.CONNECTION, usuario=None, puerto=50000 + i)

    def test_salta_con_muchos_puertos_distintos(self):
        det = soc.PortScanDetector(threshold=4)
        alertas = alimentar(det, [self._conexion(i) for i in range(4)])
        assert len(alertas) == 1
        assert alertas[0].detector == "escaneo_puertos"
        assert "4 puertos distintos" in alertas[0].description

    def test_no_salta_con_pocos_puertos_distintos(self):
        det = soc.PortScanDetector(threshold=4, min_distinct_ports=5)
        eventos = [
            evento(segundos=i, kind=soc.EventKind.CONNECTION, usuario=None, puerto=22)
            for i in range(6)
        ]
        assert alimentar(det, eventos) == []

    def test_ignora_eventos_sin_puerto(self):
        det = soc.PortScanDetector(threshold=2)
        eventos = [
            evento(segundos=i, kind=soc.EventKind.CONNECTION, usuario=None, puerto=None)
            for i in range(10)
        ]
        assert alimentar(det, eventos) == []


class TestTormentaAutenticacion:
    def test_salta_entre_varios_servicios(self):
        det = soc.AuthFailStormDetector(threshold=4)
        eventos = [
            evento(segundos=0, servicio="sshd"),
            evento(segundos=1, servicio="sshd"),
            evento(segundos=2, servicio="dovecot"),
            evento(segundos=3, servicio="vsftpd"),
        ]
        alerta = alimentar(det, eventos)[0]
        assert "dovecot, sshd, vsftpd" in alerta.description
        # Afectar a varios servicios eleva la gravedad.
        assert alerta.severity is soc.Severity.HIGH

    def test_un_solo_servicio_mantiene_gravedad_media(self):
        det = soc.AuthFailStormDetector(threshold=3)
        alerta = alimentar(det, [evento(segundos=i, servicio="sshd") for i in range(3)])[0]
        assert alerta.severity is soc.Severity.MEDIUM

    def test_ignora_autenticaciones_correctas(self):
        det = soc.AuthFailStormDetector(threshold=3)
        eventos = [evento(segundos=i, kind=soc.EventKind.AUTH_SUCCESS) for i in range(10)]
        assert alimentar(det, eventos) == []


# ---------------------------------------------------------------------------
# Motor
# ---------------------------------------------------------------------------


class TestMotor:
    def test_el_escenario_de_demo_genera_las_tres_alertas(self):
        motor = soc.SOCEngine(sinks=[])
        emitidos = {
            alerta.detector for linea in soc.demo_lines() for alerta in motor._process_line(linea)
        }
        assert emitidos == {"ssh_fuerza_bruta", "escaneo_puertos", "tormenta_autenticacion"}

    def test_lista_de_sinks_vacia_no_escribe_por_consola(self, capsys):
        motor = soc.SOCEngine(sinks=[])
        motor.process(soc.demo_lines())
        assert capsys.readouterr().out == ""

    def test_filtro_por_gravedad_minima(self):
        alto = soc.SOCEngine(sinks=[], min_severity=soc.Severity.HIGH)
        alto.process(soc.demo_lines())
        assert alto.stats["alerts"] >= 1

        critico = soc.SOCEngine(sinks=[], min_severity=soc.Severity.CRITICAL)
        critico.process(soc.demo_lines())
        assert critico.stats["alerts"] == 0

    def test_estadisticas_coherentes(self):
        motor = soc.SOCEngine(sinks=[])
        motor.process(soc.demo_lines())
        assert motor.stats["lines"] == 23
        assert motor.stats["events"] == motor.stats["lines"]  # todas parseables
        assert motor.stats["alerts"] == 3

    def test_una_salida_rota_no_tumba_el_motor(self):
        class SinkRoto(soc.AlertSink):
            def emit(self, alert):
                raise RuntimeError("boom")

        motor = soc.SOCEngine(sinks=[SinkRoto()])
        assert motor.process(soc.demo_lines()) == 3


class TestSinks:
    def test_json_escribe_jsonl_valido(self, tmp_path):
        destino = tmp_path / "alertas.jsonl"
        sink = soc.JSONSink(destino)
        motor = soc.SOCEngine(sinks=[sink])
        motor.process(soc.demo_lines())
        motor.close()

        lineas = destino.read_text(encoding="utf-8").strip().splitlines()
        assert len(lineas) == 3
        registro = json.loads(lineas[0])
        assert registro["detector"] == "ssh_fuerza_bruta"
        assert registro["severity"] == "alta"
        assert registro["events"]

    def test_csv_escribe_la_cabecera_una_sola_vez(self, tmp_path):
        destino = tmp_path / "alertas.csv"
        for _ in range(2):
            sink = soc.CSVSink(destino)
            motor = soc.SOCEngine(sinks=[sink])
            motor.process(soc.demo_lines())
            motor.close()

        lineas = destino.read_text(encoding="utf-8").strip().splitlines()
        assert lineas[0].startswith("timestamp,detector")
        assert sum(1 for linea in lineas if linea.startswith("timestamp,")) == 1
        assert len(lineas) == 1 + 6  # cabecera + 3 alertas × 2 ejecuciones

    def test_webhook_envia_las_alertas(self, servidor_webhook):
        url, recibidas = servidor_webhook
        sink = soc.WebhookSink(url)
        motor = soc.SOCEngine(sinks=[sink])
        motor.process(soc.demo_lines())

        assert len(recibidas) == 3
        assert sink.failures == 0
        assert recibidas[0]["text"].startswith("[ALTA] Fuerza bruta SSH")
        assert recibidas[0]["detector"] == "ssh_fuerza_bruta"

    def test_webhook_recorta_los_eventos_de_contexto(self, servidor_webhook):
        url, recibidas = servidor_webhook
        motor = soc.SOCEngine(sinks=[soc.WebhookSink(url)])
        motor.process(soc.demo_lines())
        for alerta in recibidas:
            assert len(alerta["events"]) <= soc.WebhookSink.MAX_EVENTOS
            assert alerta["event_count"] >= len(alerta["events"])

    def test_webhook_caido_no_tumba_el_motor(self):
        sink = soc.WebhookSink("http://127.0.0.1:1/no-existe", timeout=0.2)
        motor = soc.SOCEngine(sinks=[sink])
        assert motor.process(soc.demo_lines()) == 3
        assert sink.failures == 3

    @pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://host/x", "/ruta/local"])
    def test_webhook_rechaza_esquemas_no_http(self, url):
        with pytest.raises(ValueError):
            soc.WebhookSink(url)

    def test_consola_sin_color_al_redirigir(self, tmp_path):
        destino = tmp_path / "salida.txt"
        with destino.open("w", encoding="utf-8") as fp:
            sink = soc.StdoutSink(stream=fp)
            sink.emit(soc.Alert("d", soc.Severity.HIGH, "titulo", "descripcion", ATACANTE))
        assert "\033[" not in destino.read_text(encoding="utf-8")

    def test_consola_con_color_forzado(self, tmp_path):
        destino = tmp_path / "salida.txt"
        with destino.open("w", encoding="utf-8") as fp:
            sink = soc.StdoutSink(stream=fp, color=True)
            sink.emit(soc.Alert("d", soc.Severity.HIGH, "titulo", "descripcion", ATACANTE))
        assert "\033[31m" in destino.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


class TestCLI:
    def test_analizar_sin_fichero_ni_demo_falla_con_mensaje_claro(self, capsys):
        with pytest.raises(SystemExit) as exc:
            soc.main(["analizar"])
        assert exc.value.code == 2
        assert "--demo" in capsys.readouterr().err

    def test_fichero_inexistente_devuelve_codigo_de_error(self, capsys, tmp_path):
        assert soc.main(["analizar", str(tmp_path / "no-existe.log"), "-q"]) == 2
        assert "no se encuentra" in capsys.readouterr().err

    def test_demo_termina_correctamente(self, capsys):
        assert soc.main(["analizar", "--demo", "--sin-color"]) == 0
        assert "Fuerza bruta SSH" in capsys.readouterr().out

    def test_alias_en_ingles_sigue_funcionando(self, capsys):
        assert soc.main(["run", "--demo", "-q"]) == 0

    def test_listado_de_detectores(self, capsys):
        assert soc.main(["detectores"]) == 0
        salida = capsys.readouterr().out
        for nombre in ("ssh_fuerza_bruta", "escaneo_puertos", "tormenta_autenticacion"):
            assert nombre in salida

    def test_lee_de_la_entrada_estandar(self, capsys, monkeypatch):
        import io

        monkeypatch.setattr(soc.sys, "stdin", io.StringIO("".join(soc.demo_lines())))
        assert soc.main(["analizar", "-", "--sin-color"]) == 0
        salida = capsys.readouterr().out
        assert "entrada estándar" in salida
        assert "Fuerza bruta SSH" in salida

    def test_excluir_acepta_cidr(self, capsys):
        assert soc.main(["analizar", "--demo", "--excluir", "203.0.113.0/24", "--sin-color"]) == 0
        salida = capsys.readouterr().out
        assert "Fuerza bruta SSH" not in salida
        assert "de confianza=" in salida

    def test_excluir_invalido_falla_con_mensaje_claro(self, capsys):
        with pytest.raises(SystemExit) as exc:
            soc.main(["analizar", "--demo", "--excluir", "no-es-una-red"])
        assert exc.value.code == 2
        assert "--excluir" in capsys.readouterr().err

    def test_webhook_invalido_falla_con_mensaje_claro(self, capsys):
        with pytest.raises(SystemExit) as exc:
            soc.main(["analizar", "--demo", "--webhook", "file:///etc/passwd"])
        assert exc.value.code == 2
        assert "--webhook" in capsys.readouterr().err

    def test_analiza_el_log_de_ejemplo(self, capsys):
        assert soc.main(["analizar", str(HERE / "sample_auth.log"), "--sin-color"]) == 0
        assert "análisis completado" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# Regresiones de la versión 2.0.0
# ---------------------------------------------------------------------------


class TestRegresiones:
    """Cada prueba fija uno de los fallos corregidos en la 2.0.0."""

    def test_el_recuento_de_la_alerta_solo_cuenta_eventos_relevantes(self):
        """Antes, cualquier evento de la IP engordaba el contador del detector.

        Cuatro conexiones cerradas más un único fallo producían una alerta que
        anunciaba «5 intentos fallidos».
        """
        det = soc.SSHBruteForceDetector(threshold=5)
        ruido = [evento(segundos=i, kind=soc.EventKind.CONNECTION, usuario=None) for i in range(4)]
        alertas = alimentar(det, ruido + [evento(segundos=5)])
        assert alertas == []
        assert len(det.window(ATACANTE)) == 1

    def test_el_silenciamiento_caduca(self):
        """Antes el silenciamiento era permanente: una IP sólo alertaba una vez."""
        motor = soc.SOCEngine(sinks=[], cooldown_seconds=300)
        det = motor.detectors[0]

        primera = alimentar(det, [evento(segundos=i) for i in range(5)])
        assert len(primera) == 1
        assert not motor._silenced(primera[0])
        motor._fired[(primera[0].detector, primera[0].source_ip)] = primera[0].timestamp

        # Dentro del periodo de silencio: se descarta.
        repetida = soc.Alert(
            primera[0].detector,
            soc.Severity.HIGH,
            "t",
            "d",
            ATACANTE,
            timestamp=primera[0].timestamp + timedelta(seconds=60),
        )
        assert motor._silenced(repetida)

        # Pasado el periodo: vuelve a alertar.
        tardia = soc.Alert(
            primera[0].detector,
            soc.Severity.HIGH,
            "t",
            "d",
            ATACANTE,
            timestamp=primera[0].timestamp + timedelta(seconds=301),
        )
        assert not motor._silenced(tardia)

    def test_el_mismo_ataque_repetido_mas_tarde_vuelve_a_alertar(self):
        """Comprobación de extremo a extremo del silenciamiento con caducidad."""
        motor = soc.SOCEngine(sinks=[], cooldown_seconds=60)
        assert motor.process(soc.demo_lines()) == 3
        # El mismo escenario una hora después vuelve a generar alertas.
        mas_tarde = [ln.replace("Jul 29 12:", "Jul 29 13:") for ln in soc.demo_lines()]
        assert motor.process(mas_tarde) == 3

    def test_los_puertos_respetan_la_ventana_temporal(self):
        """Antes el conjunto de puertos crecía sin límite e ignoraba la ventana."""
        det = soc.PortScanDetector(window_seconds=30, threshold=10)
        eventos = [
            evento(segundos=i * 100, kind=soc.EventKind.CONNECTION, usuario=None, puerto=1000 + i)
            for i in range(50)
        ]
        assert alimentar(det, eventos) == []
        # Sólo queda el último evento, y con él un único puerto.
        assert len(det.window(ATACANTE)) == 1
        assert len(det._ports[ATACANTE]) == 1

    def test_las_ips_inactivas_se_liberan(self):
        """Antes el estado por IP crecía indefinidamente en ejecución continua."""
        det = soc.SSHBruteForceDetector(window_seconds=10, threshold=100)
        det._GC_EVERY = 50
        for i in range(200):
            det.feed(evento(segundos=i, ip=f"10.0.{i // 256}.{i % 256}"))
        assert len(det._buckets) < 50

    def test_las_lineas_desordenadas_no_rompen_la_ventana(self):
        """Una línea muy antigua intercalada no debe reabrir la ventana."""
        det = soc.SSHBruteForceDetector(window_seconds=60, threshold=3)
        det.feed(evento(segundos=1000))
        # Evento de hace horas: queda fuera de la ventana vigente.
        assert det.feed(evento(segundos=0)) is None
        assert len(det.window(ATACANTE)) == 1

    def test_follow_detecta_la_rotacion_del_log(self, tmp_path):
        """Antes el seguimiento se quedaba pegado al fichero antiguo tras logrotate."""
        log = tmp_path / "auth.log"
        log.write_text("linea inicial\n", encoding="utf-8")
        motor = soc.SOCEngine(sinks=[])

        with log.open("r", encoding="utf-8") as fp:
            fp.seek(0, 2)
            import os as _os

            estado = _os.fstat(fp.fileno())
            identidad = (estado.st_dev, estado.st_ino)

            assert motor._rotated(log, fp, identidad) is False

            # logrotate: el fichero se renombra y se crea uno nuevo.
            log.rename(tmp_path / "auth.log.1")
            log.write_text("", encoding="utf-8")
            assert motor._rotated(log, fp, identidad) is True

    def test_follow_detecta_el_truncado(self, tmp_path):
        log = tmp_path / "auth.log"
        log.write_text("una linea bastante larga\n", encoding="utf-8")
        motor = soc.SOCEngine(sinks=[])
        with log.open("r", encoding="utf-8") as fp:
            fp.seek(0, 2)
            import os as _os

            estado = _os.fstat(fp.fileno())
            identidad = (estado.st_dev, estado.st_ino)
            log.write_text("", encoding="utf-8")  # copytruncate
            assert motor._rotated(log, fp, identidad) is True
