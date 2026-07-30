#!/usr/bin/env python3
"""Genera `docs/demo.svg`: una animación de terminal con la salida real de SOC Monitor.

La demo no está dibujada a mano: se ejecuta la herramienta de verdad, se captura
su salida y se convierte en un SVG animado con CSS. Así la imagen del README no
puede quedarse desfasada respecto al comportamiento real — basta con volver a
ejecutar este script.

Uso:  python tools/generar_demo.py
"""

from __future__ import annotations

import html
import subprocess
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
SALIDA = RAIZ / "docs" / "demo.svg"

COMANDO = "soc-monitor analizar /var/log/auth.log --seguir"

# Paleta alineada con el tema oscuro de GitHub.
FONDO = "#0d1117"
BORDE = "#30363d"
BARRA = "#161b22"
TEXTO = "#c9d1d9"
TENUE = "#6e7681"
PROMPT = "#3fb950"
RUTA = "#58a6ff"
COLOR_GRAVEDAD = {"ALTA": "#f85149", "MEDIA": "#d29922", "BAJA": "#3fb950", "CRITICA": "#bc8cff"}

# Geometría, en píxeles.
ANCHO_CAR = 7.42
ALTO_LINEA = 20
MARGEN_X = 22
BARRA_ALTO = 34
PADDING_SUP = 18
PADDING_INF = 20

# Ritmo de la animación, en segundos.
TECLEO = 1.1
PAUSA_TRAS_COMANDO = 0.5
ENTRE_LINEAS = 0.42
PAUSA_FINAL = 3.0


def capturar_salida() -> list[str]:
    """Ejecuta la herramienta y devuelve las líneas de su salida real."""
    proceso = subprocess.run(
        [sys.executable, str(RAIZ / "soc_monitor.py"), "analizar", "--demo", "--sin-color"],
        capture_output=True,
        text=True,
        check=True,
    )
    lineas = proceso.stdout.rstrip("\n").split("\n")
    # La última línea del modo demo habla del "escenario de demostración"; en la
    # imagen queremos que parezca lo que vería alguien vigilando un log real.
    return [ln for ln in lineas if not ln.startswith("— fin del escenario")]


def color_de(linea: str) -> str:
    """Elige el color de una línea según lo que representa."""
    for gravedad, color in COLOR_GRAVEDAD.items():
        if f"[{gravedad}" in linea:
            return color
    if linea.lstrip().startswith("↳"):
        return TENUE
    return TEXTO


def construir_svg(lineas: list[str]) -> str:
    prompt = "$ "
    todas = [prompt + COMANDO, "", *lineas]
    columnas = max(len(ln) for ln in todas) + 4
    ancho = int(columnas * ANCHO_CAR + MARGEN_X * 2)
    alto = int(BARRA_ALTO + PADDING_SUP + len(todas) * ALTO_LINEA + PADDING_INF)

    # Instante en el que aparece cada línea de salida.
    inicio_salida = TECLEO + PAUSA_TRAS_COMANDO
    tiempos = [inicio_salida + i * ENTRE_LINEAS for i in range(len(lineas))]
    total = round((tiempos[-1] if tiempos else inicio_salida) + PAUSA_FINAL, 2)

    def pct(segundos: float) -> float:
        return round(min(100.0, max(0.0, segundos / total * 100)), 3)

    reglas = [
        f"@keyframes teclear{{0%{{width:0}}{pct(TECLEO)}%,100%{{width:{len(COMANDO) * ANCHO_CAR:.1f}px}}}}",
        "@keyframes cursor{0%,49%{opacity:1}50%,100%{opacity:0}}",
    ]
    for i, t in enumerate(tiempos):
        aparece = pct(t)
        reglas.append(
            f"@keyframes ap{i}{{0%,{aparece}%{{opacity:0}}{min(aparece + 0.4, 100):.3f}%,100%{{opacity:1}}}}"
        )

    estilo = "\n".join(
        [
            ".t{font-family:ui-monospace,'SF Mono',SFMono-Regular,Menlo,Consolas,"
            "'DejaVu Sans Mono',monospace;font-size:13px}",
            f".cmd{{animation:teclear {total}s steps({len(COMANDO)}) infinite}}",
            ".cur{animation:cursor 1s step-end infinite}",
            *[
                f".l{i}{{opacity:0;animation:ap{i} {total}s linear infinite}}"
                for i in range(len(lineas))
            ],
            *reglas,
        ]
    )

    y_base = BARRA_ALTO + PADDING_SUP + 14
    partes: list[str] = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{ancho}" height="{alto}" '
        f'viewBox="0 0 {ancho} {alto}" role="img" '
        f'aria-label="SOC Monitor detectando un ataque en tiempo real">',
        f"<style>{estilo}</style>",
        f'<rect width="{ancho}" height="{alto}" rx="10" fill="{FONDO}" stroke="{BORDE}"/>',
        f'<path d="M0 10a10 10 0 0 1 10-10h{ancho - 20}a10 10 0 0 1 10 10v{BARRA_ALTO - 10}H0z" '
        f'fill="{BARRA}"/>',
        f'<line x1="0" y1="{BARRA_ALTO}" x2="{ancho}" y2="{BARRA_ALTO}" stroke="{BORDE}"/>',
    ]
    for i, color in enumerate(("#ff5f57", "#febc2e", "#28c840")):
        partes.append(f'<circle cx="{22 + i * 18}" cy="{BARRA_ALTO / 2}" r="5.5" fill="{color}"/>')
    partes.append(
        f'<text class="t" x="{ancho / 2}" y="{BARRA_ALTO / 2 + 4}" fill="{TENUE}" '
        f'text-anchor="middle" font-size="11.5">soc-monitor</text>'
    )

    # Línea de comando, revelada como si se estuviera tecleando.
    partes.append(f'<text class="t" x="{MARGEN_X}" y="{y_base}" fill="{PROMPT}">$</text>')
    x_cmd = MARGEN_X + 2 * ANCHO_CAR
    partes.append(
        f'<clipPath id="teclado"><rect class="cmd" x="{x_cmd}" y="{y_base - 14}" '
        f'width="0" height="{ALTO_LINEA}"/></clipPath>'
    )
    partes.append(
        f'<text class="t" x="{x_cmd}" y="{y_base}" fill="{RUTA}" clip-path="url(#teclado)">'
        f"{html.escape(COMANDO)}</text>"
    )
    partes.append(
        f'<rect class="cur" x="{x_cmd + len(COMANDO) * ANCHO_CAR + 2}" y="{y_base - 11}" '
        f'width="7" height="14" fill="{TEXTO}" opacity="0.8"/>'
    )

    for i, linea in enumerate(lineas):
        y = y_base + (i + 2) * ALTO_LINEA
        partes.append(
            f'<text class="t l{i}" x="{MARGEN_X}" y="{y}" fill="{color_de(linea)}" '
            f'xml:space="preserve">{html.escape(linea)}</text>'
        )

    partes.append("</svg>")
    return "\n".join(partes)


def main() -> int:
    lineas = capturar_salida()
    SALIDA.parent.mkdir(parents=True, exist_ok=True)
    SALIDA.write_text(construir_svg(lineas), encoding="utf-8")
    print(f"{SALIDA.relative_to(RAIZ)} generado a partir de {len(lineas)} líneas de salida real")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
