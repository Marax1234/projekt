"""
cli_ui.py – Terminal-UI-Hilfsfunktionen

Beschreibung: Box-Drawing-Chars für die laufende CLI-Oberfläche sowie
              figlet via subprocess für den Startup-Banner. Keine externen
              Python-Pakete erforderlich – nur die stdlib.

Autor:        Gruppe 2
Datum:        2026-03-26
Modul:        Network Security 2026
"""

import select
import shutil
import subprocess
import sys

# ---------------------------------------------------------------------------
# Box-Drawing-Zeichen (Unicode, hardcoded – kein externes Paket)
# ---------------------------------------------------------------------------
#  Einfache Linie          Doppelte Linie
#  ┌──┬──┐                 ╔══╦══╗
#  │  │  │                 ║  ║  ║
#  ├──┼──┤                 ╠══╬══╣
#  └──┴──┘                 ╚══╩══╝

_TL  = "┌"   # top-left (einfach)
_TR  = "┐"   # top-right
_BL  = "└"   # bottom-left
_BR  = "┘"   # bottom-right
_H   = "─"   # horizontal
_V   = "│"   # vertical

_DTL = "╔"   # top-left (doppelt)
_DTR = "╗"   # top-right
_DBL = "╚"   # bottom-left
_DBR = "╝"   # bottom-right
_DH  = "═"   # double horizontal
_DV  = "║"   # double vertical

_MSG_BAR = "┃"   # Nachrichtenrand (empfangene Nachrichten)
_SEP     = "╌"   # weiche Trennlinie (Info-Zeilen)


# ---------------------------------------------------------------------------
# Hilfsfunktionen
# ---------------------------------------------------------------------------

def _term_breite() -> int:
    """Gibt die aktuelle Terminal-Breite zurück (Fallback: 80)."""
    return shutil.get_terminal_size((80, 24)).columns


# ---------------------------------------------------------------------------
# Startup-Banner (figlet via subprocess, Fallback: ASCII-Box)
# ---------------------------------------------------------------------------

def banner_anzeigen() -> None:
    """Zeigt den Startup-Banner an.

    Versucht zuerst ``figlet`` über subprocess. Ist figlet nicht installiert
    oder schlägt es fehl, wird eine hardcoded doppelte Box-Zeichnung genutzt.
    """
    breite = _term_breite()
    try:
        ergebnis = subprocess.run(
            ["figlet", "-w", str(breite), "-f", "standard", "P2P Chat"],
            capture_output=True,
            text=True,
            timeout=3,
        )
        if ergebnis.returncode == 0 and ergebnis.stdout.strip():
            print(ergebnis.stdout.rstrip())
            return
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass

    # Fallback: doppelt-umrandete ASCII-Box
    zeilen = [
        "  ____  ____  ____     ____ _           _   ",
        " |  _ \\|___ \\|  _ \\   / ___| |__   __ _| |_ ",
        " | |_) | __) | |_) | | |   | '_ \\ / _` | __|",
        " |  __/ / __/|  __/  | |___| | | | (_| | |_ ",
        " |_|   |_____|_|      \\____|_| |_|\\__,_|\\__|",
    ]
    innen_w = max(len(z) for z in zeilen) + 4
    box_w   = max(innen_w, breite - 2)
    print(_DTL + _DH * box_w + _DTR)
    for zeile in zeilen:
        print(_DV + zeile.center(box_w) + _DV)
    print(_DBL + _DH * box_w + _DBR)

    untertitel = "NetSec 2026 · Gruppe 2 · P2P-Chat v1.0"
    print(_DV + untertitel.center(box_w) + _DV)
    print(_DBL + _DH * box_w + _DBR)


# ---------------------------------------------------------------------------
# Laufende UI-Elemente
# ---------------------------------------------------------------------------

def trennlinie() -> None:
    """Gibt eine volle horizontale Trennlinie aus."""
    print(_H * _term_breite())


def status_box(modus: str, port: int, name: str) -> None:
    """Zeigt eine eingerahmte Status-Zeile mit Verbindungsinfos.

    Beispiel:
        ┌─ Status ──────────────────────────────────┐
        │  Modus: SERVER  │  Port: 6769  │  Name: X  │
        └────────────────────────────────────────────┘
    """
    breite = _term_breite()
    felder = f"  Modus: {modus.upper():6}  {_V}  Port: {port}  {_V}  Name: {name}  "
    inner  = max(len(felder), breite - 2)

    kopf   = _TL + _H + " Status " + _H * (inner - 9) + _TR
    mitte  = _V  + felder.ljust(inner) + _V
    fuss   = _BL + _H * inner + _BR

    print(kopf)
    print(mitte)
    print(fuss)


def info_zeile(text: str) -> None:
    """Gibt eine weiche Info-Trennlinie aus (z.B. Verbindungs-Events).

    Beispiel:  ╌╌ Client verbunden ╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌
    """
    breite  = _term_breite()
    kern    = f" {text} "
    rechts  = max(0, breite - len(kern) - 2)
    print(f"{_SEP}{_SEP}{kern}{_SEP * rechts}")


def nachricht_ausgeben(absender: str, text: str, zeitstempel: str) -> None:
    """Gibt eine empfangene Nachricht formatiert aus und stellt den Prompt wieder her.

    Beispiel:
        ┃ [14:32:05] Alice: Hallo!
        >
    """
    anzeige_zeit = zeitstempel[11:19] if len(zeitstempel) >= 19 else zeitstempel
    print(f"\r{_MSG_BAR} [{anzeige_zeit}] {absender}: {text}")
    print("> ", end="", flush=True)


def eingabe_prompt(trenn_ereignis=None) -> str | None:
    """Liest eine Zeile vom Nutzer (mit ``>``-Prompt).

    Parameter:
        trenn_ereignis: Optionales threading.Event – gibt None zurück wenn es
                        gesetzt wird bevor der Nutzer Enter drückt.

    Rückgabe:
        Eingabe-String oder None wenn die Verbindung von der Gegenseite getrennt wurde.
    """
    print("> ", end="", flush=True)
    while True:
        if trenn_ereignis is not None and trenn_ereignis.is_set():
            print()  # Cursor auf neue Zeile
            return None
        r, _, _ = select.select([sys.stdin], [], [], 0.5)
        if r:
            zeile = sys.stdin.readline()
            if not zeile:  # EOF
                raise EOFError
            return zeile.strip()
