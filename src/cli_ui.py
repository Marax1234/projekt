"""
cli_ui.py – Terminal-UI-Hilfsfunktionen (curses-basiert)

Beschreibung: Stellt eine curses-basierte TUI mit drei festen Bereichen bereit:
              - Chat-Fenster (oben, scrollend): Chatnachrichten
              - Status-Zeile (Mitte, invertiert): technische Logs und Events
              - Eingabe-Bereich (unten): asynchron-sichere Nutzereingabe

              Fallback auf print()-Ausgabe wenn die TUI nicht initialisiert ist
              (z.B. für Tests oder den Banner-/Username-Bereich vor curses.wrapper).

              Alle curses-Operationen werden durch ein threading.Lock serialisiert,
              sodass Netzwerk-Thread und Eingabe-Thread gleichzeitig sicher schreiben
              können.

Autor:        Gruppe 2
Datum:        2026-04-19
Modul:        Network Security 2026
"""

import curses
import locale
import select
import shutil
import subprocess
import sys
import threading
import time
from typing import Optional

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
# Muss VOR curses.wrapper() aufgerufen werden – nutzt print().
# ---------------------------------------------------------------------------

def banner_anzeigen() -> None:
    """Zeigt den Startup-Banner an.

    Versucht zuerst ``figlet`` über subprocess. Ist figlet nicht installiert
    oder schlägt es fehl, wird eine hardcoded doppelte Box-Zeichnung genutzt.
    Muss vor der TUI-Initialisierung aufgerufen werden.
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


def username_abfragen(standard: str = "Peer") -> str:
    """Fragt den Benutzer nach seinem Anzeigenamen (vor TUI-Start, nutzt input()).

    Gibt den eingegebenen Namen zurück oder ``standard`` wenn nichts eingegeben wurde.
    """
    try:
        name = input(f"Bitte Benutzernamen eingeben [{standard}]: ").strip()
        return name if name else standard
    except (EOFError, KeyboardInterrupt):
        return standard


# ---------------------------------------------------------------------------
# CursesTUI – Dreifenster-Layout
# ---------------------------------------------------------------------------

class CursesTUI:
    """curses-basierte TUI mit Chat-, Status- und Eingabe-Fenster.

    Layout (von oben nach unten):
        chat_win   : h-2 Zeilen – scrollende Chatnachrichten
        status_win : 1 Zeile    – invertiert, technische Statusmeldungen
        input_win  : 1 Zeile    – Nutzereingabe ohne lokales Echo

    Thread-Sicherheit:
        Alle curses-Operationen werden durch ``self._lock`` serialisiert.
        Der Eingabe-Thread hält das Lock nur für die Dauer eines einzelnen
        ``get_wch()``-Aufrufs bzw. eines Zeichen-Redraws (< 1 ms).
    """

    def __init__(self, stdscr) -> None:
        self._stdscr = stdscr
        self._lock   = threading.Lock()
        self._cursor_x     = 2   # Cursorposition nach "> " in der Eingabezeile
        self._eingabe_puffer = ""  # Aktueller Puffer für Redraw nach fremden Refreshes

        try:
            locale.setlocale(locale.LC_ALL, "")
        except locale.Error:
            pass

        curses.noecho()
        curses.cbreak()
        stdscr.keypad(True)

        if curses.has_colors():
            curses.start_color()
            curses.use_default_colors()

        self._fenster_aufbauen()

    # ------------------------------------------------------------------
    # Fensteraufbau
    # ------------------------------------------------------------------

    def _fenster_aufbauen(self) -> None:
        """Erstellt oder erneuert alle Fenster basierend auf aktueller Terminalgröße."""
        h, w = self._stdscr.getmaxyx()
        self._h = h
        self._w = w

        chat_h = max(1, h - 2)

        self._chat_win = curses.newwin(chat_h, w, 0, 0)
        self._chat_win.scrollok(True)
        self._chat_win.idlok(True)

        self._status_win = curses.newwin(1, w, chat_h, 0)
        self._status_win.bkgd(' ', curses.A_REVERSE)

        self._input_win = curses.newwin(1, w, h - 1, 0)
        self._input_win.nodelay(True)
        self._input_win.keypad(True)

        # Initiale Hinweiszeile
        hint = " Nachrichten eingeben · 'quit' zum Beenden "
        try:
            self._status_win.addstr(0, 0, hint[: w - 1], curses.A_REVERSE)
        except curses.error:
            pass
        self._status_win.refresh()
        self._eingabe_zeichnen(self._eingabe_puffer)

    # ------------------------------------------------------------------
    # Interne Zeichenhilfen (Lock muss bereits gehalten werden)
    # ------------------------------------------------------------------

    def _eingabe_zeichnen(self, text: str) -> None:
        """Zeichnet die Eingabezeile neu. Lock muss vom Aufrufer gehalten werden."""
        try:
            self._input_win.clear()
            anzeige = ("> " + text)[: self._w - 1]
            self._input_win.addstr(0, 0, anzeige)
            self._cursor_x = len(anzeige)
        except curses.error:
            pass
        self._input_win.refresh()

    def _cursor_wiederherstellen(self) -> None:
        """Bewegt Cursor nach einem fremden Refresh zurück in die Eingabezeile."""
        try:
            self._input_win.move(0, min(self._cursor_x, self._w - 1))
            self._input_win.refresh()
        except curses.error:
            pass

    # ------------------------------------------------------------------
    # Öffentliche, thread-sichere Methoden
    # ------------------------------------------------------------------

    def chat_hinzufuegen(self, zeile: str) -> None:
        """Fügt eine Zeile zum Chat-Fenster hinzu (thread-sicher)."""
        with self._lock:
            try:
                self._chat_win.addstr(zeile + "\n")
            except curses.error:
                pass
            self._chat_win.refresh()
            self._cursor_wiederherstellen()

    def status_setzen(self, text: str) -> None:
        """Setzt den Statustext in der invertierten Statuszeile (thread-sicher).

        Überschreibt den vorherigen Statustext vollständig.
        """
        with self._lock:
            try:
                self._status_win.clear()
                self._status_win.addstr(0, 0, text[: self._w - 1], curses.A_REVERSE)
            except curses.error:
                pass
            self._status_win.refresh()
            self._cursor_wiederherstellen()

    def eingabe_lesen(self, trenn_ereignis=None) -> Optional[str]:
        """Liest eine Zeile vom Nutzer zeichenweise über curses.

        Läuft als Blocking-Funktion in einem Thread (via ``asyncio.to_thread``).
        ``get_wch()`` wird mit ``nodelay(True)`` im nicht-blockierenden Modus
        aufgerufen; zwischen Polls wird 50 ms geschlafen, sodass das Lock
        minimal kontendiert wird.

        Unicode-Zeichen (z.B. deutsche Umlaute) werden korrekt über ``get_wch()``
        empfangen – kein manuelles Byte-Decoding erforderlich.

        Parameter:
            trenn_ereignis: threading.Event – Rückgabe None wenn gesetzt.

        Rückgabe:
            Eingabe-String (auch ""), oder None bei Verbindungstrennung.
        """
        puffer: list[str] = []

        while True:
            if trenn_ereignis is not None and trenn_ereignis.is_set():
                return None

            with self._lock:
                try:
                    ch = self._input_win.get_wch()
                except curses.error:
                    ch = -1

            if ch == -1:
                time.sleep(0.05)
                continue

            if isinstance(ch, str):
                if ch in ("\n", "\r"):
                    ergebnis = "".join(puffer)
                    with self._lock:
                        self._eingabe_puffer = ""
                        self._eingabe_zeichnen("")
                    return ergebnis
                elif ch in ("\x7f", "\x08"):  # Rücktaste (DEL / BS)
                    if puffer:
                        puffer.pop()
                        with self._lock:
                            self._eingabe_puffer = "".join(puffer)
                            self._eingabe_zeichnen(self._eingabe_puffer)
                elif ord(ch) >= 32:  # Druckbares Zeichen inkl. Unicode
                    puffer.append(ch)
                    with self._lock:
                        self._eingabe_puffer = "".join(puffer)
                        self._eingabe_zeichnen(self._eingabe_puffer)

            elif isinstance(ch, int):
                if ch in (10, 13, curses.KEY_ENTER):
                    ergebnis = "".join(puffer)
                    with self._lock:
                        self._eingabe_puffer = ""
                        self._eingabe_zeichnen("")
                    return ergebnis
                elif ch in (curses.KEY_BACKSPACE, 127, 8):
                    if puffer:
                        puffer.pop()
                        with self._lock:
                            self._eingabe_puffer = "".join(puffer)
                            self._eingabe_zeichnen(self._eingabe_puffer)
                elif ch == curses.KEY_RESIZE:
                    with self._lock:
                        try:
                            curses.update_lines_cols()
                        except AttributeError:
                            pass
                        self._fenster_aufbauen()
                        self._eingabe_puffer = "".join(puffer)
                        self._eingabe_zeichnen(self._eingabe_puffer)


# ---------------------------------------------------------------------------
# Globale TUI-Instanz
# ---------------------------------------------------------------------------

_tui: Optional[CursesTUI] = None


def tui_starten(stdscr) -> None:
    """Initialisiert die CursesTUI. Muss innerhalb von ``curses.wrapper()`` aufgerufen werden."""
    global _tui
    _tui = CursesTUI(stdscr)


# ---------------------------------------------------------------------------
# Öffentliche API – leitet an TUI weiter oder fällt auf print zurück
# ---------------------------------------------------------------------------

def trennlinie() -> None:
    """Horizontale Trennlinie (nur außerhalb der TUI; in der TUI ein No-Op)."""
    if _tui is None:
        print(_H * _term_breite())


def leerzeile() -> None:
    """Leerzeile (nur außerhalb der TUI; in der TUI ein No-Op)."""
    if _tui is None:
        print()


def chat_hinweis() -> None:
    """Gibt den Eingabe-Hinweis aus (nur außerhalb der TUI; TUI zeigt ihn in der Statuszeile)."""
    if _tui is None:
        print("  Nachrichten eingeben · 'quit' zum Beenden")


def status_box(modus: str, port: int, name: str) -> None:
    """Zeigt Verbindungsinfos (TUI: Statuszeile; sonst: eingerahmte Box).

    Beispiel (ohne TUI):
        ┌─ Status ──────────────────────────────────┐
        │  Modus: SERVER  │  Port: 6769  │  Name: X  │
        └────────────────────────────────────────────┘
    """
    if _tui is not None:
        _tui.status_setzen(f" Modus: {modus.upper()} · Port: {port} · Name: {name} ")
        return

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
    """Technische Statusmeldung (TUI: Statuszeile; sonst: weiche Trennlinie).

    Beispiel (ohne TUI):  ╌╌ Client verbunden ╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌
    """
    if _tui is not None:
        breite = _tui._w
        kern   = f" {text} "
        rechts = max(0, breite - len(kern) - 2)
        _tui.status_setzen(f"{_SEP}{_SEP}{kern}{_SEP * rechts}")
        return

    breite = _term_breite()
    kern   = f" {text} "
    rechts = max(0, breite - len(kern) - 2)
    print(f"{_SEP}{_SEP}{kern}{_SEP * rechts}")


def fehler_zeile(text: str) -> None:
    """Fehlermeldung (TUI: Chat-Fenster; sonst: auffällige Print-Ausgabe).

    Beispiel (ohne TUI):  !! Peer dauerhaft nicht erreichbar. !!
    """
    if _tui is not None:
        _tui.chat_hinzufuegen(f"!! {text} !!")
        return

    breite = _term_breite()
    kern   = f" {text} "
    pad    = max(0, (breite - len(kern) - 4) // 2)
    print(f"{'!!' + ' ' * pad}{kern}{' ' * pad + '!!'}")


def nachricht_ausgeben(absender: str, text: str, zeitstempel: str) -> None:
    """Gibt eine empfangene Nachricht formatiert aus.

    TUI: Chat-Fenster. Ohne TUI: print mit Prompt-Wiederherstellung.

    Beispiel:  ┃ [14:32:05] Alice: Hallo!
    """
    anzeige_zeit = zeitstempel[11:19] if len(zeitstempel) >= 19 else zeitstempel
    zeile = f"{_MSG_BAR} [{anzeige_zeit}] {absender}: {text}"
    if _tui is not None:
        _tui.chat_hinzufuegen(zeile)
    else:
        print(f"\r{zeile}")
        print("> ", end="", flush=True)


def eigene_nachricht_ausgeben(absender: str, text: str) -> None:
    """Zeigt eine erfolgreich gesendete eigene Nachricht mit Zeitstempel an.

    TUI: Chat-Fenster. Ohne TUI: print mit Prompt-Wiederherstellung.

    Beispiel:    [14:32:06] Du (Alice): Hallo!
    """
    import datetime
    anzeige_zeit = datetime.datetime.now().strftime("%H:%M:%S")
    zeile = f"  [{anzeige_zeit}] {absender}: {text}"
    if _tui is not None:
        _tui.chat_hinzufuegen(zeile)
    else:
        print(f"\r{zeile}")
        print("> ", end="", flush=True)


def eingabe_prompt(trenn_ereignis=None) -> Optional[str]:
    """Liest eine Zeile vom Nutzer.

    TUI: zeichenweise über curses (kein lokales Echo, Unicode-sicher).
    Ohne TUI: UTF-8-tolerantes readline vom stdin-Buffer.

    Parameter:
        trenn_ereignis: threading.Event – gibt None zurück wenn gesetzt.

    Rückgabe:
        Eingabe-String oder None wenn Verbindung getrennt wurde.
    """
    if _tui is not None:
        return _tui.eingabe_lesen(trenn_ereignis)

    # Fallback ohne TUI – liest direkt vom binären stdin-Buffer und dekodiert
    # mit errors='replace', um UnicodeDecodeError bei ungültigen Byte-Sequenzen
    # (z.B. durch Backspace über Multibyte-Zeichen) zuverlässig abzufangen.
    print("> ", end="", flush=True)
    while True:
        if trenn_ereignis is not None and trenn_ereignis.is_set():
            print()
            return None
        r, _, _ = select.select([sys.stdin], [], [], 0.5)
        if r:
            try:
                rohdaten = sys.stdin.buffer.readline()
            except AttributeError:
                # Fallback wenn buffer nicht verfügbar (z.B. in Tests)
                rohdaten = sys.stdin.readline().encode("utf-8", errors="replace")
            if not rohdaten:  # EOF
                raise EOFError
            return rohdaten.decode("utf-8", errors="replace").strip()
