"""
gui.py – Tkinter-Oberflaeche

Beschreibung: Grafische Benutzeroberflaeche fuer den P2P-Chat. Zeigt Nachrichtenverlauf,
              Eingabefeld und Statusleiste. Kommuniziert ueber queue.Queue mit dem
              Empfangs-Thread (thread-sicheres GUI-Update via root.after()).
              Sprint 5: Vollstaendige GUI mit VerbindungsDialog, ChatApp und
              thread-sicherem 3-Thread-Modell (GUI, Verbindung, Empfang).
Autor:        Gruppe 2
Datum:        2026-03-24
Modul:        Network Security 2026
"""

import logging
import queue
import sys
import threading
import tkinter as tk
from dataclasses import dataclass
from datetime import datetime
from tkinter import messagebox, ttk
from typing import Any

import konfig
from netzwerk import server_erstellen, verbindung_akzeptieren, verbindung_herstellen
from sitzung import Sitzung, SitzungsZustand

# Modul-Logger fuer alle GUI-Ereignisse
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Farb-Palette (Dark Mode – Catppuccin Mocha)
# ---------------------------------------------------------------------------
FARBEN: dict[str, str] = {
    "hintergrund":  "#1e1e2e",   # Haupt-Hintergrund
    "oberflaeche":  "#313244",   # Karten, Panels, Eingabefelder
    "primaer":      "#89b4fa",   # Primaerfarbe (Blau)
    "text":         "#cdd6f4",   # Haupttext
    "subtext":      "#a6adc8",   # Sekundaertext / Zeitstempel
    "rahmen":       "#45475a",   # Rahmen
    "erfolg":       "#a6e3a1",   # Gruen – verbunden
    "fehler":       "#f38ba8",   # Rot – getrennt / Fehler
    "warnung":      "#fab387",   # Orange – verbindend / Warnung
}

# Plattformabhaengige Schriftart
if sys.platform == "win32":
    BASIS_SCHRIFT: str = "Segoe UI"
    MONO_SCHRIFT: str = "Consolas"
elif sys.platform == "darwin":
    BASIS_SCHRIFT = "SF Pro Display"
    MONO_SCHRIFT = "Menlo"
else:
    BASIS_SCHRIFT = "Ubuntu"
    MONO_SCHRIFT = "Monospace"


# ---------------------------------------------------------------------------
# QueueEreignis – typisiertes Event fuer thread-sichere Kommunikation
# ---------------------------------------------------------------------------

@dataclass
class QueueEreignis:
    """Typisiertes Ereignis fuer die thread-sichere Queue-Kommunikation.

    Attribute:
        typ:   Ereignistyp ("verbunden" | "getrennt" | "nachricht" | "fehler" | "status")
        daten: Optionale Nutzdaten (dict, str oder None)
    """

    typ: str    # Ereignistyp fuer Verarbeitungs-Dispatch
    daten: Any = None


# ---------------------------------------------------------------------------
# VerbindungsDialog – modaler Startdialog (Task 5.2)
# ---------------------------------------------------------------------------

class VerbindungsDialog:
    """Modaler Dialog zur Konfiguration der Verbindungsparameter.

    Fragt Betriebsmodus (Server/Client), IP-Adresse, Port und Namen ab.
    Blockiert mit wait_window() bis der Nutzer bestaetigt oder abbricht.
    """

    def __init__(self, eltern: tk.Tk) -> None:
        """Erstellt und konfiguriert den modalen Verbindungsdialog.

        Parameter:
            eltern: Elternfenster (Hauptfenster der Anwendung)
        """
        self._ergebnis: dict | None = None  # Wird bei Bestaetigung befuellt

        # Toplevel-Dialog erstellen
        self._dialog = tk.Toplevel(eltern)
        self._dialog.title("Verbindung konfigurieren")
        self._dialog.configure(bg=FARBEN["hintergrund"])
        self._dialog.resizable(False, False)

        # Modal: alle Ereignisse an diesen Dialog weiterleiten
        self._dialog.grab_set()
        self._dialog.focus_force()

        # Dialog zentrieren
        breite, hoehe = 440, 330
        self._dialog.update_idletasks()
        sw = self._dialog.winfo_screenwidth()
        sh = self._dialog.winfo_screenheight()
        x = (sw - breite) // 2
        y = (sh - hoehe) // 2
        self._dialog.geometry(f"{breite}x{hoehe}+{x}+{y}")

        # ttk-Styles fuer Dialog konfigurieren
        self._style = ttk.Style(self._dialog)
        self._style.theme_use("clam")
        self._dialog_styles_anwenden()

        self._modus_var = tk.StringVar(value="server")  # Voreinstellung: Server

        self._ui_erstellen()

        # Schliessen-Kreuz = Abbrechen
        self._dialog.protocol("WM_DELETE_WINDOW", self._abbrechen)

    def _dialog_styles_anwenden(self) -> None:
        """Wendet Dark-Mode-Styles auf den Dialog an."""
        s = self._style
        s.configure(".", background=FARBEN["hintergrund"], foreground=FARBEN["text"],
                    font=(BASIS_SCHRIFT, 10))
        s.configure("TFrame", background=FARBEN["hintergrund"])
        s.configure("TLabel", background=FARBEN["hintergrund"], foreground=FARBEN["text"],
                    font=(BASIS_SCHRIFT, 10))
        s.configure("TRadiobutton", background=FARBEN["hintergrund"],
                    foreground=FARBEN["text"], font=(BASIS_SCHRIFT, 10),
                    indicatorcolor=FARBEN["primaer"])
        s.map("TRadiobutton",
              background=[("active", FARBEN["hintergrund"])],
              foreground=[("active", FARBEN["primaer"])])
        s.configure("TEntry", fieldbackground=FARBEN["oberflaeche"],
                    foreground=FARBEN["text"], insertcolor=FARBEN["text"],
                    borderwidth=1, relief="flat", padding=(8, 4))
        s.map("TEntry",
              fieldbackground=[("focus", "#3d3f5a")])
        s.configure("TButton", background=FARBEN["primaer"],
                    foreground=FARBEN["hintergrund"],
                    font=(BASIS_SCHRIFT, 10, "bold"), padding=(12, 6),
                    relief="flat", borderwidth=0)
        s.map("TButton",
              background=[("active", "#b4d0fb"), ("pressed", "#7aa2f7"),
                          ("disabled", FARBEN["rahmen"])],
              foreground=[("disabled", FARBEN["subtext"])])
        s.configure("Abbruch.TButton", background=FARBEN["oberflaeche"],
                    foreground=FARBEN["text"])
        s.map("Abbruch.TButton",
              background=[("active", FARBEN["rahmen"]), ("pressed", "#5a5c70")])
        s.configure("Titel.TLabel", font=(BASIS_SCHRIFT, 15, "bold"),
                    foreground=FARBEN["primaer"])

    def _ui_erstellen(self) -> None:
        """Erstellt alle UI-Elemente des Verbindungsdialogs."""
        haupt = ttk.Frame(self._dialog, padding=(28, 22))
        haupt.pack(fill="both", expand=True)

        # Spaltenkonfiguration: Label links, Eingabe rechts
        haupt.columnconfigure(1, weight=1)

        # --- Titel ---
        ttk.Label(haupt, text="Verbindung konfigurieren",
                  style="Titel.TLabel").grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 18))

        # --- Modus-Auswahl ---
        ttk.Label(haupt, text="Modus:").grid(row=1, column=0, sticky="w", pady=5)
        modus_frame = ttk.Frame(haupt)
        modus_frame.grid(row=1, column=1, sticky="w", pady=5)
        ttk.Radiobutton(modus_frame, text="Server  (warten)",
                        variable=self._modus_var, value="server",
                        command=self._modus_geaendert).pack(side="left", padx=(0, 16))
        ttk.Radiobutton(modus_frame, text="Client  (verbinden)",
                        variable=self._modus_var, value="client",
                        command=self._modus_geaendert).pack(side="left")

        # --- Server-IP (nur Client-Modus) ---
        ttk.Label(haupt, text="Server-IP:").grid(row=2, column=0, sticky="w", pady=5)
        self._ip_feld = ttk.Entry(haupt, width=26)
        self._ip_feld.insert(0, "192.168.56.101")
        self._ip_feld.grid(row=2, column=1, sticky="ew", pady=5)

        # --- Port ---
        ttk.Label(haupt, text="Port:").grid(row=3, column=0, sticky="w", pady=5)
        self._port_feld = ttk.Entry(haupt, width=10)
        self._port_feld.insert(0, str(konfig.PORT))
        self._port_feld.grid(row=3, column=1, sticky="w", pady=5)

        # --- Anzeigename ---
        ttk.Label(haupt, text="Anzeigename:").grid(row=4, column=0, sticky="w", pady=5)
        self._name_feld = ttk.Entry(haupt, width=26)
        self._name_feld.insert(0, "Alice")
        self._name_feld.grid(row=4, column=1, sticky="ew", pady=5)

        # --- Trennlinie ---
        ttk.Separator(haupt, orient="horizontal").grid(
            row=5, column=0, columnspan=2, sticky="ew", pady=(16, 14))

        # --- Button-Leiste ---
        btn_frame = ttk.Frame(haupt)
        btn_frame.grid(row=6, column=0, columnspan=2, sticky="e")
        ttk.Button(btn_frame, text="Abbrechen", style="Abbruch.TButton",
                   command=self._abbrechen).pack(side="left", padx=(0, 10))
        self._verbinden_btn = ttk.Button(btn_frame, text="Verbinden",
                                         command=self._bestaetigen)
        self._verbinden_btn.pack(side="left")

        # Tastaturkuerzel
        self._dialog.bind("<Return>", lambda _e: self._bestaetigen())
        self._dialog.bind("<Escape>", lambda _e: self._abbrechen())

        # Initialen Feldstatus setzen (Server → IP deaktiviert)
        self._modus_geaendert()

    def _modus_geaendert(self) -> None:
        """Aktiviert oder deaktiviert das IP-Feld je nach Modus-Auswahl."""
        if self._modus_var.get() == "client":
            self._ip_feld.configure(state="normal")
            self._ip_feld.focus_set()
        else:
            self._ip_feld.configure(state="disabled")

    def _bestaetigen(self) -> None:
        """Validiert alle Eingaben und schliesst den Dialog mit Ergebnis."""
        modus = self._modus_var.get()

        # Port-Validierung
        try:
            port = int(self._port_feld.get().strip())
            if not (1 <= port <= 65535):
                raise ValueError("Port ausserhalb des gueltigen Bereichs (1–65535)")
        except ValueError as fehler:
            messagebox.showerror("Eingabefehler", str(fehler), parent=self._dialog)
            self._port_feld.focus_set()
            return

        # IP-Adresse validieren (nur Client-Modus)
        ip = self._ip_feld.get().strip()
        if modus == "client" and not ip:
            messagebox.showerror("Eingabefehler",
                                 "Bitte eine Server-IP-Adresse eingeben.",
                                 parent=self._dialog)
            self._ip_feld.focus_set()
            return

        # Anzeigenamen ableiten falls leer
        name = self._name_feld.get().strip()
        if not name:
            name = "Server" if modus == "server" else "Client"

        self._ergebnis = {
            "modus": modus,
            "ip":    ip,
            "port":  port,
            "name":  name,
        }
        self._dialog.destroy()

    def _abbrechen(self) -> None:
        """Schliesst den Dialog ohne Rueckgabewert."""
        self._ergebnis = None
        self._dialog.destroy()

    def ergebnis_holen(self) -> dict | None:
        """Wartet auf Benutzerinteraktion und gibt das Ergebnis zurueck.

        Blockiert bis der Dialog geschlossen wird (modal via wait_window).

        Rueckgabe:
            dict mit 'modus', 'ip', 'port', 'name' oder None bei Abbruch
        """
        self._dialog.wait_window()
        return self._ergebnis


# ---------------------------------------------------------------------------
# ChatApp – Hauptfenster (Tasks 5.1 – 5.8)
# ---------------------------------------------------------------------------

class ChatApp(tk.Tk):
    """Haupt-Chat-Fenster mit vollstaendigem Verbindungsmanagement.

    Verwaltet:
        - GUI-Layout: Statusleiste, Nachrichtenbereich, Eingabebereich (Task 5.1)
        - Verbindungsdialog (Task 5.2)
        - Statusanzeige (Task 5.3)
        - Thread-sicheres Empfangen via queue.Queue + root.after() (Task 5.4)
        - Senden-Button + Enter-Taste (Task 5.5)
        - Nachrichtenformatierung mit Zeitstempel (Task 5.6)
        - Graceful Disconnect bei Fenster-Schliessen (Task 5.7)
        - Scrollbar mit Auto-Scroll (Task 5.8)
    """

    def __init__(self) -> None:
        """Initialisiert ChatApp, konfiguriert Fenster und startet Verbindungsdialog."""
        super().__init__()

        # Interner Zustand
        self._sitzung: Sitzung | None = None          # Aktive P2P-Sitzung
        self._srv_socket = None                        # Server-Listen-Socket
        self._gui_queue: queue.Queue = queue.Queue()   # Thread-sichere Ereignisqueue
        self._verbindungs_params: dict | None = None   # Parameter aus Dialog
        self._queue_aktiv: bool = False                # Laeuft Queue-Polling?
        self._schliessen_laeuft: bool = False          # Verhindert doppeltes Schliessen

        # Fenster-Konfiguration
        self.title(konfig.FENSTER_TITEL)
        self.geometry(f"{konfig.FENSTER_BREITE}x{konfig.FENSTER_HOEHE}")
        self.minsize(600, 400)
        self.configure(bg=FARBEN["hintergrund"])
        self._fenster_zentrieren(konfig.FENSTER_BREITE, konfig.FENSTER_HOEHE)

        # UI aufbauen
        self._styles_anwenden()
        self._ui_erstellen()

        # Task 5.7: WM_DELETE_WINDOW abfangen
        self.protocol("WM_DELETE_WINDOW", self._fenster_schliessen)

        # Verbindungsdialog nach kurzem Delay (Fenster muss sichtbar sein)
        self.after(120, self._dialog_anzeigen)

    def _fenster_zentrieren(self, breite: int, hoehe: int) -> None:
        """Berechnet und setzt die zentrierte Fensterposition.

        Parameter:
            breite: Gewuenschte Fensterbreite in Pixeln
            hoehe:  Gewuenschte Fensterhoehe in Pixeln
        """
        self.update_idletasks()
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        x = (sw - breite) // 2
        y = (sh - hoehe) // 2
        self.geometry(f"{breite}x{hoehe}+{x}+{y}")

    def _styles_anwenden(self) -> None:
        """Konfiguriert alle ttk-Styles mit Dark-Mode-Farbpalette.

        Verwendet clam als Basis (beste Unterstuetzung fuer Custom Styling).
        """
        self._style = ttk.Style(self)
        self._style.theme_use("clam")
        s = self._style

        # Globale Basis
        s.configure(".", background=FARBEN["hintergrund"], foreground=FARBEN["text"],
                    font=(BASIS_SCHRIFT, 10), borderwidth=0)

        # Frames
        s.configure("TFrame", background=FARBEN["hintergrund"])
        s.configure("Status.TFrame", background=FARBEN["oberflaeche"])
        s.configure("Eingabe.TFrame", background=FARBEN["oberflaeche"])

        # Labels (verschiedene Statusvarianten)
        s.configure("TLabel", background=FARBEN["hintergrund"], foreground=FARBEN["text"])
        s.configure("Status.TLabel", background=FARBEN["oberflaeche"],
                    foreground=FARBEN["subtext"], font=(BASIS_SCHRIFT, 9),
                    padding=(10, 5))
        s.configure("Verbunden.TLabel", background=FARBEN["oberflaeche"],
                    foreground=FARBEN["erfolg"], font=(BASIS_SCHRIFT, 9, "bold"),
                    padding=(10, 5))
        s.configure("Getrennt.TLabel", background=FARBEN["oberflaeche"],
                    foreground=FARBEN["fehler"], font=(BASIS_SCHRIFT, 9),
                    padding=(10, 5))
        s.configure("Verbindend.TLabel", background=FARBEN["oberflaeche"],
                    foreground=FARBEN["warnung"], font=(BASIS_SCHRIFT, 9),
                    padding=(10, 5))
        s.configure("Peer.TLabel", background=FARBEN["oberflaeche"],
                    foreground=FARBEN["subtext"], font=(BASIS_SCHRIFT, 9),
                    padding=(10, 5))

        # Button
        s.configure("TButton", background=FARBEN["primaer"],
                    foreground=FARBEN["hintergrund"],
                    font=(BASIS_SCHRIFT, 10, "bold"), padding=(16, 8),
                    relief="flat", borderwidth=0)
        s.map("TButton",
              background=[("active", "#b4d0fb"), ("pressed", "#7aa2f7"),
                          ("disabled", FARBEN["rahmen"])],
              foreground=[("disabled", FARBEN["subtext"])])

        # Entry
        s.configure("TEntry", fieldbackground=FARBEN["oberflaeche"],
                    foreground=FARBEN["text"], insertcolor=FARBEN["text"],
                    borderwidth=0, relief="flat", padding=(10, 6))
        s.map("TEntry",
              fieldbackground=[("focus", "#3d3f5a")])

        # Scrollbar
        s.configure("TScrollbar", background=FARBEN["oberflaeche"],
                    troughcolor=FARBEN["hintergrund"],
                    relief="flat", arrowcolor=FARBEN["subtext"],
                    borderwidth=0)
        s.map("TScrollbar",
              background=[("active", FARBEN["rahmen"])])

        # Separator
        s.configure("TSeparator", background=FARBEN["rahmen"])

    def _ui_erstellen(self) -> None:
        """Erstellt das vollstaendige Fenster-Layout mit grid()-Manager.

        Layoutstruktur:
            Zeile 0: Statusleiste   (feste Hoehe, Style=Status.TFrame)
            Zeile 1: Trennlinie
            Zeile 2: Nachrichtenbereich + Scrollbar (expandiert, weight=1)
            Zeile 3: Trennlinie
            Zeile 4: Eingabebereich (feste Hoehe, Style=Eingabe.TFrame)
        """
        # Haupt-Frame: Zeile 2 bekommt allen flexiblen Platz
        self.grid_rowconfigure(2, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # --- Zeile 0: Statusleiste (Task 5.3) ---
        status_frame = ttk.Frame(self, style="Status.TFrame")
        status_frame.grid(row=0, column=0, sticky="ew")
        status_frame.grid_columnconfigure(0, weight=1)

        self._status_label = ttk.Label(
            status_frame,
            text="  Nicht verbunden",
            style="Status.TLabel",
        )
        self._status_label.grid(row=0, column=0, sticky="w")

        self._peer_label = ttk.Label(
            status_frame,
            text="",
            style="Peer.TLabel",
        )
        self._peer_label.grid(row=0, column=1, sticky="e")

        # --- Zeile 1: Trennlinie ---
        ttk.Separator(self, orient="horizontal").grid(row=1, column=0, sticky="ew")

        # --- Zeile 2: Nachrichtenbereich (Tasks 5.6, 5.8) ---
        msg_container = ttk.Frame(self)
        msg_container.grid(row=2, column=0, sticky="nsew")
        msg_container.grid_rowconfigure(0, weight=1)
        msg_container.grid_columnconfigure(0, weight=1)

        # tk.Text (nicht ttk): noetig fuer farbige Text-Tags
        self._nachrichten_text = tk.Text(
            msg_container,
            state="disabled",            # Kein direktes Editieren
            wrap="word",                 # Wortumbruch aktivieren
            bg=FARBEN["hintergrund"],
            fg=FARBEN["text"],
            insertbackground=FARBEN["text"],
            selectbackground=FARBEN["rahmen"],
            selectforeground=FARBEN["text"],
            font=(MONO_SCHRIFT, 10),
            relief="flat",
            borderwidth=0,
            padx=14,
            pady=10,
            cursor="arrow",              # Kein Texteingabe-Cursor
        )
        self._nachrichten_text.grid(row=0, column=0, sticky="nsew")

        # Scrollbar (Task 5.8)
        scrollbar = ttk.Scrollbar(
            msg_container, orient="vertical",
            command=self._nachrichten_text.yview,
        )
        scrollbar.grid(row=0, column=1, sticky="ns")
        self._nachrichten_text.configure(yscrollcommand=scrollbar.set)

        # Text-Tags fuer farbige Formatierung
        self._nachrichten_text.tag_configure(
            "zeitstempel",
            foreground=FARBEN["subtext"],
            font=(MONO_SCHRIFT, 9),
        )
        self._nachrichten_text.tag_configure(
            "eigener_name",
            foreground=FARBEN["primaer"],
            font=(MONO_SCHRIFT, 10, "bold"),
        )
        self._nachrichten_text.tag_configure(
            "peer_name",
            foreground=FARBEN["erfolg"],
            font=(MONO_SCHRIFT, 10, "bold"),
        )
        self._nachrichten_text.tag_configure(
            "nachricht_text",
            foreground=FARBEN["text"],
            font=(MONO_SCHRIFT, 10),
        )
        self._nachrichten_text.tag_configure(
            "system",
            foreground=FARBEN["warnung"],
            font=(MONO_SCHRIFT, 9, "italic"),
        )

        # --- Zeile 3: Trennlinie ---
        ttk.Separator(self, orient="horizontal").grid(row=3, column=0, sticky="ew")

        # --- Zeile 4: Eingabebereich (Task 5.5) ---
        eingabe_frame = ttk.Frame(self, style="Eingabe.TFrame", padding=(10, 8))
        eingabe_frame.grid(row=4, column=0, sticky="ew")
        eingabe_frame.grid_columnconfigure(0, weight=1)  # Eingabefeld nimmt Restplatz

        self._eingabe_var = tk.StringVar()
        self._eingabe_feld = ttk.Entry(
            eingabe_frame,
            textvariable=self._eingabe_var,
            font=(BASIS_SCHRIFT, 11),
            state="disabled",       # Erst nach Verbindungsaufbau aktiv
        )
        self._eingabe_feld.grid(row=0, column=0, sticky="ew", padx=(0, 8))

        self._senden_btn = ttk.Button(
            eingabe_frame,
            text="Senden",
            command=self._nachricht_absenden,
            state="disabled",       # Erst nach Verbindungsaufbau aktiv
        )
        self._senden_btn.grid(row=0, column=1)

        # Enter-Taste sendet Nachricht (Task 5.5)
        self._eingabe_feld.bind("<Return>", lambda _e: self._nachricht_absenden())

    # -----------------------------------------------------------------------
    # Dialog und Verbindungsaufbau
    # -----------------------------------------------------------------------

    def _dialog_anzeigen(self) -> None:
        """Oeffnet den modalen Verbindungsdialog und verarbeitet das Ergebnis."""
        dialog = VerbindungsDialog(self)
        params = dialog.ergebnis_holen()

        if params is None:
            # Nutzer hat abgebrochen → Anwendung beenden
            self.destroy()
            return

        self._verbindungs_params = params
        self._verbindung_starten(params)

    def _verbindung_starten(self, params: dict) -> None:
        """Startet den Verbindungsaufbau in einem Hintergrund-Thread.

        Parameter:
            params: dict mit Schluesseln 'modus', 'ip', 'port', 'name'
        """
        modus_text = "Server – warte auf Client" if params["modus"] == "server" \
            else f"Client – verbinde mit {params['ip']}"
        self._status_setzen(f"  {modus_text} ...", "verbindend")

        # Queue-Polling starten (falls noch nicht laufend)
        if not self._queue_aktiv:
            self._queue_aktiv = True
            self.after(konfig.GUI_QUEUE_INTERVALL, self._queue_verarbeiten)

        # Verbindungs-Thread (daemon: beendet sich automatisch mit Hauptprozess)
        thread = threading.Thread(
            target=self._verbindung_aufbauen_thread,
            args=(params,),
            daemon=True,
            name="VerbindungsThread",
        )
        thread.start()

    def _verbindung_aufbauen_thread(self, params: dict) -> None:
        """Baut TLS-Verbindung und Protokoll-Handshake im Hintergrund auf.

        Nach erfolgreichem Aufbau wird direkt in die Empfangsschleife uebergegangen.
        Alle Ergebnisse werden via QueueEreignis an den GUI-Thread gemeldet.

        Parameter:
            params: dict mit 'modus', 'ip', 'port', 'name'
        """
        try:
            modus = params["modus"]
            port  = params["port"]
            name  = params["name"]

            logger.info("Verbindungsaufbau gestartet: Modus=%s Port=%d Name=%s", modus, port, name)

            if modus == "server":
                # Server-Modus: Socket binden und auf Verbindung warten
                self._gui_queue.put(QueueEreignis(
                    "status", f"  Warte auf Verbindung auf Port {port} ..."
                ))
                self._srv_socket = server_erstellen()
                verbindung, adresse = verbindung_akzeptieren(self._srv_socket)
                peer_ip = adresse[0]
                logger.info("TCP/TLS-Verbindung von %s akzeptiert (GUI-Modus)", peer_ip)

            else:
                # Client-Modus: Verbindung zum Server herstellen
                ip = params["ip"]
                self._gui_queue.put(QueueEreignis(
                    "status", f"  Verbinde mit {ip}:{port} ..."
                ))
                verbindung = verbindung_herstellen(ip, port)
                peer_ip = ip
                logger.info("TCP/TLS-Verbindung zu %s:%d hergestellt (GUI-Modus)", ip, port)

            # Sitzungsobjekt erstellen
            sitzung = Sitzung(
                verbindung=verbindung,
                absender_name=name,
                server_modus=(modus == "server"),
            )
            self._sitzung = sitzung

            # Protokoll-Handshake (CONNECT/ACK)
            self._gui_queue.put(QueueEreignis("status", "  TLS-Handshake ..."))
            if not sitzung.verbindungsaufbau():
                logger.error("Protokoll-Handshake (CONNECT/ACK) fehlgeschlagen (GUI-Modus)")
                self._gui_queue.put(QueueEreignis(
                    "fehler", "Protokoll-Handshake fehlgeschlagen."
                ))
                return

            logger.info("Sitzung aktiv: Peer=%s Name=%s", peer_ip, name)

            # Verbindung erfolgreich – GUI benachrichtigen
            self._gui_queue.put(QueueEreignis("verbunden", {
                "peer_ip": peer_ip,
                "name":    name,
            }))

            # Sofort in die Empfangsschleife wechseln
            self._empfangs_schleife()

        except OSError as fehler:
            logger.error("Netzwerkfehler beim Verbindungsaufbau (GUI-Modus): %s", fehler)
            self._gui_queue.put(QueueEreignis("fehler", f"Netzwerkfehler: {fehler}"))
        except Exception as fehler:
            logger.error("Unerwarteter Fehler beim Verbindungsaufbau (GUI-Modus): %s", fehler)
            self._gui_queue.put(QueueEreignis("fehler", f"Fehler: {fehler}"))

    def _empfangs_schleife(self) -> None:
        """Wartet im Verbindungs-Thread kontinuierlich auf eingehende Nachrichten.

        Legt empfangene Nachrichten und Ereignisse per QueueEreignis in der
        GUI-Queue ab. Beendet sich bei Verbindungsabbau oder Fehler.
        """
        sitzung = self._sitzung
        if sitzung is None:
            return

        logger.info("Empfangsschleife gestartet")
        while sitzung.zustand == SitzungsZustand.VERBUNDEN:
            try:
                nachricht = sitzung.nachricht_empfangen()

                if nachricht is None:
                    # None zurueck: Timeout (Verbindung noch aktiv) oder Disconnect
                    if sitzung.zustand != SitzungsZustand.VERBUNDEN:
                        # Sitzung wurde durch DISCONNECT oder Fehler getrennt
                        self._gui_queue.put(QueueEreignis("getrennt", None))
                        return
                    # Timeout: normal, weiter auf naechste Nachricht warten
                    continue

                # Gueltige Nachricht empfangen → an GUI melden
                self._gui_queue.put(QueueEreignis("nachricht", nachricht))

            except Exception as fehler:
                self._gui_queue.put(QueueEreignis(
                    "fehler", f"Empfangsfehler: {fehler}"
                ))
                return

        # Schleife verlassen weil Zustand nicht mehr VERBUNDEN
        logger.info("Empfangsschleife beendet – Sitzungszustand: %s", sitzung.zustand.value)
        self._gui_queue.put(QueueEreignis("getrennt", None))

    # -----------------------------------------------------------------------
    # Queue-Verarbeitung (Task 5.4)
    # -----------------------------------------------------------------------

    def _queue_verarbeiten(self) -> None:
        """Verarbeitet alle Events aus der GUI-Queue (laeuft im Haupt-Thread).

        Wird periodisch via root.after() aufgerufen. Verarbeitet max. 20 Events
        pro Aufruf, um die GUI reaktiv zu halten. Re-scheduled sich selbst solange
        _queue_aktiv True ist.
        """
        try:
            for _ in range(20):  # Max. 20 Events pro Tick
                try:
                    ereignis: QueueEreignis = self._gui_queue.get_nowait()
                except queue.Empty:
                    break
                self._ereignis_verarbeiten(ereignis)
        finally:
            # Naechsten Poll einplanen
            if self._queue_aktiv:
                self.after(konfig.GUI_QUEUE_INTERVALL, self._queue_verarbeiten)

    def _ereignis_verarbeiten(self, ereignis: QueueEreignis) -> None:
        """Verarbeitet ein einzelnes Queue-Ereignis und aktualisiert die GUI.

        Parameter:
            ereignis: Zu verarbeitendes QueueEreignis
        """
        match ereignis.typ:

            case "status":
                # Statustext waehrend Verbindungsaufbau aktualisieren
                self._status_setzen(ereignis.daten, "verbindend")

            case "verbunden":
                # Verbindung erfolgreich aufgebaut (Task 5.3)
                peer_ip = ereignis.daten.get("peer_ip", "?")
                name    = ereignis.daten.get("name", "")
                self._status_setzen(f"  Verbunden mit {peer_ip}", "verbunden")
                self._peer_label.configure(text=f"TLS 1.3  |  {name}  ")
                # Eingabe aktivieren (Task 5.5)
                self._eingabe_feld.configure(state="normal")
                self._senden_btn.configure(state="normal")
                self._eingabe_feld.focus_set()
                # Systemmeldung im Nachrichtenbereich
                self._systemnachricht_anzeigen(f"Verbunden mit {peer_ip}")

            case "getrennt":
                # Verbindung getrennt (Task 5.3)
                self._status_setzen("  Verbindung getrennt", "getrennt")
                self._peer_label.configure(text="")
                self._eingabe_feld.configure(state="disabled")
                self._senden_btn.configure(state="disabled")
                self._systemnachricht_anzeigen("Verbindung wurde getrennt.")

            case "nachricht":
                # Empfangene Nachricht anzeigen (Task 5.6)
                daten      = ereignis.daten
                absender   = daten.get("absender", "Unbekannt")
                text       = daten.get("nachricht", "")
                zeitstempel = daten.get("zeitstempel", "")
                # ISO-8601-Zeitstempel kuerzen auf HH:MM:SS
                if "T" in zeitstempel:
                    zeitstempel = zeitstempel.split("T")[1][:8]
                self._nachricht_anzeigen(absender, text, zeitstempel, eigen=False)

            case "fehler":
                # Fehlermeldung anzeigen
                self._status_setzen(f"  Fehler: {ereignis.daten}", "getrennt")
                self._systemnachricht_anzeigen(f"Fehler: {ereignis.daten}")
                self._eingabe_feld.configure(state="disabled")
                self._senden_btn.configure(state="disabled")

    # -----------------------------------------------------------------------
    # Nachrichtenanzeige (Tasks 5.6, 5.8)
    # -----------------------------------------------------------------------

    def _nachricht_anzeigen(
        self,
        absender: str,
        text: str,
        zeitstempel: str,
        eigen: bool = False,
    ) -> None:
        """Fuegt eine formatierte Nachricht in den Nachrichtenbereich ein.

        Format: [HH:MM:SS] Absender: Nachrichtentext
        Eigene Nachrichten: blaue Schrift; Peer-Nachrichten: gruene Schrift.

        Parameter:
            absender:    Anzeigename des Absenders
            text:        Nachrichtentext
            zeitstempel: Zeitstempel-String (HH:MM:SS)
            eigen:       True = eigene gesendete Nachricht
        """
        name_tag = "eigener_name" if eigen else "peer_name"

        # Text-Widget kurz schreibbar machen, dann zurueck auf readonly
        self._nachrichten_text.configure(state="normal")
        self._nachrichten_text.insert("end", f"[{zeitstempel}] ", "zeitstempel")
        self._nachrichten_text.insert("end", f"{absender}: ", name_tag)
        self._nachrichten_text.insert("end", f"{text}\n", "nachricht_text")
        self._nachrichten_text.configure(state="disabled")

        # Auto-Scroll ans Ende (Task 5.8)
        self._nachrichten_text.see("end")

    def _systemnachricht_anzeigen(self, text: str) -> None:
        """Zeigt eine kursive Systemmeldung im Nachrichtenbereich an.

        Wird fuer Verbindungsereignisse (verbunden, getrennt, Fehler) verwendet.

        Parameter:
            text: Anzuzeigender Systemtext
        """
        jetzt = datetime.now().strftime("%H:%M:%S")
        self._nachrichten_text.configure(state="normal")
        self._nachrichten_text.insert(
            "end", f"── {text} [{jetzt}] ──\n", "system"
        )
        self._nachrichten_text.configure(state="disabled")
        self._nachrichten_text.see("end")

    # -----------------------------------------------------------------------
    # Nachricht senden (Task 5.5)
    # -----------------------------------------------------------------------

    def _nachricht_absenden(self) -> None:
        """Sendet die eingegebene Nachricht und zeigt sie sofort lokal an.

        Liest Eingabefeld, zeigt eigene Nachricht direkt an, leert das Feld
        und uebergibt den Text an einen Hintergrund-Thread fuer die Uebertragung.
        """
        if self._sitzung is None or self._sitzung.zustand != SitzungsZustand.VERBUNDEN:
            return

        text = self._eingabe_var.get().strip()
        if not text:
            return  # Leere Eingabe ignorieren

        # Anzeigenamen aus Verbindungsparametern holen
        name = (self._verbindungs_params or {}).get("name", "Ich")

        # Eingabefeld sofort leeren (Task 5.5)
        self._eingabe_var.set("")

        # Eigene Nachricht sofort im Chat anzeigen (optimistisch)
        jetzt = datetime.now().strftime("%H:%M:%S")
        self._nachricht_anzeigen(name, text, jetzt, eigen=True)

        # Senden im Hintergrund (non-blocking, GUI friert nicht ein)
        thread = threading.Thread(
            target=self._nachricht_senden_thread,
            args=(text,),
            daemon=True,
            name="SendeThread",
        )
        thread.start()

    def _nachricht_senden_thread(self, text: str) -> None:
        """Sendet eine Nachricht ueber die Sitzung (laeuft im Hintergrund-Thread).

        Parameter:
            text: Zu sendender Nachrichtentext
        """
        if self._sitzung is None:
            return
        try:
            erfolg = self._sitzung.nachricht_senden(text)
            if not erfolg:
                self._gui_queue.put(QueueEreignis(
                    "fehler", "Nachricht konnte nicht uebertragen werden."
                ))
        except Exception as fehler:
            self._gui_queue.put(QueueEreignis("fehler", f"Sendefehler: {fehler}"))

    # -----------------------------------------------------------------------
    # Statusleiste (Task 5.3)
    # -----------------------------------------------------------------------

    def _status_setzen(self, text: str, zustand: str) -> None:
        """Aktualisiert Statustext und -farbe in der Statusleiste.

        Parameter:
            text:    Anzuzeigender Statustext
            zustand: "verbunden" | "getrennt" | "verbindend"
        """
        stil_map: dict[str, str] = {
            "verbunden":  "Verbunden.TLabel",
            "getrennt":   "Getrennt.TLabel",
            "verbindend": "Verbindend.TLabel",
        }
        stil = stil_map.get(zustand, "Status.TLabel")
        self._status_label.configure(text=text, style=stil)

    # -----------------------------------------------------------------------
    # Graceful Shutdown (Task 5.7)
    # -----------------------------------------------------------------------

    def _fenster_schliessen(self) -> None:
        """WM_DELETE_WINDOW-Handler: DISCONNECT senden, Threads beenden, Fenster schliessen.

        Ablauf:
            1. Doppelaufruf verhindern (_schliessen_laeuft-Flag)
            2. Eingabe sofort deaktivieren
            3. Queue-Polling stoppen
            4. DISCONNECT im Hintergrund senden (sitzung.verbindungsabbau())
            5. Server-Socket schliessen
            6. Fenster nach Abschluss (oder max. 2s) zerstoeren
        """
        if self._schliessen_laeuft:
            return
        self._schliessen_laeuft = True

        # Eingabe deaktivieren
        self._eingabe_feld.configure(state="disabled")
        self._senden_btn.configure(state="disabled")
        self._status_setzen("  Trenne Verbindung ...", "verbindend")

        # Queue-Polling stoppen
        self._queue_aktiv = False

        def _disconnect_und_destroy() -> None:
            """Sendet DISCONNECT und schliesst alle Ressourcen."""
            if (self._sitzung is not None and
                    self._sitzung.zustand == SitzungsZustand.VERBUNDEN):
                try:
                    self._sitzung.verbindungsabbau()
                except Exception as fehler:
                    logger.debug("Verbindungsabbau beim Schliessen ignoriert (Peer weg?): %s", fehler)

            if self._srv_socket is not None:
                try:
                    self._srv_socket.close()
                except Exception as fehler:
                    logger.debug("Server-Socket-Schliessen ignoriert: %s", fehler)

            # GUI-Thread: Fenster zerstoeren
            self.after(0, self.destroy)

        # Disconnect in Hintergrund-Thread (blockiert nicht die GUI)
        thread = threading.Thread(
            target=_disconnect_und_destroy,
            daemon=True,
            name="DisconnectThread",
        )
        thread.start()

        # Fallback: Fenster spaetestens nach 2s schliessen
        self.after(2000, self._destroy_erzwingen)

    def _destroy_erzwingen(self) -> None:
        """Erzwingt das Schliessen des Fensters als Fallback (nach 2s Timeout)."""
        try:
            self.destroy()
        except Exception as fehler:
            logger.debug("Fenster-Destroy-Fallback ignoriert (bereits zerstoert?): %s", fehler)


# ---------------------------------------------------------------------------
# Einstiegspunkt
# ---------------------------------------------------------------------------

def gui_starten() -> None:
    """Erstellt und startet die ChatApp-Instanz.

    Wird von hauptprogramm.py mit --gui aufgerufen oder direkt bei
    python3 gui.py. Blockiert bis das Fenster geschlossen wird.
    """
    app = ChatApp()
    app.mainloop()


if __name__ == "__main__":
    gui_starten()
