"""
sitzung.py – Sitzungsmanagement

Beschreibung: Verwaltet den Lebenszyklus einer P2P-Chat-Sitzung.
              TCP garantiert Zustellung und Reihenfolge; TLS garantiert
              Vertraulichkeit und Integrität auf Transportschicht.
              Die Sitzung startet direkt im Zustand VERBUNDEN und wechselt
              auf GETRENNT wenn der Socket geschlossen wird.
Autor:        Gruppe 2
Datum:        2026-03-24
Modul:        Network Security 2026

Testschritte (2 Terminals):
    Terminal 1 (Server):
        python3 hauptprogramm.py --modus server --port 6769

    Terminal 2 (Client):
        python3 hauptprogramm.py --modus client --ziel 127.0.0.1 --port 6769
        > Hallo Welt
        > quit
"""

import json
import logging
import socket
import ssl
from datetime import datetime
from enum import Enum

import konfig
from netzwerk import daten_empfangen, daten_senden

# Modul-Logger für alle Sitzungs-Ereignisse
logger = logging.getLogger(__name__)


class SitzungsZustand(Enum):
    """Zustände des Sitzungs-Automaten."""

    GETRENNT: str  = "GETRENNT"   # Keine aktive Verbindung
    VERBUNDEN: str = "VERBUNDEN"  # Sitzung aktiv, Datenaustausch möglich


class Sitzung:
    """Verwaltet eine P2P-Chat-Sitzung über eine bestehende TLS-Verbindung.

    TCP garantiert Zustellung und Reihenfolge; TLS garantiert Vertraulichkeit
    und Integrität auf Transportschicht.

    Attribute:
        verbindung:    Die aktive TLS-Socket-Verbindung (von netzwerk.py)
        absender_name: Anzeigename dieses Peers (für JSON-Payload)
        server_modus:  True = Server-Seite; False = Client-Seite
        zustand:       Aktueller Zustand (VERBUNDEN oder GETRENNT)
    """

    def __init__(
        self,
        verbindung: ssl.SSLSocket,
        absender_name: str,
        server_modus: bool = False,
    ) -> None:
        """Initialisiert eine neue Sitzung.

        Die TLS-Verbindung ist zu diesem Zeitpunkt bereits aufgebaut.
        Der Zustand wird sofort auf VERBUNDEN gesetzt, da TCP+TLS
        den Verbindungsaufbau bereits abgeschlossen haben.

        Parameter:
            verbindung:    Fertig verbundener TLS-Socket
            absender_name: Name dieses Peers (erscheint in Nachrichten-Payloads)
            server_modus:  True wenn dieser Peer der Server ist
        """
        self.verbindung: ssl.SSLSocket = verbindung      # Aktiver TLS-Socket
        self.absender_name: str = absender_name          # Anzeigename in Nachrichten
        self.server_modus: bool = server_modus           # Rolle dieses Peers
        self.zustand: SitzungsZustand = SitzungsZustand.VERBUNDEN  # TLS-Verbindung steht bereits

    # ---------------------------------------------------------------------------
    # Interne Hilfsmethoden
    # ---------------------------------------------------------------------------

    def _zustand_setzen(self, neuer_zustand: SitzungsZustand) -> None:
        """Setzt den Sitzungszustand und protokolliert den Übergang.

        Parameter:
            neuer_zustand: Der neue Zielzustand
        """
        alter_zustand = self.zustand  # Alter Zustand für Log-Ausgabe merken
        self.zustand = neuer_zustand
        logger.info(
            "Zustand: %s -> %s",
            alter_zustand.value,
            neuer_zustand.value,
        )

    # ---------------------------------------------------------------------------
    # Nachricht senden
    # ---------------------------------------------------------------------------

    def nachricht_senden(self, nachricht_text: str) -> bool:
        """Sendet eine Nachricht als JSON-Bytes direkt über den TLS-Socket.

        Schlägt `sendall()` fehl, ist die Verbindung ohnehin unterbrochen –
        der Fehler wird als False zurückgegeben.

        Payload-Format: JSON mit den Schlüsseln "nachricht", "zeitstempel", "absender".

        Parameter:
            nachricht_text: Der zu sendende Nachrichtentext (UTF-8)

        Rückgabe:
            True bei erfolgreichem Senden, False bei Fehler
        """
        if self.zustand != SitzungsZustand.VERBUNDEN:
            logger.error(
                "Senden nicht möglich: Zustand ist %s (erwartet VERBUNDEN)",
                self.zustand.value,
            )
            return False

        # JSON-Payload mit Nachrichtentext, Zeitstempel und Absendername aufbauen
        payload_dict = {
            "nachricht": nachricht_text,
            "zeitstempel": datetime.now().isoformat(),
            "absender": self.absender_name,
        }
        payload = json.dumps(payload_dict, ensure_ascii=False).encode("utf-8")

        try:
            daten_senden(self.verbindung, payload)  # JSON-Bytes direkt senden
        except (OSError, ssl.SSLError) as fehler:
            logger.error("Senden fehlgeschlagen: %s", fehler)
            return False

        logger.info("Nachricht gesendet: \"%s\"", nachricht_text)
        return True

    # ---------------------------------------------------------------------------
    # Verbindungsabbau
    # ---------------------------------------------------------------------------

    def verbindungsabbau(self) -> None:
        """Schliesst die Verbindung und setzt den Zustand auf GETRENNT.

        Der TCP-Stack sendet dem Peer automatisch ein FIN-Segment, das die
        Verbindung sauber beendet.
        """
        if self.zustand == SitzungsZustand.GETRENNT:
            logger.warning("Verbindungsabbau: Zustand ist bereits GETRENNT")
            return

        self._zustand_setzen(SitzungsZustand.GETRENNT)  # Zustand vor Socket-Close setzen
        self._socket_schliessen()

    def _socket_schliessen(self) -> None:
        """Schliesst TLS- und TCP-Socket sauber.

        Ignoriert Fehler beim Schliessen (Socket könnte bereits geschlossen sein).
        """
        try:
            self.verbindung.shutdown(socket.SHUT_RDWR)  # Graceful TLS-Shutdown
        except OSError as fehler:
            logger.debug("Socket-Shutdown ignoriert (bereits geschlossen): %s", fehler)

        try:
            self.verbindung.close()  # Socket-Ressource freigeben
        except OSError as fehler:
            logger.debug("Socket-Schliessen ignoriert (bereits geschlossen): %s", fehler)

        logger.info("Verbindung vollständig geschlossen")

    # ---------------------------------------------------------------------------
    # Nachricht empfangen
    # ---------------------------------------------------------------------------

    def nachricht_empfangen(self) -> dict | None:
        """Empfängt JSON-Bytes direkt vom TLS-Socket und gibt den Payload-Dict zurück.

        Bei einem Verbindungsabbruch (ConnectionError) wird der Zustand
        automatisch auf GETRENNT gesetzt, damit die Empfangsschleife endet.
        EMPFANG_TIMEOUT wird gesetzt, da der Nutzer Zeit zum Tippen benötigt.

        Rückgabe:
            Payload-Dict bei empfangener Nachricht, None bei Fehler oder Timeout
        """
        # Längeren Timeout setzen: Nutzer benötigt Zeit zum Tippen
        self.verbindung.settimeout(konfig.EMPFANG_TIMEOUT)

        try:
            rohdaten = daten_empfangen(self.verbindung)  # JSON-Bytes direkt empfangen
        except ConnectionError as fehler:
            # Gegenseite hat Verbindung geschlossen – Zustand auf GETRENNT setzen,
            # damit die Empfangsschleife in konsole.py sauber endet
            logger.error("Verbindung unterbrochen beim Empfang: %s", fehler)
            self._zustand_setzen(SitzungsZustand.GETRENNT)
            return None
        except (OSError, ssl.SSLError, socket.timeout, TimeoutError) as fehler:
            # Timeout ist Normalzustand bei Idle – kein echter Fehler
            if isinstance(fehler, (socket.timeout, TimeoutError)):
                logger.debug("Empfangs-Timeout (Idle erwartet)")
            else:
                logger.error("Netzwerkfehler beim Empfang: %s", fehler)
            return None
        finally:
            # Original-Timeout wiederherstellen, damit Sende-Operationen nicht blockieren
            self.verbindung.settimeout(konfig.SENDE_TIMEOUT)

        try:
            payload_dict: dict = json.loads(rohdaten.decode("utf-8"))  # JSON dekodieren
        except (json.JSONDecodeError, UnicodeDecodeError) as fehler:
            logger.error("Ungültige JSON-Payload: %s", fehler)
            return None

        nachricht = payload_dict.get("nachricht", "<leer>")  # Nachrichtentext für Log
        logger.info("Nachricht empfangen: \"%s\"", nachricht)
        return payload_dict
