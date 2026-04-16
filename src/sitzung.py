"""
sitzung.py – Sitzungsmanagement

Beschreibung: Verwaltet den Lebenszyklus einer P2P-Chat-Sitzung.
              TCP garantiert Zustellung und Reihenfolge; mTLS garantiert
              Vertraulichkeit, Integrität und gegenseitige Authentifizierung
              auf Transportschicht. Die Sitzung startet direkt im Zustand
              VERBUNDEN und wechselt auf GETRENNT wenn der Stream geschlossen wird.
Autor:        Gruppe 2
Datum:        2026-03-24
Modul:        Network Security 2026

Testschritte (2 Terminals):
    Terminal 1 (Server):
        python3 src/hauptprogramm.py --modus server --port 6769

    Terminal 2 (Client):
        python3 src/hauptprogramm.py --modus client --ziel 127.0.0.1 --port 6769
        > Hallo Welt
        > quit
"""

import asyncio
import json
import logging
import ssl
from datetime import datetime
from enum import Enum

from netzwerk import daten_empfangen, daten_senden

logger = logging.getLogger(__name__)


class SitzungsZustand(Enum):
    """Zustände des Sitzungs-Automaten."""

    GETRENNT  = "GETRENNT"   # Keine aktive Verbindung
    VERBUNDEN = "VERBUNDEN"  # Sitzung aktiv, Datenaustausch möglich


class Sitzung:
    """Verwaltet eine P2P-Chat-Sitzung über bestehende TLS-Streams.

    Attribute:
        reader:        asyncio.StreamReader der TLS-Verbindung
        writer:        asyncio.StreamWriter der TLS-Verbindung
        absender_name: Anzeigename dieses Peers (für JSON-Payload)
        server_modus:  True = Server-Seite; False = Client-Seite
        zustand:       Aktueller Zustand (VERBUNDEN oder GETRENNT)
    """

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        absender_name: str,
        server_modus: bool = False,
    ) -> None:
        """Initialisiert eine neue Sitzung.

        Die TLS-Verbindung ist zu diesem Zeitpunkt bereits aufgebaut.
        Der Zustand wird sofort auf VERBUNDEN gesetzt.

        Parameter:
            reader:        Fertig verbundener TLS-StreamReader
            writer:        Fertig verbundener TLS-StreamWriter
            absender_name: Name dieses Peers (erscheint in Nachrichten-Payloads)
            server_modus:  True wenn dieser Peer der Server ist
        """
        self.reader: asyncio.StreamReader = reader
        self.writer: asyncio.StreamWriter = writer
        self.absender_name: str = absender_name
        self.server_modus: bool = server_modus
        self.zustand: SitzungsZustand = SitzungsZustand.VERBUNDEN

    # ---------------------------------------------------------------------------
    # Interne Hilfsmethoden
    # ---------------------------------------------------------------------------

    def _zustand_setzen(self, neuer_zustand: SitzungsZustand) -> None:
        """Setzt den Sitzungszustand und protokolliert den Übergang."""
        alter_zustand = self.zustand
        self.zustand = neuer_zustand
        logger.info("Zustand: %s -> %s", alter_zustand.value, neuer_zustand.value)

    # ---------------------------------------------------------------------------
    # Nachricht senden
    # ---------------------------------------------------------------------------

    async def nachricht_senden(self, nachricht_text: str) -> bool:
        """Sendet eine Nachricht als JSON-Bytes direkt über den TLS-Stream.

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

        payload = json.dumps(
            {
                "nachricht": nachricht_text,
                "zeitstempel": datetime.now().isoformat(),
                "absender": self.absender_name,
            },
            ensure_ascii=False,
        ).encode("utf-8")

        try:
            await daten_senden(self.writer, payload)
        except (OSError, ssl.SSLError) as fehler:
            logger.error("Senden fehlgeschlagen: %s", fehler)
            return False

        logger.info("Nachricht gesendet: \"%s\"", nachricht_text)
        return True

    # ---------------------------------------------------------------------------
    # Verbindungsabbau
    # ---------------------------------------------------------------------------

    async def verbindungsabbau(self) -> None:
        """Schliesst die Verbindung und setzt den Zustand auf GETRENNT."""
        if self.zustand == SitzungsZustand.GETRENNT:
            logger.warning("Verbindungsabbau: Zustand ist bereits GETRENNT")
            return

        self._zustand_setzen(SitzungsZustand.GETRENNT)
        await self._socket_schliessen()

    async def _socket_schliessen(self) -> None:
        """Schliesst TLS-Stream sauber (close + wait_closed)."""
        try:
            self.writer.close()
            await self.writer.wait_closed()
        except OSError as fehler:
            logger.debug("Socket-Schliessen ignoriert (bereits geschlossen): %s", fehler)

        logger.info("Verbindung vollständig geschlossen")

    # ---------------------------------------------------------------------------
    # Nachricht empfangen
    # ---------------------------------------------------------------------------

    async def nachricht_empfangen(self) -> dict | None:
        """Empfängt JSON-Bytes vom TLS-Stream und gibt den Payload-Dict zurück.

        Bei einem Verbindungsabbruch (ConnectionError) wird der Zustand
        automatisch auf GETRENNT gesetzt, damit die Empfangsschleife endet.

        Rückgabe:
            Payload-Dict bei empfangener Nachricht, None bei Fehler
        """
        try:
            rohdaten = await daten_empfangen(self.reader)
        except ConnectionError as fehler:
            logger.error("Verbindung unterbrochen beim Empfang: %s", fehler)
            self._zustand_setzen(SitzungsZustand.GETRENNT)
            return None
        except (OSError, ssl.SSLError) as fehler:
            logger.error("Netzwerkfehler beim Empfang: %s", fehler)
            self._zustand_setzen(SitzungsZustand.GETRENNT)
            return None

        try:
            payload_dict: dict = json.loads(rohdaten.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as fehler:
            logger.error("Ungültige JSON-Payload: %s", fehler)
            return None

        logger.info("Nachricht empfangen: \"%s\"", payload_dict.get("nachricht", "<leer>"))
        return payload_dict
