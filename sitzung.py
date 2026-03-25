"""
sitzung.py – Sitzungsmanagement: Connect, Disconnect, Sequenznummern

Beschreibung: Verwaltet den vollstaendigen Lebenszyklus einer P2P-Chat-Sitzung:
              Zustandsautomat (GETRENNT → VERBINDEND → VERBUNDEN → TRENNEND → GETRENNT),
              Verbindungsaufbau (CONNECT/ACK), Datenuebertragung mit Sequenznummern und
              ACK-Retry, Verbindungsabbau (DISCONNECT/ACK) sowie Sequenznummer-Tracking
              zur Erkennung von Duplikaten und veralteten Paketen.
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
import queue
import socket
import ssl
import time
from datetime import datetime
from enum import Enum

import konfig
from krypto import hmac_pruefen
from netzwerk import daten_empfangen, daten_senden
from protokoll import NachrichtenTyp, PaketErgebnis, paket_erstellen, paket_zerlegen

# Modul-Logger fuer alle Sitzungs-Ereignisse
logger = logging.getLogger(__name__)


class SitzungsZustand(Enum):
    """Zustaende des Sitzungs-Automaten."""

    GETRENNT: str   = "GETRENNT"    # Keine aktive Verbindung
    VERBINDEND: str = "VERBINDEND"  # Verbindungsaufbau laeuft
    VERBUNDEN: str  = "VERBUNDEN"   # Sitzung aktiv, Datenaustausch moeglich
    TRENNEND: str   = "TRENNEND"    # Verbindungsabbau laeuft


class Sitzung:
    """Verwaltet eine P2P-Chat-Sitzung ueber eine bestehende TLS-Verbindung.

    Implementiert den vollstaendigen Lebenszyklus:
        GETRENNT → VERBINDEND → VERBUNDEN → TRENNEND → GETRENNT

    Attribute:
        verbindung:       Die aktive TLS-Socket-Verbindung (von netzwerk.py)
        absender_name:    Anzeigename dieses Peers (fuer JSON-Payload)
        server_modus:     True = wartet auf CONNECT; False = sendet CONNECT
        zustand:          Aktueller Zustandsautomat-Zustand
        sende_sequenz:    Eigene Sequenznummer (wird bei jedem gesendeten Paket inkrementiert)
        empfangs_sequenz: Naechste erwartete Sequenznummer des Peers
        schluessel:       Gemeinsamer HMAC-Schluessel (aus konfig.py)
    """

    def __init__(
        self,
        verbindung: ssl.SSLSocket,
        absender_name: str,
        server_modus: bool = False,
    ) -> None:
        """Initialisiert eine neue Sitzung.

        Parameter:
            verbindung:    Fertig verbundener TLS-Socket
            absender_name: Name dieses Peers (erscheint in Nachrichten-Payloads)
            server_modus:  True wenn dieser Peer auf CONNECT wartet, False wenn er CONNECT sendet
        """
        self.verbindung: ssl.SSLSocket = verbindung
        self.absender_name: str = absender_name
        self.server_modus: bool = server_modus
        self.zustand: SitzungsZustand = SitzungsZustand.GETRENNT
        self.sende_sequenz: int = 0       # Aufsteigende eigene Sequenznummer
        self.empfangs_sequenz: int = 0    # Naechste erwartete Peer-Sequenznummer
        self.schluessel: bytes = konfig.GETEILTES_GEHEIMNIS  # HMAC-Schluessel
        self._ack_queue: queue.Queue = queue.Queue()  # Thread-sicherer ACK-Kanal: Empfangs-Thread → Sende-Thread

    # ---------------------------------------------------------------------------
    # Interne Hilfsmethoden
    # ---------------------------------------------------------------------------

    def _zustand_setzen(self, neuer_zustand: SitzungsZustand) -> None:
        """Setzt den Sitzungszustand und protokolliert den Uebergang.

        Parameter:
            neuer_zustand: Der neue Zielzustand
        """
        alter_zustand = self.zustand
        self.zustand = neuer_zustand
        logger.info(
            "Zustand: %s → %s",
            alter_zustand.value,
            neuer_zustand.value,
        )

    def _naechste_sende_seq(self) -> int:
        """Inkrementiert und gibt die naechste Sende-Sequenznummer zurueck.

        Rueckgabe:
            Naechste Sequenznummer (ab 1 aufsteigend)
        """
        self.sende_sequenz += 1
        return self.sende_sequenz

    def _paket_senden_raw(self, typ: int, sequenz: int, payload: bytes) -> None:
        """Erstellt ein Paket mit gegebener Sequenznummer und sendet es.

        Parameter:
            typ:      Nachrichtentyp (NachrichtenTyp.*-Wert)
            sequenz:  Sequenznummer fuer dieses Paket
            payload:  UTF-8-codiertes JSON als Bytes
        """
        paket = paket_erstellen(typ, sequenz, payload, self.schluessel)
        daten_senden(self.verbindung, paket)
        logger.debug(
            "Paket gesendet: Typ=%02x Seq=%d Payload=%d Bytes",
            typ, sequenz, len(payload),
        )

    def _paket_empfangen_intern(self, timeout: float | None = None) -> PaketErgebnis | None:
        """Empfaengt ein Rohpaket, zerlegt es und prueft den HMAC.

        Parameter:
            timeout: Optionaler Socket-Timeout in Sekunden. Wird gesetzt vor dem
                     Lesen und nach dem Lesen auf konfig.SENDE_TIMEOUT zurueckgesetzt.
                     None = aktuellen Socket-Timeout unveraendert lassen.

        Rueckgabe:
            Verifiziertes PaketErgebnis, oder None bei Fehler/ungueltigem HMAC
        """
        # Timeout temporaer anpassen, damit Empfang und Senden unterschiedliche Grenzen haben
        if timeout is not None:
            self.verbindung.settimeout(timeout)

        try:
            rohdaten = daten_empfangen(self.verbindung)
        except ConnectionError as fehler:
            logger.error("Verbindung unterbrochen beim Empfang: %s", fehler)
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
            if timeout is not None:
                self.verbindung.settimeout(konfig.SENDE_TIMEOUT)

        try:
            ergebnis = paket_zerlegen(rohdaten)
        except ValueError as fehler:
            logger.error("Paket konnte nicht zerlegt werden: %s", fehler)
            return None

        # HMAC-Integritaetspruefung
        if not hmac_pruefen(ergebnis, self.schluessel):
            logger.warning(
                "Paket mit ungueltigem HMAC verworfen (Typ=%02x Seq=%d)",
                ergebnis.typ, ergebnis.sequenz,
            )
            return None

        return ergebnis

    def _ack_senden(self, sequenz: int) -> None:
        """Sendet ein ACK-Paket fuer die angegebene Sequenznummer.

        ACKs verwenden die Echo-Sequenznummer des bestaetigen Pakets und
        inkrementieren NICHT den eigenen Sequenz-Zaehler.

        Parameter:
            sequenz: Sequenznummer des zu bestaetigen Pakets
        """
        payload = json.dumps({"seq": sequenz}).encode("utf-8")  # Minimaler ACK-Payload
        # ACK: Echo-Sequenznummer, kein Inkrement des eigenen Zaehlers
        self._paket_senden_raw(NachrichtenTyp.ACK.value, sequenz, payload)
        logger.debug("ACK gesendet (Seq: %d)", sequenz)

    def _sequenz_pruefen(self, empfangene_seq: int) -> bool:
        """Prueft ob eine empfangene Sequenznummer gueltig und aktuell ist.

        Erkennt Duplikate (zu niedrig) und protokolliert Luecken (zu hoch).
        Bei Gueltigkeit wird empfangs_sequenz aktualisiert.

        Parameter:
            empfangene_seq: Sequenznummer des empfangenen Pakets

        Rueckgabe:
            True wenn Paket verarbeitet werden soll, False wenn verworfen
        """
        if empfangene_seq < self.empfangs_sequenz:
            logger.warning(
                "Doppelte/veraltete Sequenznummer %d verworfen (erwartet >= %d)",
                empfangene_seq,
                self.empfangs_sequenz,
            )
            return False

        if empfangene_seq > self.empfangs_sequenz:
            logger.warning(
                "Luecke in Sequenznummern: erwartet %d, erhalten %d – akzeptiere trotzdem",
                self.empfangs_sequenz,
                empfangene_seq,
            )

        self.empfangs_sequenz = empfangene_seq + 1  # Naechste erwartete Sequenz
        return True

    # ---------------------------------------------------------------------------
    # Task 3.2 – Verbindungsaufbau
    # ---------------------------------------------------------------------------

    def verbindungsaufbau(self) -> bool:
        """Fuehrt den Anwendungs-Verbindungsaufbau durch (CONNECT/ACK-Phase).

        Im Server-Modus: Wartet auf CONNECT-Paket, sendet ACK.
        Im Client-Modus: Sendet CONNECT-Paket, wartet auf ACK.

        Zustandsuebergaenge:
            GETRENNT → VERBINDEND → VERBUNDEN (bei Erfolg)
            GETRENNT → VERBINDEND → GETRENNT  (bei Fehler)

        Rueckgabe:
            True wenn Verbindungsaufbau erfolgreich, False bei Fehler
        """
        self._zustand_setzen(SitzungsZustand.VERBINDEND)

        if self.server_modus:
            return self._verbindungsaufbau_server()
        else:
            return self._verbindungsaufbau_client()

    def _verbindungsaufbau_server(self) -> bool:
        """Server-seitiger Verbindungsaufbau: Empfaengt CONNECT und sendet ACK.

        Rueckgabe:
            True bei Erfolg, False bei Fehler
        """
        logger.info("Warte auf CONNECT-Paket ...")

        # VERBINDUNGS_TIMEOUT: Begrenzter Zeitraum fuer initialen Handshake
        ergebnis = self._paket_empfangen_intern(timeout=konfig.VERBINDUNGS_TIMEOUT)
        if ergebnis is None:
            logger.error("Verbindungsaufbau fehlgeschlagen: kein Paket empfangen")
            self._zustand_setzen(SitzungsZustand.GETRENNT)
            return False

        if ergebnis.typ != NachrichtenTyp.CONNECT.value:
            logger.error(
                "Unerwarteter Pakettyp beim Verbindungsaufbau: %02x (erwartet CONNECT=01)",
                ergebnis.typ,
            )
            self._zustand_setzen(SitzungsZustand.GETRENNT)
            return False

        # Peer-Sequenznummer initialisieren
        self.empfangs_sequenz = ergebnis.sequenz + 1

        logger.info("CONNECT empfangen, sende ACK")
        self._ack_senden(ergebnis.sequenz)

        self._zustand_setzen(SitzungsZustand.VERBUNDEN)
        return True

    def _verbindungsaufbau_client(self) -> bool:
        """Client-seitiger Verbindungsaufbau: Sendet CONNECT und wartet auf ACK.

        Rueckgabe:
            True bei Erfolg, False bei Fehler
        """
        payload_dict = {
            "absender": self.absender_name,
            "version": konfig.APP_VERSION,
        }
        payload = json.dumps(payload_dict).encode("utf-8")

        seq = self._naechste_sende_seq()  # Sequenz 1 fuer CONNECT
        logger.info("Sende CONNECT-Paket (Seq: %d, Absender: %s)", seq, self.absender_name)
        self._paket_senden_raw(NachrichtenTyp.CONNECT.value, seq, payload)

        # Auf ACK des Servers warten – VERBINDUNGS_TIMEOUT fuer Handshake-Phase
        ergebnis = self._paket_empfangen_intern(timeout=konfig.VERBINDUNGS_TIMEOUT)
        if ergebnis is None:
            logger.error("Verbindungsaufbau fehlgeschlagen: kein ACK empfangen")
            self._zustand_setzen(SitzungsZustand.GETRENNT)
            return False

        if ergebnis.typ != NachrichtenTyp.ACK.value:
            logger.error(
                "Unerwarteter Pakettyp statt ACK: %02x (erwartet ACK=04)",
                ergebnis.typ,
            )
            self._zustand_setzen(SitzungsZustand.GETRENNT)
            return False

        self._zustand_setzen(SitzungsZustand.VERBUNDEN)
        logger.info("Verbindung aufgebaut – Sitzung aktiv (Server-ACK fuer Seq %d)", ergebnis.sequenz)
        return True

    # ---------------------------------------------------------------------------
    # Task 3.3 – Nachricht senden (DATA + ACK mit Retry)
    # ---------------------------------------------------------------------------

    def nachricht_senden(self, nachricht_text: str) -> bool:
        """Sendet eine DATA-Nachricht und wartet auf ACK (mit Retry).

        Payload-Format: JSON mit Schluessel "nachricht", "zeitstempel", "absender".
        Sequenznummer wird inkrementiert. Bei Timeout: bis zu MAX_WIEDERHOLUNGEN Versuche
        mit exponentiellem Backoff.

        Parameter:
            nachricht_text: Der zu sendende Nachrichtentext (UTF-8)

        Rueckgabe:
            True bei erfolgreichem Senden und Bestaetigung, False bei dauerhaftem Fehler
        """
        if self.zustand != SitzungsZustand.VERBUNDEN:
            logger.error(
                "Senden nicht moeglich: Zustand ist %s (erwartet VERBUNDEN)",
                self.zustand.value,
            )
            return False

        payload_dict = {
            "nachricht": nachricht_text,
            "zeitstempel": datetime.now().isoformat(),
            "absender": self.absender_name,
        }
        payload = json.dumps(payload_dict, ensure_ascii=False).encode("utf-8")

        seq = self._naechste_sende_seq()  # Sequenznummer inkrementieren
        paket = paket_erstellen(NachrichtenTyp.DATA.value, seq, payload, self.schluessel)

        wartezeit = konfig.BACKOFF_BASIS  # Startwartezeit fuer exponentiellen Backoff

        for versuch in range(1, konfig.MAX_WIEDERHOLUNGEN + 1):
            logger.debug(
                "Sende DATA-Paket: Seq=%d Versuch=%d/%d",
                seq, versuch, konfig.MAX_WIEDERHOLUNGEN,
            )

            try:
                daten_senden(self.verbindung, paket)
            except (OSError, ssl.SSLError) as fehler:
                logger.error("Senden fehlgeschlagen (Versuch %d): %s", versuch, fehler)
                if versuch == konfig.MAX_WIEDERHOLUNGEN:
                    logger.error("Maximale Wiederholungen erreicht – Senden aufgegeben (Seq %d)", seq)
                    return False
                time.sleep(wartezeit)
                wartezeit = min(wartezeit * konfig.BACKOFF_FAKTOR, konfig.BACKOFF_MAX)
                continue

            # Auf ACK warten – aus der _ack_queue, die der Empfangs-Thread befuellt.
            # Direktes Lesen vom Socket wuerde mit der Empfangsschleife konkurrieren
            # und das ACK-Paket koennte von dort "gestohlen" werden (Race Condition).
            try:
                ack = self._ack_queue.get(timeout=konfig.SENDE_TIMEOUT)
            except queue.Empty:
                logger.warning(
                    "Kein ACK empfangen (Versuch %d/%d, Seq %d) – Timeout nach %.1fs",
                    versuch, konfig.MAX_WIEDERHOLUNGEN, seq, konfig.SENDE_TIMEOUT,
                )
                if versuch == konfig.MAX_WIEDERHOLUNGEN:
                    logger.error("Maximale Wiederholungen nach Timeout erreicht (Seq %d)", seq)
                    return False
                time.sleep(wartezeit)
                wartezeit = min(wartezeit * konfig.BACKOFF_FAKTOR, konfig.BACKOFF_MAX)
                continue

            if ack.typ == NachrichtenTyp.ACK.value and ack.sequenz == seq:
                logger.info("DATA gesendet und bestaetigt (Seq: %d)", seq)
                return True

            logger.warning(
                "Unerwartetes Paket als ACK-Antwort: Typ=%02x Seq=%d (erwartet ACK fuer Seq=%d)",
                ack.typ, ack.sequenz, seq,
            )
            # Naechsten Versuch ohne Sleep probieren (falsches Paket, kein Timeout)

        return False

    # ---------------------------------------------------------------------------
    # Task 3.4 – Verbindungsabbau (DISCONNECT + ACK)
    # ---------------------------------------------------------------------------

    def verbindungsabbau(self) -> None:
        """Graceful Shutdown: Sendet DISCONNECT, wartet auf ACK, schliesst Verbindung.

        Zustandsuebergaenge:
            VERBUNDEN → TRENNEND → GETRENNT

        Bei bereits getrennter Verbindung wird nur der Zustand aktualisiert.
        """
        if self.zustand not in (SitzungsZustand.VERBUNDEN, SitzungsZustand.VERBINDEND):
            logger.warning(
                "Verbindungsabbau: Zustand ist bereits %s – Socket wird trotzdem geschlossen",
                self.zustand.value,
            )
            self._socket_schliessen()
            return

        self._zustand_setzen(SitzungsZustand.TRENNEND)

        payload = json.dumps({"grund": "Normaler Verbindungsabbau"}).encode("utf-8")
        seq = self._naechste_sende_seq()

        logger.info("Sende DISCONNECT-Paket (Seq: %d)", seq)

        try:
            self._paket_senden_raw(NachrichtenTyp.DISCONNECT.value, seq, payload)
        except (OSError, ssl.SSLError) as fehler:
            logger.error("Senden von DISCONNECT fehlgeschlagen: %s – schliesse trotzdem", fehler)
            self._zustand_setzen(SitzungsZustand.GETRENNT)
            self._socket_schliessen()
            return

        # Auf DISCONNECT-ACK warten.
        # Zuerst in der _ack_queue nachsehen: Empfangs-Thread koennte das ACK
        # bereits abgeholt und eingestellt haben, bevor er wegen TRENNEND-Zustand endet.
        # Fallback: direkt vom Socket lesen, falls der Empfangs-Thread bereits beendet ist.
        try:
            ack = self._ack_queue.get(timeout=konfig.VERBINDUNGS_TIMEOUT)
            if ack.typ == NachrichtenTyp.ACK.value:
                logger.info("DISCONNECT-ACK empfangen (Seq: %d)", ack.sequenz)
            else:
                logger.warning("Unerwartetes Paket statt DISCONNECT-ACK – fahre fort")
        except queue.Empty:
            # Empfangs-Thread war bereits beendet → direkt vom Socket lesen
            ack = self._paket_empfangen_intern(timeout=konfig.VERBINDUNGS_TIMEOUT)
            if ack is not None and ack.typ == NachrichtenTyp.ACK.value:
                logger.info("DISCONNECT-ACK empfangen (Seq: %d, Fallback-Lesen)", ack.sequenz)
            else:
                logger.warning("Kein gueltiges ACK auf DISCONNECT erhalten – fahre fort")

        self._zustand_setzen(SitzungsZustand.GETRENNT)
        self._socket_schliessen()

    def _socket_schliessen(self) -> None:
        """Schliesst TLS- und TCP-Socket sauber.

        Ignoriert Fehler beim Schliessen (Socket koennte bereits geschlossen sein).
        """
        try:
            self.verbindung.shutdown(socket.SHUT_RDWR)  # Graceful TLS-Shutdown
        except OSError as fehler:
            logger.debug("Socket-Shutdown ignoriert (bereits geschlossen): %s", fehler)

        try:
            self.verbindung.close()  # Socket-Ressource freigeben
        except OSError as fehler:
            logger.debug("Socket-Schliessen ignoriert (bereits geschlossen): %s", fehler)

        logger.info("Verbindung vollstaendig geschlossen")

    # ---------------------------------------------------------------------------
    # Task 3.5 – Nachricht empfangen (Dispatch)
    # ---------------------------------------------------------------------------

    def nachricht_empfangen(self) -> dict | None:
        """Empfaengt ein Paket und routet es an den passenden Handler.

        Dispatch-Tabelle:
            DATA       → ACK senden, decodierten Payload-Dict zurueckgeben
            DISCONNECT → ACK senden, Zustand → GETRENNT, None zurueckgeben
            ACK        → ignorieren (unerwartet in dieser Phase), None
            CONNECT    → ignorieren (Verbindung bereits aufgebaut), None
            Unbekannt  → warnen, None

        Rueckgabe:
            Payload-Dict bei DATA-Paketen, None bei Kontrollpaketen oder Fehler
        """
        # EMPFANG_TIMEOUT: Laengere Wartezeit, da Nutzer Zeit zum Tippen benoetigt
        ergebnis = self._paket_empfangen_intern(timeout=konfig.EMPFANG_TIMEOUT)
        if ergebnis is None:
            return None

        match ergebnis.typ:
            case NachrichtenTyp.DATA.value:
                return self._handler_data(ergebnis)
            case NachrichtenTyp.DISCONNECT.value:
                return self._handler_disconnect(ergebnis)
            case NachrichtenTyp.ACK.value:
                # ACK in die Queue stellen, damit nachricht_senden() es abholen kann.
                # Frueheres Verwerfen war der Grund fuer die ACK-Race-Condition:
                # Der Empfangs-Thread las das ACK zuerst und warf es weg; der
                # Sende-Thread bekam nie eine Bestaetigung und lief in den Timeout.
                logger.debug(
                    "ACK empfangen (Seq: %d) – wird an Sende-Thread weitergeleitet",
                    ergebnis.sequenz,
                )
                self._ack_queue.put(ergebnis)
                return None
            case NachrichtenTyp.CONNECT.value:
                logger.warning(
                    "Unerwartetes CONNECT empfangen – Verbindung bereits aufgebaut"
                )
                return None
            case _:
                logger.warning("Unbekannter Pakettyp: %02x", ergebnis.typ)
                return None

    def _handler_data(self, ergebnis: PaketErgebnis) -> dict | None:
        """Verarbeitet ein eingehendes DATA-Paket.

        Prueft Sequenznummer, sendet ACK und gibt decodierten Payload zurueck.

        Parameter:
            ergebnis: Verifiziertes PaketErgebnis mit Typ=DATA

        Rueckgabe:
            Payload-Dict oder None bei Fehler
        """
        # Sequenznummer auf Duplikate und Veraltung pruefen
        if not self._sequenz_pruefen(ergebnis.sequenz):
            return None  # Duplikat oder veraltet – verwerfen

        try:
            payload_dict: dict = json.loads(ergebnis.payload.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as fehler:
            logger.error("Ungueltige JSON-Payload im DATA-Paket: %s", fehler)
            return None

        nachricht = payload_dict.get("nachricht", "<leer>")
        logger.info("DATA empfangen: \"%s\" (Seq: %d)", nachricht, ergebnis.sequenz)

        # ACK fuer diese DATA-Nachricht senden
        self._ack_senden(ergebnis.sequenz)
        logger.info("ACK gesendet (Seq: %d)", ergebnis.sequenz)

        return payload_dict

    def _handler_disconnect(self, ergebnis: PaketErgebnis) -> None:
        """Verarbeitet ein eingehendes DISCONNECT-Paket.

        Sendet ACK und setzt Zustand auf GETRENNT.

        Parameter:
            ergebnis: Verifiziertes PaketErgebnis mit Typ=DISCONNECT
        """
        logger.info("DISCONNECT empfangen, sende ACK")
        self._ack_senden(ergebnis.sequenz)
        self._zustand_setzen(SitzungsZustand.GETRENNT)
        self._socket_schliessen()
        return None
