"""
sitzung.py – Protokoll-Sitzungsmanagement mit State Machine

Beschreibung: Vollständige Implementierung des Anwendungsprotokolls über TLS:
              - NDJSON-Framing (newline-delimited JSON)
              - Nachrichtenschema: type, protocol_version, msg_id, session_id, timestamp, payload
              - 7-Zustands-Automat: GETRENNT → TLS_AUFGEBAUT → HANDSHAKE_AUSSTEHEND
                                    → BEREIT → VERALTET → SCHLIESSEN → GETRENNT
              - App-Handshake (HELLO / HELLO_ACK) nach TLS
              - CHAT + RECV_ACK mit Timeout → STALE/Close
              - Deduplizierung per session_id (OrderedDict, max DEDUP_MAX_IDS)
              - Heartbeat (PING/PONG) nur bei Idle, nach 2 verpassten PONGs trennen
              - Geordneter Verbindungsabbau (CLOSE) und Fehlerbehandlung (ERROR)
Autor:        Gruppe 2
Datum:        2026-04-16
Modul:        Network Security 2026
"""

import asyncio
import collections
import json
import logging
import ssl
import uuid
from datetime import datetime, timezone
from enum import Enum

import konfig
from netzwerk import frame_empfangen, frame_senden

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Zustandsautomat
# ---------------------------------------------------------------------------

class SitzungsZustand(Enum):
    """7-Zustands-Automat der Sitzung."""

    GETRENNT             = "GETRENNT"              # Keine aktive Verbindung
    TCP_VERBUNDEN        = "TCP_VERBUNDEN"          # TCP aufgebaut (nicht genutzt, mTLS direkt)
    TLS_AUFGEBAUT        = "TLS_AUFGEBAUT"          # TLS-Kanal aktiv, App-Handshake aussteht
    HANDSHAKE_AUSSTEHEND = "HANDSHAKE_AUSSTEHEND"   # HELLO gesendet/empfangen, Antwort aussteht
    BEREIT               = "BEREIT"                 # Session ready – Chat-Nachrichten erlaubt
    VERALTET             = "VERALTET"               # ACK/Heartbeat-Timeout – Verbindung verdächtig
    SCHLIESSEN           = "SCHLIESSEN"             # Geordneter Abbau läuft


# ---------------------------------------------------------------------------
# Hilfsfunktionen
# ---------------------------------------------------------------------------

def _jetzt_iso() -> str:
    """Gibt den aktuellen UTC-Zeitstempel als ISO-8601-String zurück."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _neue_id(prefix: str = "") -> str:
    """Erzeugt eine UUID-basierte ID mit optionalem Präfix."""
    return (f"{prefix}-" if prefix else "") + str(uuid.uuid4())


# ---------------------------------------------------------------------------
# Sitzung
# ---------------------------------------------------------------------------

class Sitzung:
    """P2P-Chat-Sitzung mit vollständigem Anwendungsprotokoll.

    Attribute:
        reader:         asyncio.StreamReader der TLS-Verbindung
        writer:         asyncio.StreamWriter der TLS-Verbindung
        absender_name:  Anzeigename dieses Peers
        server_modus:   True = Server-Seite, False = Client-Seite
        zustand:        Aktueller SitzungsZustand
        sitzungs_id:    Session-ID (gesetzt nach erfolgreichem Handshake)
        ui_queue:       asyncio.Queue – CHAT-Nachrichten für die UI-Schicht
    """

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        absender_name: str,
        server_modus: bool = False,
    ) -> None:
        self.reader = reader
        self.writer = writer
        self.absender_name = absender_name
        self.server_modus = server_modus
        self.zustand = SitzungsZustand.TLS_AUFGEBAUT
        self.sitzungs_id: str = ""

        # Interne Datenstrukturen (Feature-spec §"Implementierung in Python asyncio")
        self._pending_acks: dict[str, asyncio.Future] = {}
        self._pending_pings: dict[str, asyncio.Future] = {}
        self._seen_ids: collections.OrderedDict[str, None] = collections.OrderedDict()
        self._last_activity: float = 0.0
        self._missed_pongs: int = 0

        # UI-Queue: serialisierter CHAT-Nachrichtenstrom für konsole.py
        self.ui_queue: asyncio.Queue[dict | None] = asyncio.Queue()

        # Hintergrund-Tasks (gestartet in verbinden())
        self._receiver_task: asyncio.Task | None = None
        self._heartbeat_task: asyncio.Task | None = None

    # -------------------------------------------------------------------------
    # Zustandsautomat
    # -------------------------------------------------------------------------

    def _zustand_setzen(self, neu: SitzungsZustand) -> None:
        """Ändert den Zustand und protokolliert den Übergang."""
        alt = self.zustand
        self.zustand = neu
        logger.info("Zustand: %s → %s", alt.value, neu.value)

    @property
    def ist_aktiv(self) -> bool:
        """True wenn die Sitzung im Zustand BEREIT ist."""
        return self.zustand == SitzungsZustand.BEREIT

    # -------------------------------------------------------------------------
    # Framing (delegiert an netzwerk.py)
    # -------------------------------------------------------------------------

    async def _senden(self, frame: dict) -> None:
        await frame_senden(self.writer, frame)

    async def _empfangen(self) -> dict:
        return await frame_empfangen(self.reader)

    # -------------------------------------------------------------------------
    # Frame-Bau
    # -------------------------------------------------------------------------

    def _frame(self, typ: str, payload: dict, msg_id: str | None = None) -> dict:
        """Baut einen vollständigen Protokoll-Frame mit allen Pflichtfeldern."""
        return {
            "type": typ,
            "protocol_version": konfig.PROTOKOLL_VERSION,
            "session_id": self.sitzungs_id,
            "msg_id": msg_id or _neue_id(),
            "timestamp": _jetzt_iso(),
            "payload": payload,
        }

    # -------------------------------------------------------------------------
    # Pflichtfeld-Validierung
    # -------------------------------------------------------------------------

    def _validieren(self, frame: dict) -> bool:
        """Prüft Pflichtfelder und Protokollversion eines empfangenen Frames."""
        for pflicht in ("type", "protocol_version", "timestamp"):
            if pflicht not in frame:
                logger.error("Pflichtfeld fehlt: %s (Frame: %s)", pflicht, frame.get("type"))
                return False
        if frame["protocol_version"] != konfig.PROTOKOLL_VERSION:
            logger.error(
                "Inkompatible Protokollversion: %s (erwartet %s)",
                frame["protocol_version"], konfig.PROTOKOLL_VERSION,
            )
            return False
        return True

    # -------------------------------------------------------------------------
    # App-Handshake (Schritt 4 der Implementierungsreihenfolge)
    # -------------------------------------------------------------------------

    async def verbinden(self) -> None:
        """Führt den App-Handshake durch und startet Receiver/Heartbeat-Tasks.

        Server sendet HELLO, Client antwortet mit HELLO_ACK.
        Erst nach Abschluss wird der Zustand auf BEREIT gesetzt.

        Wirft:
            ConnectionError: Bei Timeout oder Protokollverletzung.
        """
        self._zustand_setzen(SitzungsZustand.HANDSHAKE_AUSSTEHEND)

        try:
            if self.server_modus:
                await self._handshake_server()
            else:
                await self._handshake_client()
        except asyncio.TimeoutError:
            await self._fehler_senden("HANDSHAKE_TIMEOUT", "App-Handshake-Timeout")
            await self._socket_schliessen()
            self._zustand_setzen(SitzungsZustand.GETRENNT)
            raise ConnectionError("App-Handshake Timeout")
        except (ConnectionError, json.JSONDecodeError, OSError) as fehler:
            await self._socket_schliessen()
            self._zustand_setzen(SitzungsZustand.GETRENNT)
            raise ConnectionError(f"Handshake fehlgeschlagen: {fehler}") from fehler

        self._last_activity = asyncio.get_event_loop().time()
        self._zustand_setzen(SitzungsZustand.BEREIT)

        self._receiver_task = asyncio.create_task(
            self._receiver_loop(), name="ReceiverLoop"
        )
        self._heartbeat_task = asyncio.create_task(
            self._heartbeat_loop(), name="HeartbeatLoop"
        )
        logger.info(
            "Sitzung bereit: session_id=%s, Peer=%s",
            self.sitzungs_id, self.absender_name,
        )

    async def _handshake_server(self) -> None:
        """Server: HELLO senden, auf HELLO_ACK warten."""
        self.sitzungs_id = "sess-" + str(uuid.uuid4())[:8]

        hello = self._frame(
            "HELLO",
            {"server_name": self.absender_name, "capabilities": ["recv_ack", "ping"]},
        )
        await self._senden(hello)
        logger.debug("HELLO gesendet (session_id=%s)", self.sitzungs_id)

        ack = await asyncio.wait_for(
            self._empfangen(), timeout=konfig.HANDSHAKE_TIMEOUT
        )

        if not self._validieren(ack) or ack.get("type") != "HELLO_ACK":
            raise ConnectionError(
                f"Erwartetes HELLO_ACK, erhalten: {ack.get('type')}"
            )
        logger.debug(
            "HELLO_ACK empfangen von %s",
            ack.get("payload", {}).get("client_name", "?"),
        )

    async def _handshake_client(self) -> None:
        """Client: auf HELLO warten, HELLO_ACK senden."""
        hello = await asyncio.wait_for(
            self._empfangen(), timeout=konfig.HANDSHAKE_TIMEOUT
        )

        if not self._validieren(hello) or hello.get("type") != "HELLO":
            raise ConnectionError(
                f"Erwartetes HELLO, erhalten: {hello.get('type')}"
            )

        self.sitzungs_id = hello.get("session_id", "")
        logger.debug(
            "HELLO empfangen von %s, session_id=%s",
            hello.get("payload", {}).get("server_name", "?"),
            self.sitzungs_id,
        )

        ack = self._frame(
            "HELLO_ACK",
            {"client_name": self.absender_name, "capabilities": ["recv_ack", "ping"]},
        )
        await self._senden(ack)
        logger.debug("HELLO_ACK gesendet")

    # -------------------------------------------------------------------------
    # Receiver Loop (Schritt 5 der Implementierungsreihenfolge)
    # -------------------------------------------------------------------------

    async def _receiver_loop(self) -> None:
        """Empfangs-Schleife: liest Frames und dispatcht nach type.

        Läuft als asyncio Task im Hintergrund. Trennt interne Protokoll-Frames
        (RECV_ACK, PING, PONG, ERROR) von CHAT-Nachrichten für die UI.
        """
        while self.zustand in (SitzungsZustand.BEREIT, SitzungsZustand.VERALTET):
            try:
                frame = await self._empfangen()
            except (ConnectionError, OSError, ssl.SSLError) as fehler:
                logger.error("Verbindungsfehler im Receiver: %s", fehler)
                await self._sitzung_schliessen("VERBINDUNGSFEHLER")
                return
            except json.JSONDecodeError as fehler:
                logger.error("Ungültiges JSON empfangen: %s – trenne sofort", fehler)
                await self._sitzung_schliessen("UNGUELTIGE_FRAME")
                return
            except asyncio.CancelledError:
                return

            # Activity-Timer zurücksetzen (Heartbeat-Policy)
            self._last_activity = asyncio.get_event_loop().time()
            self._missed_pongs = 0

            if not self._validieren(frame):
                await self._fehler_senden("PFLICHTFELD_FEHLT", "Pflichtfeld fehlt")
                await self._sitzung_schliessen("PFLICHTFELD_FEHLT")
                return

            # Session-ID-Prüfung (nach Handshake muss sie übereinstimmen)
            frame_session_id = frame.get("session_id", "")
            if frame_session_id != self.sitzungs_id:
                logger.error(
                    "session_id-Mismatch: erwartet=%s, erhalten=%s",
                    self.sitzungs_id, frame_session_id,
                )
                await self._fehler_senden(
                    "SESSION_MISMATCH",
                    f"session_id mismatch: {frame_session_id}",
                )
                await self._sitzung_schliessen("SESSION_MISMATCH")
                return

            await self._dispatch(frame.get("type"), frame)

    async def _dispatch(self, typ: str | None, frame: dict) -> None:
        """Verteilt einen validierten Frame nach seinem type-Feld."""

        if typ == "RECV_ACK":
            # ACK für gesendete CHAT-Nachricht → passendes Future erfüllen
            reply_to = frame.get("payload", {}).get("reply_to", "")
            fut = self._pending_acks.pop(reply_to, None)
            if fut and not fut.done():
                fut.set_result(True)
            else:
                logger.debug("RECV_ACK für unbekannte msg_id %s – ignoriert", reply_to)

        elif typ == "PONG":
            # Antwort auf PING → passendes Future erfüllen
            reply_to = frame.get("payload", {}).get("reply_to", "")
            fut = self._pending_pings.pop(reply_to, None)
            if fut and not fut.done():
                fut.set_result(True)
            else:
                logger.debug("PONG ohne offenes PING %s – ignoriert", reply_to)

        elif typ == "PING":
            # Eingehender PING → sofort PONG senden
            pong = self._frame("PONG", {"reply_to": frame.get("msg_id", "")})
            await self._senden(pong)

        elif typ == "CHAT":
            if self.zustand != SitzungsZustand.BEREIT:
                await self._fehler_senden(
                    "PROTOKOLL_VERLETZUNG", "CHAT before READY"
                )
                await self._sitzung_schliessen("CHAT_VOR_BEREIT")
                return
            await self._chat_empfangen(frame)

        elif typ == "ERROR":
            logger.error(
                "ERROR vom Peer: code=%s detail=%s",
                frame.get("payload", {}).get("code", ""),
                frame.get("payload", {}).get("detail", ""),
            )
            await self._sitzung_schliessen("PEER_FEHLER")

        elif typ == "CLOSE":
            logger.info("CLOSE vom Peer empfangen")
            await self._sitzung_schliessen("PEER_CLOSE")

        elif typ in ("HELLO", "HELLO_ACK"):
            logger.error("Unerwartetes %s im Zustand BEREIT", typ)
            await self._fehler_senden("PROTOKOLL_VERLETZUNG", f"{typ} nach READY")
            await self._sitzung_schliessen("PROTOKOLL_VERLETZUNG")

        else:
            logger.error("Unbekannter Nachrichtentyp: %s", typ)
            await self._fehler_senden(
                "UNBEKANNTER_TYP", f"Unbekannter Typ: {typ}"
            )
            await self._sitzung_schliessen("UNBEKANNTER_TYP")

    # -------------------------------------------------------------------------
    # CHAT empfangen mit Deduplizierung (Schritt 7)
    # -------------------------------------------------------------------------

    async def _chat_empfangen(self, frame: dict) -> None:
        """Verarbeitet eine eingehende CHAT-Nachricht mit Deduplizierung."""
        msg_id = frame.get("msg_id", "")

        # Deduplizierung: bereits gesehene msg_id?
        if msg_id and msg_id in self._seen_ids:
            logger.debug("Duplikat CHAT %s – verworfen, sende erneut RECV_ACK", msg_id)
            if msg_id:
                await self._senden(self._frame("RECV_ACK", {"reply_to": msg_id}))
            return

        # Deduplizierungs-Cache pflegen (FIFO, max DEDUP_MAX_IDS)
        if msg_id:
            self._seen_ids[msg_id] = None
            if len(self._seen_ids) > konfig.DEDUP_MAX_IDS:
                self._seen_ids.popitem(last=False)

        # RECV_ACK senden: bestätigt "peer-process received", nicht UI-Anzeige
        if msg_id:
            await self._senden(self._frame("RECV_ACK", {"reply_to": msg_id}))

        # An UI-Queue übergeben
        await self.ui_queue.put(frame)

    # -------------------------------------------------------------------------
    # Heartbeat Loop (Schritt 8)
    # -------------------------------------------------------------------------

    async def _heartbeat_loop(self) -> None:
        """Heartbeat-Schleife: sendet PING nur bei Idle.

        Policy (aus konfig.py):
        - Nur senden wenn IDLE_TIMEOUT Sekunden kein Traffic
        - PONG innerhalb PONG_TIMEOUT Sekunden erwartet
        - Nach HEARTBEAT_MAX_FEHLSCHLAEGE verpassten PONGs → SCHLIESSEN
        """
        try:
            while self.zustand == SitzungsZustand.BEREIT:
                await asyncio.sleep(5.0)  # Prüfintervall

                if self.zustand != SitzungsZustand.BEREIT:
                    break

                jetzt = asyncio.get_event_loop().time()
                idle_seit = jetzt - self._last_activity

                if idle_seit < konfig.IDLE_TIMEOUT:
                    continue  # Noch aktiv – kein PING nötig

                # PING senden
                ping_id = _neue_id("ping")
                ping_fut: asyncio.Future = asyncio.get_running_loop().create_future()
                self._pending_pings[ping_id] = ping_fut

                await self._senden(self._frame("PING", {}, msg_id=ping_id))
                logger.debug("PING gesendet (idle seit %.0fs)", idle_seit)

                try:
                    await asyncio.wait_for(ping_fut, timeout=konfig.PONG_TIMEOUT)
                    self._missed_pongs = 0
                    logger.debug("PONG empfangen")
                except asyncio.TimeoutError:
                    self._pending_pings.pop(ping_id, None)
                    self._missed_pongs += 1
                    logger.warning(
                        "PONG-Timeout (verpasst=%d/%d)",
                        self._missed_pongs, konfig.HEARTBEAT_MAX_FEHLSCHLAEGE,
                    )
                    if self._missed_pongs >= konfig.HEARTBEAT_MAX_FEHLSCHLAEGE:
                        logger.error("Heartbeat-Limit erreicht – Verbindung schliessen")
                        await self._sitzung_schliessen("HEARTBEAT_TIMEOUT")
                        return

        except asyncio.CancelledError:
            pass

    # -------------------------------------------------------------------------
    # CHAT senden mit ACK-Mechanik (Schritt 6)
    # -------------------------------------------------------------------------

    async def chat_senden(self, text: str) -> bool:
        """Sendet eine CHAT-Nachricht und wartet auf RECV_ACK.

        Bei Timeout wird die Verbindung als VERALTET markiert und geschlossen.

        Parameter:
            text: Zu sendender Nachrichtentext.

        Rückgabe:
            True bei bestätigtem Empfang durch den Peer-Prozess, False bei Fehler.
        """
        if self.zustand != SitzungsZustand.BEREIT:
            logger.error("chat_senden: Zustand %s statt BEREIT", self.zustand.value)
            return False

        msg_id = _neue_id("msg")
        ack_fut: asyncio.Future = asyncio.get_running_loop().create_future()
        self._pending_acks[msg_id] = ack_fut

        frame = self._frame(
            "CHAT",
            {"sender": self.absender_name, "text": text},
            msg_id=msg_id,
        )

        try:
            await self._senden(frame)
        except (OSError, ssl.SSLError) as fehler:
            logger.error("CHAT senden fehlgeschlagen: %s", fehler)
            self._pending_acks.pop(msg_id, None)
            return False

        try:
            await asyncio.wait_for(ack_fut, timeout=konfig.ACK_TIMEOUT)
            logger.debug("RECV_ACK erhalten für %s", msg_id)
            return True
        except asyncio.TimeoutError:
            self._pending_acks.pop(msg_id, None)
            logger.error(
                "ACK-Timeout für %s – Verbindung auf VERALTET setzen", msg_id
            )
            self._zustand_setzen(SitzungsZustand.VERALTET)
            await self._sitzung_schliessen("ACK_TIMEOUT")
            return False

    # -------------------------------------------------------------------------
    # Fehler senden (Best-effort)
    # -------------------------------------------------------------------------

    async def _fehler_senden(self, code: str, detail: str) -> None:
        """Sendet einen ERROR-Frame (Best-effort, Fehler werden ignoriert)."""
        try:
            frame = self._frame("ERROR", {"code": code, "detail": detail})
            await self._senden(frame)
        except Exception:
            pass

    # -------------------------------------------------------------------------
    # Graceful Close + Verbindungsabbau (Schritt 9)
    # -------------------------------------------------------------------------

    async def verbindungsabbau(self) -> None:
        """Geordneter Verbindungsabbau: CLOSE senden, Tasks stoppen, Socket schliessen."""
        if self.zustand in (SitzungsZustand.GETRENNT, SitzungsZustand.SCHLIESSEN):
            return
        await self._sitzung_schliessen("NUTZER_QUIT")

    async def _sitzung_schliessen(self, grund: str = "") -> None:
        """Interne Schliess-Logik.

        Ablauf: Zustand → SCHLIESSEN, CLOSE senden, UI-Queue signalisieren,
        Hintergrund-Tasks canceln, Socket schliessen, Zustand → GETRENNT.
        """
        if self.zustand in (SitzungsZustand.GETRENNT, SitzungsZustand.SCHLIESSEN):
            return

        self._zustand_setzen(SitzungsZustand.SCHLIESSEN)
        logger.info("Sitzung wird geschlossen (Grund: %s)", grund)

        # CLOSE senden – nur wenn nicht Peer bereits geschlossen/Fehler
        if grund not in ("PEER_CLOSE", "PEER_FEHLER", "VERBINDUNGSFEHLER",
                         "UNGUELTIGE_FRAME", "PFLICHTFELD_FEHLT"):
            try:
                close_frame = self._frame("CLOSE", {"reason": grund})
                await asyncio.wait_for(
                    self._senden(close_frame), timeout=konfig.CLOSE_TIMEOUT
                )
            except Exception:
                pass

        # UI-Queue signalisieren: None = Ende des Nachrichtenstroms
        await self.ui_queue.put(None)

        # Hintergrund-Tasks canceln (nicht den aufrufenden Task selbst)
        laufender_task = asyncio.current_task()
        for task in (self._receiver_task, self._heartbeat_task):
            if task and not task.done() and task is not laufender_task:
                task.cancel()
                try:
                    await task
                except (asyncio.CancelledError, Exception):
                    pass

        await self._socket_schliessen()
        self._zustand_setzen(SitzungsZustand.GETRENNT)

    async def _socket_schliessen(self) -> None:
        """Schliesst TLS-Stream sauber (close + wait_closed)."""
        try:
            self.writer.close()
            await self.writer.wait_closed()
        except OSError as fehler:
            logger.debug("Socket-Schliessen ignoriert (bereits geschlossen): %s", fehler)
        logger.info("Verbindung vollständig geschlossen")

    # -------------------------------------------------------------------------
    # UI-Schnittstelle für konsole.py
    # -------------------------------------------------------------------------

    async def naechste_chat_nachricht(self) -> dict | None:
        """Gibt die nächste CHAT-Nachricht aus der UI-Queue zurück.

        Rückgabe:
            Frame-dict bei empfangener Nachricht, None wenn Verbindung endet.
        """
        return await self.ui_queue.get()
