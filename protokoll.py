"""
protokoll.py – Protokolldefinition: Header, Typen, Pack/Unpack

Beschreibung: Definiert das binaere P2P-Chat-Protokollformat (42-Byte-Header + Payload).
              Enthaelt Funktionen zum Serialisieren und Deserialisieren von Paketen.
Autor:        Gruppe 2
Datum:        2026-03-24
Modul:        Network Security 2026
"""

import struct
import logging
from enum import Enum
from dataclasses import dataclass

from konfig import (
    PROTOKOLL_VERSION,
    HEADER_GROESSE,
    HMAC_LAENGE,
    MAX_PAYLOAD_GROESSE,
)
from krypto import hmac_berechnen

# Modul-Logger
logger = logging.getLogger(__name__)

# Struct-Format fuer die ersten 10 Bytes des Headers (ohne HMAC):
# ! = Network Byte Order (Big Endian)
# B = unsigned char  (1 Byte) – Version
# B = unsigned char  (1 Byte) – Typ
# I = unsigned int   (4 Byte) – Sequenz (uint32)
# I = unsigned int   (4 Byte) – Laenge  (uint32)
HEADER_FORMAT: str = "!BBII"                  # Ergibt 10 Bytes
HEADER_KERN_GROESSE: int = struct.calcsize(HEADER_FORMAT)  # = 10


class NachrichtenTyp(Enum):
    """Definiert alle gueltigen Pakettypen des P2P-Chat-Protokolls."""

    CONNECT: int    = 0x01  # Verbindungsaufbau-Paket
    DATA: int       = 0x02  # Datennachricht
    DISCONNECT: int = 0x03  # Verbindungsabbau-Paket
    ACK: int        = 0x04  # Bestaetigung


@dataclass
class PaketErgebnis:
    """Repraesentiert ein vollstaendig zerlegtes Protokollpaket.

    Felder:
        version:    Protokollversion (sollte 0x01 sein)
        typ:        Nachrichtentyp als Ganzzahl
        sequenz:    Aufsteigende Sequenznummer
        laenge:     Laenge des Payloads in Bytes
        hmac:       32-Byte HMAC-SHA256 aus dem Header
        payload:    Rohe Payload-Bytes
        header_roh: Erste 10 Bytes des Headers (fuer HMAC-Pruefung benoetigt)
    """

    version: int
    typ: int
    sequenz: int
    laenge: int
    hmac: bytes
    payload: bytes
    header_roh: bytes  # Bytes[0:10] des urspruenglichen Headers, fuer HMAC-Verifikation


def header_packen(
    version: int,
    typ: int,
    sequenz: int,
    laenge: int,
    hmac_wert: bytes,
) -> bytes:
    """Serialisiert einen Protokoll-Header in 42 Bytes.

    Aufbau:
        Bytes  0-0:  Version (1 Byte)
        Bytes  1-1:  Typ     (1 Byte)
        Bytes  2-5:  Sequenz (4 Byte, Big Endian uint32)
        Bytes  6-9:  Laenge  (4 Byte, Big Endian uint32)
        Bytes 10-41: HMAC    (32 Byte)

    Parameter:
        version:   Protokollversion (0x01)
        typ:       Nachrichtentyp (0x01–0x04)
        sequenz:   Sequenznummer (uint32)
        laenge:    Payload-Laenge in Bytes (uint32)
        hmac_wert: 32-Byte HMAC-SHA256

    Rueckgabe:
        42 Bytes langer Header als bytes-Objekt

    Fehler:
        ValueError bei ungueltigem HMAC-Laenge oder Parametern ausserhalb des Bereichs
    """
    if len(hmac_wert) != HMAC_LAENGE:
        raise ValueError(
            f"HMAC muss genau {HMAC_LAENGE} Bytes lang sein, erhalten: {len(hmac_wert)}"
        )
    if laenge > MAX_PAYLOAD_GROESSE:
        raise ValueError(
            f"Payload-Laenge {laenge} ueberschreitet Maximum {MAX_PAYLOAD_GROESSE}"
        )

    # Erste 10 Bytes: Version, Typ, Sequenz, Laenge im Netzwerk-Byte-Order
    kern = struct.pack(HEADER_FORMAT, version, typ, sequenz, laenge)
    header = kern + hmac_wert  # Gesamter 42-Byte-Header
    logger.debug(
        "Header gepackt: Version=%02x Typ=%02x Sequenz=%d Laenge=%d",
        version, typ, sequenz, laenge,
    )
    return header


def header_entpacken(header_bytes: bytes) -> tuple[int, int, int, int, bytes]:
    """Deserialisiert einen 42-Byte-Protokoll-Header.

    Parameter:
        header_bytes: Genau 42 Bytes rohe Header-Daten

    Rueckgabe:
        Tuple (version, typ, sequenz, laenge, hmac) mit den geparsten Feldern

    Fehler:
        ValueError wenn header_bytes nicht genau 42 Bytes lang ist
    """
    if len(header_bytes) != HEADER_GROESSE:
        raise ValueError(
            f"Header muss genau {HEADER_GROESSE} Bytes lang sein, erhalten: {len(header_bytes)}"
        )

    # Kern-Felder aus den ersten 10 Bytes extrahieren
    version, typ, sequenz, laenge = struct.unpack(
        HEADER_FORMAT, header_bytes[:HEADER_KERN_GROESSE]
    )
    hmac_wert = header_bytes[HEADER_KERN_GROESSE:]  # Restliche 32 Bytes = HMAC

    logger.debug(
        "Header entpackt: Version=%02x Typ=%02x Sequenz=%d Laenge=%d",
        version, typ, sequenz, laenge,
    )
    return version, typ, sequenz, laenge, hmac_wert


def paket_erstellen(
    typ: int,
    sequenz: int,
    payload: bytes,
    hmac_schluessel: bytes,
    version: int = PROTOKOLL_VERSION,
) -> bytes:
    """Erstellt ein vollstaendiges Protokollpaket (Header + Payload) mit HMAC.

    Ablauf:
        1. Header-Kern (10 Bytes) ohne HMAC berechnen
        2. HMAC ueber Header-Kern + Payload berechnen
        3. Vollstaendigen 42-Byte-Header zusammensetzen
        4. Header + Payload zurueckgeben

    Parameter:
        typ:            Nachrichtentyp (z.B. NachrichtenTyp.DATA.value)
        sequenz:        Sequenznummer dieser Sitzung
        payload:        UTF-8-codiertes JSON als Bytes
        hmac_schluessel: Geteiltes Geheimnis fuer HMAC-Berechnung
        version:        Protokollversion (Standard: 0x01)

    Rueckgabe:
        Vollstaendiges Paket als bytes (42 + len(payload) Bytes)

    Fehler:
        ValueError bei ungueltigem Typ oder zu grossem Payload
    """
    if len(payload) > MAX_PAYLOAD_GROESSE:
        raise ValueError(
            f"Payload ({len(payload)} Bytes) ueberschreitet Maximum ({MAX_PAYLOAD_GROESSE} Bytes)"
        )

    laenge = len(payload)  # Payload-Laenge in Bytes

    # Header-Kern ohne HMAC fuer die HMAC-Berechnung
    header_kern = struct.pack(HEADER_FORMAT, version, typ, sequenz, laenge)

    # HMAC ueber Header-Kern + Payload berechnen
    hmac_wert = hmac_berechnen(header_kern, payload, hmac_schluessel)

    # Vollstaendigen Header zusammensetzen
    header = header_packen(version, typ, sequenz, laenge, hmac_wert)

    paket = header + payload  # Komplettes Paket: 42 Bytes Header + n Bytes Payload
    logger.debug(
        "Paket erstellt: Typ=%02x Sequenz=%d Payload=%d Bytes Gesamt=%d Bytes",
        typ, sequenz, laenge, len(paket),
    )
    return paket


def paket_zerlegen(rohdaten: bytes) -> PaketErgebnis:
    """Zerlegt ein empfangenes Paket in seine Bestandteile.

    Liest den 42-Byte-Header, extrahiert alle Felder und trennt den Payload ab.
    Speichert die ersten 10 Header-Bytes fuer spaetere HMAC-Verifikation.

    Parameter:
        rohdaten: Empfangene Bytes (mindestens 42 Bytes)

    Rueckgabe:
        PaketErgebnis-Objekt mit allen Paketfeldern

    Fehler:
        ValueError wenn rohdaten zu kurz sind oder Laenge-Feld nicht zur tatsaechlichen
        Payload-Laenge passt
    """
    if len(rohdaten) < HEADER_GROESSE:
        raise ValueError(
            f"Paket zu kurz: mindestens {HEADER_GROESSE} Bytes erwartet, "
            f"erhalten: {len(rohdaten)}"
        )

    header_bytes = rohdaten[:HEADER_GROESSE]       # Ersten 42 Bytes = Header
    payload = rohdaten[HEADER_GROESSE:]             # Alles danach = Payload

    version, typ, sequenz, laenge, hmac_wert = header_entpacken(header_bytes)

    # Konsistenzpruefung: Laenge-Feld vs. tatsaechlicher Payload-Laenge
    if laenge != len(payload):
        raise ValueError(
            f"Laenge-Feld ({laenge}) stimmt nicht mit tatsaechlicher Payload-Laenge "
            f"({len(payload)}) ueberein"
        )

    ergebnis = PaketErgebnis(
        version=version,
        typ=typ,
        sequenz=sequenz,
        laenge=laenge,
        hmac=hmac_wert,
        payload=payload,
        header_roh=header_bytes[:HEADER_KERN_GROESSE],  # Erste 10 Bytes fuer HMAC-Pruefung
    )
    logger.debug(
        "Paket zerlegt: Version=%02x Typ=%02x Sequenz=%d Payload=%d Bytes",
        version, typ, sequenz, laenge,
    )
    return ergebnis
