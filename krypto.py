"""
krypto.py – HMAC-Berechnung, Verifizierung, Schluessel-Verwaltung

Beschreibung: Stellt kryptografische Hilfsfunktionen bereit: HMAC-SHA256-Berechnung
              und -Verifizierung fuer die Nachrichtenintegritaet auf Anwendungsschicht.
Autor:        Gruppe 2
Datum:        2026-03-24
Modul:        Network Security 2026
"""

import hmac
import hashlib
import logging

from konfig import HMAC_ALGORITHMUS

# Modul-Logger
logger = logging.getLogger(__name__)


def hmac_berechnen(header_ohne_hmac: bytes, payload: bytes, schluessel: bytes) -> bytes:
    """Berechnet den HMAC-SHA256 ueber Header-Anfang und Payload.

    Der HMAC wird ueber die ersten 10 Bytes des Headers (Version, Typ, Sequenz,
    Laenge) sowie den vollstaendigen Payload berechnet – NICHT ueber das HMAC-Feld
    selbst, da dieses zum Berechnungszeitpunkt noch unbekannt ist.

    Parameter:
        header_ohne_hmac: Die ersten 10 Bytes des Headers (Version bis Laenge)
        payload:          Der Payload als Bytes-Objekt
        schluessel:       Der gemeinsame HMAC-Schluessel (Shared Secret)

    Rueckgabe:
        32 Bytes HMAC-SHA256-Digest
    """
    nachricht = header_ohne_hmac + payload  # Konkatenation der zu authentifizierenden Daten
    digest = hmac.new(schluessel, nachricht, HMAC_ALGORITHMUS).digest()
    logger.debug("HMAC berechnet: %s", digest.hex())
    return digest


def hmac_pruefen(paket_ergebnis, schluessel: bytes) -> bool:
    """Verifiziert den HMAC eines empfangenen Pakets.

    Berechnet den erwarteten HMAC neu und vergleicht ihn zeitkonstant mit dem
    im Paket enthaltenen HMAC, um Timing-Angriffe zu verhindern.

    Parameter:
        paket_ergebnis: PaketErgebnis-Objekt mit den Feldern header_roh, hmac, payload
        schluessel:     Der gemeinsame HMAC-Schluessel (Shared Secret)

    Rueckgabe:
        True wenn HMAC korrekt, False bei Manipulation
    """
    erwarteter_hmac = hmac_berechnen(
        paket_ergebnis.header_roh,  # Erste 10 Bytes des empfangenen Headers
        paket_ergebnis.payload,
        schluessel
    )
    # Zeitkonstanter Vergleich verhindert Timing-Angriffe
    ergebnis = hmac.compare_digest(erwarteter_hmac, paket_ergebnis.hmac)
    if not ergebnis:
        logger.warning("HMAC-Pruefung fehlgeschlagen – Paket moeglicherweise manipuliert")
    else:
        logger.debug("HMAC-Pruefung erfolgreich")
    return ergebnis
