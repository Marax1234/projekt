#!/usr/bin/env bash
# zertifikate_erstellen.sh – Erstellt CA + Peer-Zertifikat für mTLS
#
# Erzeugte Dateien:
#   ca_schluessel.pem   – CA-Privatschlüssel (NICHT verteilen)
#   ca_zertifikat.pem   – CA-Zertifikat (an alle Peers verteilen)
#   schluessel.pem      – Peer-Privatschlüssel (lokal behalten)
#   zertifikat.pem      – Peer-Zertifikat (signiert von CA, an Partner-Peer geben)
#
# Verwendung:
#   Einmalig pro Peer ausführen:
#       bash zertifikate_erstellen.sh
#
#   Danach ca_zertifikat.pem und zertifikat.pem an den anderen Peer übertragen,
#   damit beide Seiten das CA-Zertifikat zur Verifikation besitzen.
#
# Hinweis: ca_schluessel.pem wird nur zur Signierung benötigt und muss
#          NICHT an andere Peers weitergegeben werden.

set -euo pipefail

SKRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SKRIPT_DIR"

CA_KEY="ca_schluessel.pem"
CA_CERT="ca_zertifikat.pem"
PEER_KEY="schluessel.pem"
PEER_CERT="zertifikat.pem"
PEER_CSR="peer_anfrage.pem"

echo "[1/4] Erzeuge CA-Schlüssel ..."
openssl genrsa -out "$CA_KEY" 4096 2>/dev/null

echo "[2/4] Erzeuge selbstsigniertes CA-Zertifikat (10 Jahre) ..."
openssl req -new -x509 -days 3650 \
    -key "$CA_KEY" \
    -out "$CA_CERT" \
    -subj "/CN=P2PChat-CA/O=DHBW-NetSec-2026/OU=Gruppe2" \
    2>/dev/null

echo "[3/4] Erzeuge Peer-Schlüssel und Certificate Signing Request ..."
openssl genrsa -out "$PEER_KEY" 2048 2>/dev/null
openssl req -new \
    -key "$PEER_KEY" \
    -out "$PEER_CSR" \
    -subj "/CN=P2PChat-Peer/O=DHBW-NetSec-2026/OU=Gruppe2" \
    2>/dev/null

echo "[4/4] Signiere Peer-Zertifikat mit CA (1 Jahr) ..."
openssl x509 -req -days 365 \
    -in "$PEER_CSR" \
    -CA "$CA_CERT" \
    -CAkey "$CA_KEY" \
    -CAcreateserial \
    -out "$PEER_CERT" \
    2>/dev/null

rm -f "$PEER_CSR" ca_zertifikat.srl

echo ""
echo "Fertig. Erzeugte Dateien:"
echo "  $CA_CERT    – an alle Peers verteilen"
echo "  $PEER_CERT  – eigenes Peer-Zertifikat"
echo "  $PEER_KEY   – privater Schlüssel (lokal behalten)"
echo "  $CA_KEY     – CA-Schlüssel (lokal behalten, nicht verteilen)"
echo ""
echo "Nächster Schritt: ca_zertifikat.pem an den anderen Peer übertragen."
