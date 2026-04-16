#!/usr/bin/env bash
# zertifikate_erstellen.sh – CA + Peer-Zertifikat für mTLS
#
# VERWENDUNG
# ----------
#   Peer A (generiert CA und eigenes Zertifikat):
#       bash certs/zertifikate_erstellen.sh
#
#   Peer B (CA bereits vorhanden, nur eigenes Zertifikat erstellen):
#       bash certs/zertifikate_erstellen.sh --nur-peer-cert
#
# WORKFLOW
# --------
#   1. Peer A führt das Skript ohne Flag aus.
#   2. Peer A stellt ca_zertifikat.pem + ca_schluessel.pem bereit:
#          cd certs && python3 -m http.server 8080
#   3. Peer B holt die CA-Dateien:
#          wget http://<IP_PEER_A>:8080/ca_zertifikat.pem -O certs/ca_zertifikat.pem
#          wget http://<IP_PEER_A>:8080/ca_schluessel.pem -O certs/ca_schluessel.pem
#   4. Peer B führt das Skript mit --nur-peer-cert aus.
#   5. Peer A stoppt den HTTP-Server (Strg+C).
#
# ERZEUGTE DATEIEN
# ----------------
#   ca_schluessel.pem   – CA-Privatschlüssel       (lokal behalten, nicht verteilen)
#   ca_zertifikat.pem   – CA-Zertifikat             (an Peer B übertragen)
#   schluessel.pem      – Peer-Privatschlüssel      (lokal behalten)
#   zertifikat.pem      – Peer-Zertifikat (CA-sign) (lokal behalten)

set -euo pipefail

SKRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SKRIPT_DIR"

CA_KEY="ca_schluessel.pem"
CA_CERT="ca_zertifikat.pem"
PEER_KEY="schluessel.pem"
PEER_CERT="zertifikat.pem"
PEER_CSR="peer_anfrage.pem"

NUR_PEER_CERT=false
if [[ "${1:-}" == "--nur-peer-cert" ]]; then
    NUR_PEER_CERT=true
fi

# ---------------------------------------------------------------------------
# Modus: nur Peer-Zertifikat (CA muss bereits vorhanden sein)
# ---------------------------------------------------------------------------

if $NUR_PEER_CERT; then
    if [[ ! -f "$CA_CERT" || ! -f "$CA_KEY" ]]; then
        echo "Fehler: $CA_CERT oder $CA_KEY nicht gefunden."
        echo "Bitte zuerst vom anderen Peer holen:"
        echo "  wget http://<IP_PEER_A>:8080/ca_zertifikat.pem -O certs/ca_zertifikat.pem"
        echo "  wget http://<IP_PEER_A>:8080/ca_schluessel.pem -O certs/ca_schluessel.pem"
        exit 1
    fi

    echo "[1/2] Erzeuge Peer-Schlüssel und Certificate Signing Request ..."
    openssl genrsa -out "$PEER_KEY" 2048 2>/dev/null
    openssl req -new \
        -key "$PEER_KEY" \
        -out "$PEER_CSR" \
        -subj "/CN=P2PChat-Peer/O=DHBW-NetSec-2026/OU=Gruppe2" \
        2>/dev/null

    echo "[2/2] Signiere Peer-Zertifikat mit vorhandener CA (1 Jahr) ..."
    openssl x509 -req -days 365 \
        -in "$PEER_CSR" \
        -CA "$CA_CERT" \
        -CAkey "$CA_KEY" \
        -CAcreateserial \
        -out "$PEER_CERT" \
        2>/dev/null

    rm -f "$PEER_CSR" ca_zertifikat.srl

    echo ""
    echo "Fertig (--nur-peer-cert). Erzeugte Dateien:"
    echo "  $PEER_CERT  – Peer-Zertifikat (signiert von gemeinsamer CA)"
    echo "  $PEER_KEY   – privater Schlüssel (lokal behalten)"
    exit 0
fi

# ---------------------------------------------------------------------------
# Modus: vollständig (CA + Peer-Zertifikat)
# ---------------------------------------------------------------------------

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
echo "  $CA_CERT    – an Peer B übertragen (HTTP-Server oder SCP)"
echo "  $CA_KEY     – CA-Schlüssel, an Peer B übertragen damit dieser sein Cert signieren kann"
echo "  $PEER_CERT  – eigenes Peer-Zertifikat"
echo "  $PEER_KEY   – privater Schlüssel (lokal behalten)"
echo ""
echo "Nächster Schritt – CA an Peer B bereitstellen:"
echo "  cd certs && python3 -m http.server 8080"
echo ""
echo "Peer B holt die CA dann mit:"
echo "  wget http://$(hostname -I | awk '{print $1}'):8080/ca_zertifikat.pem -O certs/ca_zertifikat.pem"
echo "  wget http://$(hostname -I | awk '{print $1}'):8080/ca_schluessel.pem -O certs/ca_schluessel.pem"
echo "  bash certs/zertifikate_erstellen.sh --nur-peer-cert"
