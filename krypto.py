"""
krypto.py – Kryptografische Hilfsfunktionen

Beschreibung: Dieses Modul ist bewusst leer gehalten, weil kein eigener
              Krypto-Code benoetigt wird. Die Anforderungen an Vertraulichkeit
              und Integritaet sind bereits vollstaendig durch TLS erfuellt:

              Vertraulichkeit: TLS verschluesselt alle Nutzdaten mit einem
                  symmetrischen AEAD-Verfahren (z. B. AES-256-GCM), das im
                  TLS-Handshake ausgehandelt wird. Dritte koennen den
                  Klartext nicht lesen.

              Integritaet: AEAD (Authenticated Encryption with Associated Data)
                  berechnet fuer jedes TLS-Record einen kryptografischen
                  Authentifizierungstag. Eine Veraenderung der Nutzdaten
                  waehrend der Uebertragung wird vom Empfaenger zuverlassig
                  erkannt und das Paket verworfen.

              Eigener HMAC- oder Signatur-Code wuerde dieselbe Sicherheit
              doppelt implementieren und kein zusaetzliches Schutzziel erfullen.

Autor:        Gruppe 2
Datum:        2026-03-24
Modul:        Network Security 2026
"""
