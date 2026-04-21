# Sequenzdiagramme – P2P mTLS Chat-Protokoll

> Autor: Gruppe 2 | Modul: Network Security 2026

Die drei Diagramme bilden den vollständigen Protokollablauf ab:
1. **Verbindungsaufbau** – TCP + mTLS 1.3 + App-Handshake
2. **Datenübertragung** – CHAT, ACK, Heartbeat, ACK-Timeout
3. **Verbindungsabbruch, Retry & Resend** – Erkennung, Backoff, Session-Resumption, Outbox

---

## Diagramm 1 – Verbindungsaufbau (TCP → mTLS → App-Handshake)

```mermaid
sequenceDiagram
    autonumber
    participant A as Client A
    participant B as Client B

    rect rgb(220, 235, 255)
        Note over A,B: Phase 1 – TCP-Verbindungsaufbau (Race to Connect, Port 49200)
        A->>B: TCP SYN
        B-->>A: TCP SYN-ACK
        A->>B: TCP ACK
        Note over A,B: TCP-Verbindung hergestellt
    end

    rect rgb(220, 255, 230)
        Note over A,B: Phase 2 – mTLS 1.3 Handshake (gegenseitige Zertifikatsauthentifizierung)
        A->>B: ClientHello (TLS 1.3, key_share, supported_groups)
        B-->>A: ServerHello + EncryptedExtensions
        B-->>A: Certificate [Zertifikat B, CA-signiert]
        B-->>A: CertificateVerify + Finished
        Note left of A: Prüft Zertifikat B gegen CA
        A->>B: Certificate [Zertifikat A, CA-signiert]
        A->>B: CertificateVerify + Finished
        Note right of B: Prüft Zertifikat A gegen CA
        Note over A,B: Verschlüsselter mTLS-Kanal aktiv (TLSv1.3)
    end

    rect rgb(255, 245, 210)
        Note over A,B: Phase 3 – App-Handshake (Zustand: TLS_AUFGEBAUT → BEREIT)
        Note right of B: Rolle: Server (Race-to-Connect Gewinner)
        B->>A: APP_HELLO {server_name, capabilities, session_id, resume_token, last_received_seq=-1}
        Note left of A: Übernimmt session_id, merkt last_received_seq
        A-->>B: APP_HELLO_ACK {client_name, capabilities, resume_token, last_received_seq=-1}
        Note right of B: Merkt peer last_received_seq
        Note over A,B: Zustand → BEREIT | Receiver-Task + Heartbeat-Task gestartet
    end
```

---

## Diagramm 2 – Datenübertragung (CHAT + ACK + Heartbeat)

```mermaid
sequenceDiagram
    autonumber
    participant A as Client A
    participant B as Client B

    rect rgb(220, 235, 255)
        Note over A,B: Normaler Nachrichtenaustausch (Zustand: BEREIT)
        A->>B: CHAT {msg_id=X, seq=0, data: {sender, text}}
        activate B
        B-->>A: APP_MSG_ACK {msg_id=X, seq=0}
        deactivate B
        Note left of A: seq=0 aus _outbox entfernt

        B->>A: CHAT {msg_id=Y, seq=0, data: {sender, text}}
        activate A
        A-->>B: APP_MSG_ACK {msg_id=Y, seq=0}
        deactivate A
        Note right of B: Deduplizierung via msg_id (OrderedDict)
    end

    rect rgb(220, 255, 230)
        Note over A,B: Idle-Erkennung – Heartbeat (APP_PING / APP_PONG)
        Note right of B: Kein Traffic > PING_INTERVALL → PING_PENDING
        B->>A: APP_PING {msg_id=P}
        activate A
        A-->>B: APP_PONG {msg_id=P}
        deactivate A
        Note right of B: missed_pongs := 0, Zustand → VERBUNDEN

        A->>B: APP_PING {msg_id=Q}
        activate B
        B-->>A: APP_PONG {msg_id=Q}
        deactivate B
    end

    rect rgb(255, 235, 235)
        Note over A,B: ACK-Timeout (Nachricht nicht bestätigt → Verbindungsabbau)
        A->>B: CHAT {msg_id=Z, seq=1, data: {sender, text}}
        Note right of B: ACK-Timeout nach konfig.ACK_TIMEOUT
        Note left of A: Zustand → VERALTET
        A-->>B: APP_CLOSE {reason: ACK_TIMEOUT}
        Note over A,B: Geordneter Verbindungsabbau eingeleitet
    end
```

---

## Diagramm 3 – Verbindungsabbruch, Retry & Outbox-Resend

```mermaid
sequenceDiagram
    autonumber
    participant A as Client A
    participant B as Client B

    rect rgb(255, 235, 235)
        Note over A,B: Verbindungsabbruch – unerwartetes TCP-RST / Timeout
        A->>B: CHAT {msg_id=M1, seq=1, text="Nachricht während Abbruch"}
        Note over A,B: ~~~ Verbindung bricht ab ~~~
        Note left of A: Kein APP_MSG_ACK → seq=1 bleibt in _outbox
        Note left of A: HEARTBEAT_TIMEOUT oder EMPFANG_TIMEOUT erkannt
        Note left of A: Zustand: BEREIT → GETRENNT
        Note left of A: trenn_grund = HEARTBEAT_TIMEOUT
    end

    rect rgb(255, 245, 210)
        Note over A,B: Reconnect mit exponentiellem Backoff + Jitter
        loop bis MAX_RECONNECT_VERSUCHE erreicht
            Note left of A: Warte backoff = min(2^versuch + jitter, 10s)
            A->>B: TCP SYN (Versuch 1)
            alt Verbindung fehlgeschlagen
                B--xA: Timeout / Connection Refused
                Note left of A: versuch += 1 → nächster Backoff
            else Verbindung erfolgreich
                B-->>A: TCP SYN-ACK
                A->>B: TCP ACK
            end
        end
    end

    rect rgb(220, 255, 230)
        Note over A,B: mTLS Re-Handshake (identisch zu Verbindungsaufbau)
        A->>B: ClientHello (TLS 1.3)
        B-->>A: ServerHello + Certificate [B] + Finished
        A->>B: Certificate [A] + Finished
        Note over A,B: mTLS-Kanal wiederhergestellt
    end

    rect rgb(220, 235, 255)
        Note over A,B: App-Handshake mit Session-Resumption
        B->>A: APP_HELLO {resume_token, last_received_seq=0}
        Note left of A: Peer hat seq=0 empfangen, seq=1 fehlt noch
        A-->>B: APP_HELLO_ACK {resume_token, last_received_seq=0}
        Note over A,B: Zustand → BEREIT | versuch := 0
    end

    rect rgb(220, 255, 220)
        Note over A,B: Outbox-Resend – ausstehende Nachrichten erneut senden
        Note left of A: outbox_wiederholen() – seq=1 noch unbestätigt
        A->>B: CHAT {msg_id=M1-neu, seq=1, text="Nachricht während Abbruch"} [RESEND]
        activate B
        B-->>A: APP_MSG_ACK {seq=1}
        deactivate B
        Note left of A: seq=1 aus _outbox entfernt – _bestaetigt_bis=1
        Note over A,B: Normaler Betrieb wiederhergestellt
    end
```

---

## Protokoll-Nachrichtentypen (Referenz)

| Typ             | Richtung         | Beschreibung                                      |
|-----------------|------------------|---------------------------------------------------|
| `APP_HELLO`     | Server → Client  | Startet App-Handshake, überträgt `session_id`     |
| `APP_HELLO_ACK` | Client → Server  | Bestätigt Handshake, gibt `last_received_seq` an  |
| `CHAT`          | beide            | Nachricht mit `msg_id`, `seq`, `sender`, `text`   |
| `APP_MSG_ACK`   | beide            | Bestätigt empfangene CHAT-Nachricht (per `seq`)   |
| `APP_PING`      | beide            | Heartbeat-Anfrage bei Idle                        |
| `APP_PONG`      | beide            | Heartbeat-Antwort                                 |
| `APP_CLOSE`     | beide            | Geordneter Verbindungsabbau                       |
| `APP_ERROR`     | beide            | Fehlerrahmen (z. B. bei Protokollverletzung)      |
