# Beschreibung der Chat-Anwendung "LastRowChat"

Dieses Dokument beschreibt den Ablauf und die Funktionen der Peer-to-Peer Chat-Anwendung anhand von sechs Screenshots. Die Bilder zeigen jeweils beide Chat-Fenster (links PersonA, rechts PersonB) nebeneinander, um die Interaktion übersichtlich darzustellen.

### Bild 1: Start der Anwendung und Initialisierung
Die Chat-Anwendung wird über das Terminal gestartet. Dabei werden die Ziel-IP-Adresse und der Port als Parameter (`--ziel` und `--port`) übergeben. Im Anschluss fordert das Programm zur Eingabe eines Benutzernamens auf. Im linken Fenster wählt der Nutzer den Namen "PersonA", im rechten Fenster "PersonB".

### Bild 2: Warten auf Verbindung
PersonA (linkes Fenster) hat den Startvorgang abgeschlossen. In der Statuszeile im unteren Bereich wird angezeigt, dass die Anwendung nun auf eine eingehende Verbindung wartet oder versucht, eine Verbindung aufzubauen ("Warte auf Verbindung oder verbinde - Rolle wird automatisch bestimmt").

### Bild 3: Erfolgreicher Verbindungsaufbau
Beide Teilnehmer haben die Anwendung gestartet und ihre Namen eingegeben. Die grafische Aufteilung der Kommandozeilen-Oberfläche ist nun gut erkennbar: Ganz unten befindet sich das Eingabefeld für neue Nachrichten, markiert durch ein ">". Direkt darüber wird der aktuelle Verbindungsstatus angezeigt (links "Verbunden als Server", rechts "Verbunden als Client"). Der große Bereich darüber ist für den Chatverlauf, welcher zu diesem Zeitpunkt noch leer ist.

### Bild 4: Aktiver Chatverlauf
PersonA und PersonB haben Nachrichten ausgetauscht. Im Chatverlauf ist klar sichtbar, welche Person welche Nachricht gesendet hat. Jede Nachricht ist mit einem genauen Zeitstempel in eckigen Klammern versehen.

### Bild 5: Verbindungsabbruch
Die Verbindung zwischen den beiden Peers wurde unterbrochen, da bei PersonB die Ethernet-Verbindung getrennt wurde. Im linken Fenster wird ein Timeout angezeigt ("Verbindung zu Peer unterbrochen (ACK_TIMEOUT)"), während im rechten Fenster versucht wird, die Verbindung wiederherzustellen ("Race to Connect..."). Die Anwendung wartet aktiv auf einen Wiederaufbau.

### Bild 6: Wiederherstellung und asynchrone Nachrichtenübermittlung
Die Netzwerkverbindung wurde erfolgreich wiederhergestellt. PersonB hat während der Verbindungsunterbrechung eine Nachricht ("Test") in das Eingabefeld abgesetzt, PersonA eine Nachricht ("TTest"). Das System hat diese Eingabe verarbeitet und die Nachricht direkt nach dem erfolgreichen Wiederaufbau der Verbindung automatisch an PersonB bzw. PersonA nachgesendet, wo sie korrekt im Chatverlauf auftaucht.