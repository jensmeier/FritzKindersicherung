FRITZ!Box Kindersicherung für IP-Symcon – BUILD1
=================================================

Ziel von BUILD1
---------------
- PIN-geschützte HTML-SDK-Kachel
- PIN wird serverseitig geprüft; keine FRITZ!Box-Zugangsdaten/PIN im Kachel-HTML
- jede Browser-/Tablet-Sitzung hat eine eigene Freigabe
- automatische Sperre (Standard 120 s)
- 3 falsche PINs => 30 s Eingabesperre
- Status lesen: Internet erlaubt/gesperrt, Profil-ID, Zeitverbrauch/Zeitbudget (wenn FRITZ!OS dies liefert)
- Geräte einzeln oder gruppenweise sperren/freigeben
- WICHTIG: Standard ist TESTMODUS = nur lesen. Im Testmodus verändert BUILD1 nichts an der FRITZ!Box.

Voraussetzungen
---------------
- IP-Symcon >= 8.1
- FRITZ!Box mit TR-064 und X_AVM-DE_HostFilter
- FRITZ!Box-Benutzer mit passenden App-/Einstellungsrechten
- Symcon muss die FRITZ!Box im Heimnetz erreichen können

Einrichtung
-----------
1. Modul wie gewohnt in IP-Symcon einbinden.
2. Instanz "FRITZ!Box Kindersicherung" anlegen.
3. Host z. B. fritz.box, Benutzer und Kennwort eintragen.
4. Eigenen 4- bis 8-stelligen PIN setzen. Standard-PIN 1234 unbedingt ändern.
5. Bei den Geräten die IPv4-Adressen eintragen.
   Empfehlung: In der FRITZ!Box für diese Geräte "Diesem Netzwerkgerät immer die gleiche IPv4-Adresse zuweisen" aktivieren.
6. "Verbindung / TR-064 testen" ausführen.
7. Kachel in die Kachelvisualisierung legen und PIN testen.
8. Erst wenn Status korrekt gelesen wird: Testmodus deaktivieren.
9. Danach zuerst an EINEM Testgerät Sperren/Freigeben prüfen.

Sicherheitsprinzip
------------------
Die Kachel selbst besitzt eine zusätzliche PIN-Sperre. Die Freischaltung wird nicht global gespeichert,
sondern je Browser-/Tablet-Sitzung mit einer zufälligen Client-ID. Jeder Steuerbefehl wird im Modul nochmals
serverseitig geprüft. Nach Ablauf der Freigabezeit werden Steuerbefehle abgewiesen.

Hinweis zu "Freigeben"
-----------------------
"Freigeben" entfernt die zusätzliche Disallow-Sperre der FRITZ!Box. Ein bestehendes Zugangsprofil kann das
Internet trotzdem weiterhin sperren, z. B. wegen Zeitplan oder aufgebrauchtem Zeitbudget. Das ist von AVM so vorgesehen.

Geplant für BUILD2
------------------
- FRITZ!Box-Zugangsprofile mit Namen statt nur Profil-ID anzeigen
- Profilwechsel direkt aus der Kachel
- Zusatzzeit/Ticket-Funktion passend zur tatsächlich angebotenen FRITZ!OS-API
- optional automatische Geräteerkennung statt manueller IP-Eingabe
- optische Anpassung für das konkrete 10-Zoll-Tablet
