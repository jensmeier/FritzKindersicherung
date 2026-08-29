FRITZ!Box Kindersicherung – BUILD15

Basis: BUILD9 (stabile Hauptkachel + Onlinezeit Kinder).

BUILD11:
- Keine separate Elternansicht / keine zusätzliche Eltern-Kachel.
- Hauptinstanz bleibt SetVisualizationType(1), passend zum vorhandenen Symcon-9.0-Stand.
- Nach Klick auf OK bei der PIN fordert die HTML-Kachel Browser-/WebView-Vollbild an.
  Dadurch vergrößert sich dieselbe PIN-Kachel nach erfolgreicher PIN auf die gesamte Anzeige.
- Bei falscher PIN bzw. beim Sperren/Timeout wird Browser-Vollbild wieder beendet.
- In der Vollansicht wird automatisch das vorhandene Großlayout mit Gruppen, Geräten, Profilen,
  Sperren/Freigeben, +45 min und Ticketcodes verwendet.
- Neuer Pfeil ↙ in der freigeschalteten Vollansicht beendet nur das Vollbild; die PIN-Sitzung bleibt
  bis zum normalen Timeout oder bis zum Schloss-Button gültig.
- Fallback: Falls Browser/App die Fullscreen-API nicht erlaubt, bleibt die Steuerung in der 2x2-Kachel
  und zeigt einen Hinweis.
- Onlinezeit Kinder aus BUILD9 bleibt unverändert enthalten.

Hintergrund:
Der installierte Symcon-9.0-Kernel vom 15.06.2026 unterstützt die HTML-SDK-Vollbilddarstellung
noch nicht nativ. BUILD11 nutzt deshalb bewusst nicht SetVisualizationType(2).


BUILD12:
- Fully-Kiosk/Symcon-9.0-Workaround: Nach erfolgreicher PIN kann automatisch auf eine separate große Kachel-Visualisierung gewechselt werden.
- Rückkehr/Sperren führt zurück zur vorherigen Visualisierung.
- Keine zusätzliche Eltern-Modulinstanz nötig; die zweite Visualisierung enthält nur einen Link auf dieselbe Kindersicherungs-Instanz.

BUILD13
- Automatik-Assistent: erzeugt/konfiguriert nach Möglichkeit eine eigene Kachel-Visualisierung "FRITZ Eltern".
- Erzeugt die Startkategorie "FRITZ Eltern Ansicht" und einen Link auf die vorhandene Kindersicherungsinstanz.
- Trägt die Eltern-Visualisierung automatisch als Ziel nach korrekter PIN ein.
- Browserbasierter Wechsel: Fully Kiosk (Android Tablet), Chrome/Edge/Firefox unter Windows und Android-Browser.
- Android Symcon Visualization App ist für diesen URL-Wechsel nicht garantiert; dafür die Browser/Fully-Variante verwenden.


BUILD14
- Behebt die PIN-Schleife beim Wechsel in die separate Visualisierung "FRITZ Eltern".
- Nach korrekter PIN erzeugt das Modul einen zufälligen, nur 30 Sekunden gültigen Einmal-Schlüssel.
- Dieser Schlüssel wird beim Wechsel an die Eltern-Visualisierung übergeben und dort genau einmal verbraucht.
- Die neu geladene Elternansicht übernimmt dadurch die bestehende Freigabe automatisch; keine zweite PIN-Eingabe.
- Die Elternansicht erkennt sich zusätzlich über URL-Marker und öffnet sich nicht selbst erneut (kein Redirect-Loop).
- Rücksprung kennt die vorherige Visualisierungs-ID über die URL und benötigt dafür keinen Browser-Session-Speicher.
- Einmal-Schlüssel enthält weder PIN noch FRITZ!Box-Zugangsdaten und wird serverseitig nach Benutzung sofort gelöscht.

BUILD15:
- Behebt die PIN-Schleife beim Wechsel in die separate Visualisierung "FRITZ Eltern".
- Freigabe wird zusätzlich über einen zufälligen, kurzlebig serverseitig geprüften Browser-Schlüssel übernommen; die PIN selbst wird nicht gespeichert.
- Fallback: 15-Sekunden-Einmalfreigabe für den unmittelbar neu geladenen HTML-Client, falls Symcon/Fully URL-Parameter oder Browser-Speicher nicht weiterreicht.
- Rücksprung verbessert: ursprüngliche Visualisierung wird vor dem Wechsel gemerkt; zusätzlich wird ihre Visualisierungs-ID serverseitig an den Eltern-Client übergeben.
- Zurück-/Schloss-Schaltfläche in der Elternansicht sperrt alle Clients desselben Browsers und springt zur Ausgangsvisualisierung zurück.
