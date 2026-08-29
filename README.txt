FRITZ!Box Kindersicherung – BUILD11

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
