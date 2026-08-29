FRITZ!Box Kindersicherung – BUILD7

Neu/Fixes:
- Symcon 9 Vollbild-Unterstützung: SetVisualizationType(2)
  -> dieselbe geschützte HTML-Oberfläche wird jetzt auch in der maximierten Ansicht verwendet
- Migration auch für bestehende BUILD1-5-Instanzen über ApplyChanges()
- oberer Sicherheitsabstand zum Symcon-Kacheltitel, damit TEST-Badge/Buttons und Titel nicht mehr übereinander liegen
- 2x2-PIN-Feld nochmals auf die tatsächliche Tablet-Kachel angepasst
- Kompaktansicht priorisiert Gruppen mit echtem Restzeit-Budget (z. B. Paul) vor Gruppen ohne Zeitbudget
- Restzeit, Zusatz-Tickets, Gerätesperren, +45 Minuten und Ticketcodes aus BUILD5 bleiben erhalten

Hinweis:
Das Modul kann die Symcon-Kachel nicht selbstständig in Vollbild öffnen. Ab Symcon 9 kann aber der vorhandene ↗-Knopf nun die gleiche HTML-SDK-Oberfläche korrekt im Vollbild anzeigen.

Sicherheit:
Im Testmodus werden keine Sperren, Profilwechsel, +45-Minuten-Buchungen oder Ticketcodes ausgeführt.

BUILD7:
- Regression aus BUILD6 behoben: SetVisualizationType wieder auf 1.
- PIN-Kachel wird dadurch wieder direkt als HTML-SDK-Kachel dargestellt.
- Vollbild über den Symcon-Pfeil bleibt vorerst deaktiviert/ungeeignet; die kompakte 2x2-Kachel bleibt funktionsfähig.
