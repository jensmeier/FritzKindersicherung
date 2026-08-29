<?php

declare(strict_types=1);

class FritzKindersicherung extends IPSModuleStrict
{
    private const HOSTFILTER_SERVICE_FRAGMENT = 'X_AVM-DE_HostFilter';
    private const HOSTS_SERVICE_FRAGMENT = ':Hosts:';
    private const HOST_INVENTORY_CACHE_SECONDS = 300;
    private const FILTER_PROFILE_CACHE_SECONDS = 900;

    public function Create(): void
    {
        parent::Create();

        $this->SetVisualizationType(1);

        $this->RegisterPropertyString('Host', 'fritz.box');
        $this->RegisterPropertyString('User', '');
        $this->RegisterPropertyString('Password', '');
        $this->RegisterPropertyBoolean('PreferHTTPS', true);
        $this->RegisterPropertyString('TilePin', '1234');
        $this->RegisterPropertyInteger('UnlockSeconds', 120);
        $this->RegisterPropertyBoolean('ReadOnly', true);
        $this->RegisterPropertyInteger('RefreshSeconds', 60);
        $this->RegisterPropertyString('Devices', '[]');
        // BUILD12: Optionale eigene Kachel-Visualisierung als große Elternansicht.
        $this->RegisterPropertyInteger('ParentVisualizationID', 0);
        $this->RegisterPropertyBoolean('AutoOpenParentVisualization', true);

        // BUILD9: Status für Zusatzanzeigen wird ausschließlich im Modul-Buffer gehalten.
        // Dadurch entsteht keine schreibgeschützte Variable und keine Warnung beim Aktualisieren.

        $this->RegisterTimer('RefreshTimer', 0, 'FKS_Refresh($_IPS["TARGET"]);');
    }

    public function ApplyChanges(): void
    {
        parent::ApplyChanges();

        // BUILD7: Zurück auf den stabilen HTML-SDK-Kachelmodus.
        // Typ 2 führte auf dem Zielsystem zu einer leeren Darstellung und ersetzte die PIN-Kachel durch die Listenansicht.
        // Typ 1 stellt die funktionierende PIN-geschützte Kachel wieder her.
        $this->SetVisualizationType(1);

        $refresh = max(15, $this->ReadPropertyInteger('RefreshSeconds'));
        $this->SetTimerInterval('RefreshTimer', $refresh * 1000);
        $this->SetSummary($this->ReadPropertyBoolean('ReadOnly') ? 'TEST · PIN geschützt' : 'AKTIV · PIN geschützt');

        // Alte Anmeldungen und Service-Cache bei Konfigurationsänderungen verwerfen.
        $this->SetBuffer('AuthClients', '{}');
        $this->SetBuffer('FailedClients', '{}');
        $this->SetBuffer('HostFilterService', '');
        $this->SetBuffer('HostsService', '');
        $this->SetBuffer('HostInventory', '');
        $this->SetBuffer('HostInventoryTs', '0');
        $this->SetBuffer('FilterProfiles', '');
        $this->SetBuffer('FilterProfilesTs', '0');
        $this->SetBuffer('LastPayload', '');
    }

    public function GetVisualizationTile(): string
    {
        return (string) file_get_contents(__DIR__ . '/module.html');
    }

    /**
     * Liefert den zuletzt ermittelten Status für reine Anzeige-Module.
     * Enthält bewusst keine FRITZ!Box-Zugangsdaten und keine PIN.
     */
    public function GetPublicStatus(): string
    {
        // BUILD9: Nur noch Buffer verwenden. Die in BUILD8 angelegte versteckte
        // PublicStatus-Variable war auf dem Zielsystem schreibgeschützt.
        $cached = $this->GetBuffer('LastPayload');
        if ($cached !== '') {
            return $cached;
        }

        try {
            $payload = $this->BuildStatusPayload('Status für Zusatzanzeige geladen ' . date('H:i:s'));
            return json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        } catch (Throwable $e) {
            return json_encode([
                'readOnly' => true,
                'devices' => [],
                'issuedTickets' => [],
                'message' => 'Noch keine Daten: ' . $e->getMessage()
            ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        }
    }

    public function RequestAction(string $Ident, mixed $Value): void
    {
        if ($Ident !== 'command') {
            throw new Exception('Unbekannte Aktion');
        }

        $cmd = json_decode((string) $Value, true);
        if (!is_array($cmd)) {
            return;
        }

        $clientId = preg_replace('/[^a-zA-Z0-9\-_.]/', '', (string) ($cmd['clientId'] ?? '')) ?? '';
        if ($clientId === '' || strlen($clientId) > 100) {
            return;
        }

        $op = (string) ($cmd['op'] ?? '');
        $this->CleanupAuthClients();

        switch ($op) {
            case 'hello':
                $handoffToken = strtolower(trim((string) ($cmd['handoffToken'] ?? '')));
                $parentVisualizationId = (int) ($cmd['parentVisualizationId'] ?? 0);
                if ($handoffToken !== '' && $this->ConsumeParentHandoff($handoffToken, $clientId, $parentVisualizationId)) {
                    $this->SendStatusToClient($clientId, 'Elternansicht automatisch freigeschaltet.');
                } elseif ($this->IsAuthorized($clientId)) {
                    $this->SendStatusToClient($clientId, '');
                } else {
                    $this->SendToTile(['kind' => 'locked', 'target' => $clientId]);
                }
                return;

            case 'unlock':
                $this->HandleUnlock($clientId, (string) ($cmd['pin'] ?? ''));
                return;

            case 'lock':
                $this->RemoveAuthorization($clientId);
                $this->SendToTile(['kind' => 'locked', 'target' => $clientId, 'message' => 'Gesperrt.']);
                return;
        }

        if (!$this->IsAuthorized($clientId)) {
            $this->SendToTile(['kind' => 'locked', 'target' => $clientId, 'message' => 'PIN-Sitzung abgelaufen.']);
            return;
        }

        $this->TouchAuthorization($clientId);

        if ($op === 'refresh') {
            $this->SendStatusToClient($clientId, 'Aktualisiert ' . date('H:i:s'));
            return;
        }

        if ($op === 'set_disallow') {
            $ip = (string) ($cmd['ip'] ?? '');
            $disallow = (bool) ($cmd['disallow'] ?? false);
            $this->HandleSetDisallow($clientId, $ip, $disallow);
            return;
        }

        if ($op === 'set_profile') {
            $ip = (string) ($cmd['ip'] ?? '');
            $profileId = (string) ($cmd['profileId'] ?? '');
            $this->HandleSetProfile($clientId, $ip, $profileId);
            return;
        }

        if ($op === 'group_disallow') {
            $group = (string) ($cmd['group'] ?? '');
            $disallow = (bool) ($cmd['disallow'] ?? false);
            $this->HandleGroupDisallow($clientId, $group, $disallow);
            return;
        }

        if ($op === 'group_profile') {
            $group = (string) ($cmd['group'] ?? '');
            $profileId = (string) ($cmd['profileId'] ?? '');
            $this->HandleGroupProfile($clientId, $group, $profileId);
            return;
        }

        if ($op === 'add_ticket_time') {
            $ip = (string) ($cmd['ip'] ?? '');
            $this->HandleAddTicketTime($clientId, $ip);
            return;
        }

        if ($op === 'mark_ticket') {
            $this->HandleMarkTicket($clientId);
            return;
        }
    }

    /**
     * BUILD13: Richtet eine separate Kachel-Visualisierung als große Elternansicht weitgehend automatisch ein.
     * Die Visualisierung erhält eine eigene Startkategorie mit einem Link auf diese Instanz.
     * Anschließend wird sie als Ziel für den automatischen Wechsel nach korrekter PIN hinterlegt.
     */
    public function SetupParentVisualization(): string
    {
        try {
            $moduleId = $this->FindTileVisualizationModuleId();
            if ($moduleId === '') {
                throw new Exception('Modul "Kachel Visualisierung" wurde nicht gefunden.');
            }

            $categoryId = $this->FindOrCreateParentViewCategory();
            $this->EnsureParentViewLink($categoryId);

            $visId = $this->FindParentVisualizationByName($moduleId);
            $created = false;
            if ($visId === 0) {
                $visId = IPS_CreateInstance($moduleId);
                IPS_SetName($visId, 'FRITZ Eltern');
                $created = true;
            }

            $this->ConfigureTileVisualizationStartCategory($visId, $categoryId, $moduleId);

            IPS_SetProperty($this->InstanceID, 'ParentVisualizationID', $visId);
            IPS_SetProperty($this->InstanceID, 'AutoOpenParentVisualization', true);
            IPS_ApplyChanges($this->InstanceID);

            return sprintf(
                "OK – Eltern-Visualisierung %s (ID %d) ist eingerichtet. Ziel-URL im Browser: /#%d\n" .
                "Nach korrekter PIN versucht die 2x2-Kachel automatisch dorthin zu wechseln. " .
                "Zum Testen am Windows-PC die normale Symcon-Adresse öffnen und am Ende #%-d verwenden.",
                $created ? 'neu erstellt' : 'gefunden/aktualisiert',
                $visId,
                $visId,
                $visId
            );
        } catch (Throwable $e) {
            $this->SendDebug('SetupParentVisualization', $e->getMessage(), 0);
            return 'Fehler beim automatischen Einrichten: ' . $e->getMessage();
        }
    }

    public function Refresh(): void
    {
        try {
            $payload = $this->BuildStatusPayload('Automatisch aktualisiert ' . date('H:i:s'));
            $this->SetBuffer('LastPayload', json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));

            // Nur offene, bereits per PIN freigeschaltete Kacheln werten den Broadcast aus.
            if ($this->HasAuthorizedClients()) {
                $this->SendToTile([
                    'kind' => 'status',
                    'target' => '*',
                    'payload' => $payload
                ]);
            }
        } catch (Throwable $e) {
            $this->SendDebug('Refresh', $e->getMessage(), 0);
        }
    }

    public function DiscoverDevices(): string
    {
        try {
            $inventory = $this->GetHostInventory(true, true);
            $existing = $this->GetRawDeviceRows();
            $usedExisting = [];
            $rows = [];
            $online = 0;

            foreach ($inventory as $host) {
                $matchIndex = $this->FindMatchingDeviceRow($existing, $host, $usedExisting);
                $old = $matchIndex !== null ? $existing[$matchIndex] : [];
                if ($matchIndex !== null) {
                    $usedExisting[$matchIndex] = true;
                }

                if ((bool) ($host['active'] ?? false)) {
                    $online++;
                }

                $foundName = trim((string) ($host['friendlyName'] ?? ''));
                if ($foundName === '') {
                    $foundName = trim((string) ($host['hostName'] ?? ''));
                }
                if ($foundName === '') {
                    $foundName = (string) ($host['ip'] ?? 'Unbekanntes Gerät');
                }

                $oldName = trim((string) ($old['Name'] ?? ''));
                $profileName = trim((string) ($host['profileName'] ?? ''));
                if ($profileName === '') {
                    $profileName = trim((string) ($host['profileId'] ?? ''));
                }

                $rows[] = [
                    'Enabled'   => $matchIndex !== null ? (bool) ($old['Enabled'] ?? false) : false,
                    'Group'     => $matchIndex !== null ? trim((string) ($old['Group'] ?? '')) : '',
                    'Name'      => $oldName !== '' ? $oldName : $foundName,
                    'IP'        => (string) ($host['ip'] ?? ''),
                    'MAC'       => (string) ($host['mac'] ?? ''),
                    'Status'    => (bool) ($host['active'] ?? false) ? 'online' : 'offline',
                    'Interface' => (string) ($host['interface'] ?? ''),
                    'Profile'   => $profileName
                ];
            }

            // Bereits konfigurierte Geräte nicht verlieren, wenn sie bei einer Suche gerade fehlen.
            foreach ($existing as $idx => $old) {
                if (isset($usedExisting[$idx])) {
                    continue;
                }
                $ip = trim((string) ($old['IP'] ?? ''));
                $mac = $this->NormalizeMac((string) ($old['MAC'] ?? ''));
                if ($ip === '' && $mac === '') {
                    continue; // alte BUILD1/2-Platzhalter verwerfen
                }
                $rows[] = [
                    'Enabled'   => (bool) ($old['Enabled'] ?? false),
                    'Group'     => trim((string) ($old['Group'] ?? '')),
                    'Name'      => trim((string) ($old['Name'] ?? 'Gerät')) ?: 'Gerät',
                    'IP'        => $ip,
                    'MAC'       => $mac,
                    'Status'    => 'nicht gefunden',
                    'Interface' => trim((string) ($old['Interface'] ?? '')),
                    'Profile'   => trim((string) ($old['Profile'] ?? ''))
                ];
            }

            usort($rows, static function (array $a, array $b): int {
                $aOnline = ($a['Status'] ?? '') === 'online' ? 0 : 1;
                $bOnline = ($b['Status'] ?? '') === 'online' ? 0 : 1;
                if ($aOnline !== $bOnline) {
                    return $aOnline <=> $bOnline;
                }
                return strnatcasecmp((string) ($a['Name'] ?? ''), (string) ($b['Name'] ?? ''));
            });

            $this->UpdateFormField('Devices', 'values', json_encode($rows, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));

            return count($rows) . ' Geräte gefunden/übernommen, davon ' . $online . ' aktuell online. '
                . 'Neue Geräte sind aus Sicherheitsgründen deaktiviert. Gewünschte Geräte anhaken, Gruppe (z. B. Paul/Tom) eintragen und anschließend Übernehmen drücken.';
        } catch (Throwable $e) {
            return 'FEHLER bei der Gerätesuche: ' . $e->getMessage();
        }
    }

    public function TestConnection(): string
    {
        try {
            $service = $this->DiscoverHostFilterService(true);
            $devices = $this->GetResolvedConfiguredDevices();
            $sample = null;
            foreach ($devices as $device) {
                if ($device['ip'] !== '') {
                    $sample = $device;
                    break;
                }
            }

            if ($sample !== null) {
                $result = $this->SoapAction($service, 'GetWANAccessByIP', ['NewIPv4Address' => $sample['ip']]);
                $wan = (string) ($result['NewWANAccess'] ?? 'unbekannt');
                return 'OK – HostFilter gefunden. Testgerät ' . $sample['name'] . ' (' . $sample['ip'] . '): ' . $wan;
            }

            return 'OK – TR-064 HostFilter gefunden. Jetzt "Geräte automatisch suchen/importieren" verwenden.';
        } catch (Throwable $e) {
            return 'FEHLER: ' . $e->getMessage();
        }
    }

    private function HandleUnlock(string $clientId, string $pin): void
    {
        $failed = $this->GetJsonBuffer('FailedClients');
        $now = time();
        $entry = is_array($failed[$clientId] ?? null) ? $failed[$clientId] : ['count' => 0, 'until' => 0];

        if ((int) ($entry['until'] ?? 0) > $now) {
            $wait = (int) $entry['until'] - $now;
            $this->SendToTile([
                'kind' => 'auth', 'target' => $clientId, 'ok' => false,
                'message' => 'Zu viele Fehlversuche. Noch ' . $wait . ' s gesperrt.'
            ]);
            return;
        }

        $configuredPin = $this->ReadPropertyString('TilePin');
        $validFormat = (bool) preg_match('/^\d{4,8}$/', $configuredPin);
        $ok = $validFormat && hash_equals(hash('sha256', $configuredPin), hash('sha256', $pin));

        if (!$ok) {
            $count = (int) ($entry['count'] ?? 0) + 1;
            $until = $count >= 3 ? $now + 30 : 0;
            if ($count >= 3) {
                $count = 0;
            }
            $failed[$clientId] = ['count' => $count, 'until' => $until];
            $this->SetJsonBuffer('FailedClients', $failed);
            $this->SendToTile([
                'kind' => 'auth', 'target' => $clientId, 'ok' => false,
                'message' => $until > 0 ? '3 falsche PINs – 30 s gesperrt.' : 'PIN falsch.'
            ]);
            return;
        }

        unset($failed[$clientId]);
        $this->SetJsonBuffer('FailedClients', $failed);
        $expires = $this->Authorize($clientId);

        try {
            $payload = $this->BuildStatusPayload('PIN akzeptiert.');
        } catch (Throwable $e) {
            $payload = [
                'readOnly' => $this->ReadPropertyBoolean('ReadOnly'),
                'devices' => [],
                'message' => 'PIN OK, FRITZ!Box noch nicht erreichbar: ' . $e->getMessage()
            ];
        }

        $parentVisualizationId = $this->ReadPropertyInteger('ParentVisualizationID');
        $handoffToken = '';
        if ($this->ReadPropertyBoolean('AutoOpenParentVisualization') && $parentVisualizationId > 0) {
            $handoffToken = $this->CreateParentHandoff($parentVisualizationId);
        }

        $this->SendToTile([
            'kind' => 'auth', 'target' => $clientId, 'ok' => true,
            'expires' => $expires, 'payload' => $payload,
            'handoffToken' => $handoffToken
        ]);
    }

    private function HandleSetDisallow(string $clientId, string $ip, bool $disallow): void
    {
        if ($this->ReadPropertyBoolean('ReadOnly')) {
            $this->SendStatusToClient($clientId, 'TESTMODUS: Es wurde nichts an der FRITZ!Box geändert.');
            return;
        }
        if (!$this->IsConfiguredIP($ip)) {
            $this->SendStatusToClient($clientId, 'Abgelehnt: IP ist nicht in der Modulkonfiguration freigegeben.');
            return;
        }

        try {
            $service = $this->DiscoverHostFilterService(false);
            $this->SoapAction($service, 'DisallowWANAccessByIP', [
                'NewIPv4Address' => $ip,
                'NewDisallow' => $disallow ? 1 : 0
            ]);
            $this->SendStatusToClient($clientId, $disallow ? 'Sperrbefehl gesendet.' : 'Freigabebefehl gesendet. Profilregeln gelten weiterhin.');
        } catch (Throwable $e) {
            $this->SendStatusToClient($clientId, 'FRITZ!Box Fehler: ' . $e->getMessage());
        }
    }

    private function HandleGroupDisallow(string $clientId, string $group, bool $disallow): void
    {
        if ($this->ReadPropertyBoolean('ReadOnly')) {
            $this->SendStatusToClient($clientId, 'TESTMODUS: Gruppenbefehl wurde nicht ausgeführt.');
            return;
        }

        $targets = array_values(array_filter($this->GetResolvedConfiguredDevices(), static fn(array $d): bool => $d['group'] === $group && $d['ip'] !== ''));
        if ($targets === []) {
            $this->SendStatusToClient($clientId, 'Keine Geräte in dieser Gruppe gefunden.');
            return;
        }

        $ok = 0;
        $errors = [];
        try {
            $service = $this->DiscoverHostFilterService(false);
            foreach ($targets as $device) {
                try {
                    $this->SoapAction($service, 'DisallowWANAccessByIP', [
                        'NewIPv4Address' => $device['ip'],
                        'NewDisallow' => $disallow ? 1 : 0
                    ]);
                    $ok++;
                } catch (Throwable $e) {
                    $errors[] = $device['name'];
                }
            }
        } catch (Throwable $e) {
            $errors[] = $e->getMessage();
        }

        $msg = ($disallow ? 'Sperren' : 'Freigeben') . ': ' . $ok . '/' . count($targets) . ' Befehle gesendet.';
        if ($errors !== []) {
            $msg .= ' Fehler: ' . implode(', ', $errors);
        }
        $this->SendStatusToClient($clientId, $msg);
    }

    private function HandleSetProfile(string $clientId, string $ip, string $profileId): void
    {
        if ($this->ReadPropertyBoolean('ReadOnly')) {
            $this->SendStatusToClient($clientId, 'TESTMODUS: Profil wurde nicht geändert.');
            return;
        }
        if (!$this->IsConfiguredIP($ip)) {
            $this->SendStatusToClient($clientId, 'Abgelehnt: IP ist nicht in der Modulkonfiguration freigegeben.');
            return;
        }

        try {
            $profiles = $this->GetFilterProfileNames(false);
            if ($profileId === '' || !array_key_exists($profileId, $profiles)) {
                $this->SendStatusToClient($clientId, 'Abgelehnt: Unbekanntes FRITZ!-Zugangsprofil.');
                return;
            }
            $service = $this->DiscoverHostFilterService(false);
            $this->SoapAction($service, 'AddHostEntryToFilterProfile', [
                'NewIPv4Address' => $ip,
                'NewFilterProfileID' => $profileId
            ]);
            $this->SetBuffer('HostInventoryTs', '0');
            $this->SendStatusToClient($clientId, 'Profil geändert auf „' . $profiles[$profileId] . '“.');
        } catch (Throwable $e) {
            $this->SendStatusToClient($clientId, 'FRITZ!Box Fehler beim Profilwechsel: ' . $e->getMessage());
        }
    }

    private function HandleGroupProfile(string $clientId, string $group, string $profileId): void
    {
        if ($this->ReadPropertyBoolean('ReadOnly')) {
            $this->SendStatusToClient($clientId, 'TESTMODUS: Gruppenprofil wurde nicht geändert.');
            return;
        }

        $targets = array_values(array_filter(
            $this->GetResolvedConfiguredDevices(),
            static fn(array $d): bool => $d['group'] === $group && $d['ip'] !== ''
        ));
        if ($targets === []) {
            $this->SendStatusToClient($clientId, 'Keine Geräte in dieser Gruppe gefunden.');
            return;
        }

        try {
            $profiles = $this->GetFilterProfileNames(false);
            if ($profileId === '' || !array_key_exists($profileId, $profiles)) {
                $this->SendStatusToClient($clientId, 'Abgelehnt: Unbekanntes FRITZ!-Zugangsprofil.');
                return;
            }

            $service = $this->DiscoverHostFilterService(false);
            $ok = 0;
            $errors = [];
            foreach ($targets as $device) {
                try {
                    $this->SoapAction($service, 'AddHostEntryToFilterProfile', [
                        'NewIPv4Address' => $device['ip'],
                        'NewFilterProfileID' => $profileId
                    ]);
                    $ok++;
                } catch (Throwable $e) {
                    $errors[] = $device['name'];
                }
            }
            $this->SetBuffer('HostInventoryTs', '0');
            $msg = 'Profil „' . $profiles[$profileId] . '“: ' . $ok . '/' . count($targets) . ' Geräte geändert.';
            if ($errors !== []) {
                $msg .= ' Fehler: ' . implode(', ', $errors);
            }
            $this->SendStatusToClient($clientId, $msg);
        } catch (Throwable $e) {
            $this->SendStatusToClient($clientId, 'FRITZ!Box Fehler beim Gruppenprofil: ' . $e->getMessage());
        }
    }

    private function HandleAddTicketTime(string $clientId, string $ip): void
    {
        if ($this->ReadPropertyBoolean('ReadOnly')) {
            $this->SendStatusToClient($clientId, 'TESTMODUS: Es wurde keine Zusatzzeit vergeben.');
            return;
        }
        if (!$this->IsConfiguredIP($ip)) {
            $this->SendStatusToClient($clientId, 'Abgelehnt: IP ist nicht in der Modulkonfiguration freigegeben.');
            return;
        }

        try {
            $service = $this->DiscoverHostFilterService(false);
            $result = $this->SoapAction($service, 'AddTicketTimeToHostEntryByIP', [
                'NewIPv4Address' => $ip
            ]);
            $ticketValid = (int) ($result['NewTicketValid'] ?? 0);
            $tickets = (int) ($result['NewTicketsInAdvance'] ?? 0);
            $msg = '+45 Minuten vergeben.';
            if ($ticketValid > 0 || $tickets > 0) {
                $msg .= ' Zusatz-Tickets: ' . $tickets;
                if ($ticketValid > 0) {
                    $msg .= ' · aktuelle Ticketzeit ' . $ticketValid . ' min';
                }
            }
            $this->SendStatusToClient($clientId, $msg);
        } catch (Throwable $e) {
            $this->SendStatusToClient($clientId, 'FRITZ!Box Fehler bei +45 Minuten: ' . $e->getMessage());
        }
    }

    private function HandleMarkTicket(string $clientId): void
    {
        if ($this->ReadPropertyBoolean('ReadOnly')) {
            $this->SendStatusToClient($clientId, 'TESTMODUS: Es wurde kein Ticketcode markiert.');
            return;
        }

        try {
            $service = $this->DiscoverHostFilterService(false);
            $result = $this->SoapAction($service, 'MarkTicket', []);
            $ticket = trim((string) ($result['NewTicketID'] ?? ''));
            if (!preg_match('/^\d{6}$/', $ticket)) {
                throw new Exception('FRITZ!Box hat keinen gültigen 6-stelligen Ticketcode geliefert.');
            }

            $issued = $this->GetJsonBuffer('IssuedTickets');
            $issued[$ticket] = ['created' => time(), 'status' => 'marked'];
            if (count($issued) > 12) {
                uasort($issued, static fn(array $a, array $b): int => ((int) ($a['created'] ?? 0)) <=> ((int) ($b['created'] ?? 0)));
                while (count($issued) > 12) {
                    array_shift($issued);
                }
            }
            $this->SetJsonBuffer('IssuedTickets', $issued);
            $this->SendStatusToClient($clientId, 'Ticketcode ' . $ticket . ' bereit. Er kann einmalig für 45 Minuten eingelöst werden.');
        } catch (Throwable $e) {
            $msg = $e->getMessage();
            if (str_contains($msg, '714')) {
                $msg = 'Kein neuer unmarkierter Ticketcode verfügbar. Bereits erzeugte Codes in der FRITZ!Box bleiben gültig.';
            }
            $this->SendStatusToClient($clientId, 'Ticket: ' . $msg);
        }
    }

    private function GetIssuedTicketStatus(): array
    {
        $issued = $this->GetJsonBuffer('IssuedTickets');
        if ($issued === []) {
            return [];
        }

        try {
            $service = $this->DiscoverHostFilterService(false);
            foreach ($issued as $ticket => &$entry) {
                if (!preg_match('/^\d{6}$/', (string) $ticket)) {
                    unset($issued[$ticket]);
                    continue;
                }
                try {
                    $status = $this->SoapAction($service, 'GetTicketIDStatus', ['NewTicketID' => (string) $ticket]);
                    $entry['status'] = (string) ($status['NewTicketIDStatus'] ?? ($entry['status'] ?? 'unknown'));
                } catch (Throwable $ignored) {
                    $entry['status'] = (string) ($entry['status'] ?? 'unknown');
                }
            }
            unset($entry);
            $this->SetJsonBuffer('IssuedTickets', $issued);
        } catch (Throwable $ignored) {
        }

        $rows = [];
        foreach ($issued as $ticket => $entry) {
            $rows[] = [
                'id' => (string) $ticket,
                'status' => (string) ($entry['status'] ?? 'unknown'),
                'created' => (int) ($entry['created'] ?? 0)
            ];
        }
        usort($rows, static fn(array $a, array $b): int => $b['created'] <=> $a['created']);
        return $rows;
    }

    private function SendStatusToClient(string $clientId, string $message): void
    {
        $expires = $this->GetAuthorizationExpiry($clientId);
        try {
            $payload = $this->BuildStatusPayload($message);
        } catch (Throwable $e) {
            $payload = [
                'readOnly' => $this->ReadPropertyBoolean('ReadOnly'),
                'devices' => [],
                'message' => ($message !== '' ? $message . ' · ' : '') . 'Fehler: ' . $e->getMessage()
            ];
        }
        $this->SendToTile([
            'kind' => 'status', 'target' => $clientId, 'expires' => $expires, 'payload' => $payload
        ]);
    }

    private function FindTileVisualizationModuleId(): string
    {
        foreach (IPS_GetModuleList() as $moduleId) {
            try {
                $m = IPS_GetModule($moduleId);
            } catch (Throwable) {
                continue;
            }
            $name = strtolower((string) ($m['ModuleName'] ?? $m['ModuleNameDE'] ?? ''));
            if ($name === '') {
                $name = strtolower((string) ($m['ModuleName'] ?? ''));
            }
            if (str_contains($name, 'kachel') && str_contains($name, 'visual')) {
                return (string) $moduleId;
            }
            if (str_contains($name, 'tile') && str_contains($name, 'visual')) {
                return (string) $moduleId;
            }
        }
        return '';
    }

    private function FindOrCreateParentViewCategory(): int
    {
        foreach (IPS_GetChildrenIDs($this->InstanceID) as $id) {
            $obj = IPS_GetObject($id);
            if ((int) ($obj['ObjectType'] ?? -1) === 0 && IPS_GetName($id) === 'FRITZ Eltern Ansicht') {
                return $id;
            }
        }
        $id = IPS_CreateCategory();
        IPS_SetParent($id, $this->InstanceID);
        IPS_SetName($id, 'FRITZ Eltern Ansicht');
        IPS_SetPosition($id, 9990);
        return $id;
    }

    private function EnsureParentViewLink(int $categoryId): void
    {
        foreach (IPS_GetChildrenIDs($categoryId) as $id) {
            $obj = IPS_GetObject($id);
            if ((int) ($obj['ObjectType'] ?? -1) !== 6) {
                continue;
            }
            try {
                if (IPS_GetLink($id)['TargetID'] === $this->InstanceID) {
                    IPS_SetName($id, 'FRITZ!Box Kindersicherung');
                    return;
                }
            } catch (Throwable) {
            }
        }
        $link = IPS_CreateLink();
        IPS_SetParent($link, $categoryId);
        IPS_SetName($link, 'FRITZ!Box Kindersicherung');
        IPS_SetLinkTargetID($link, $this->InstanceID);
        IPS_SetPosition($link, 10);
    }

    private function FindParentVisualizationByName(string $moduleId): int
    {
        foreach (IPS_GetInstanceListByModuleID($moduleId) as $id) {
            if (IPS_GetName($id) === 'FRITZ Eltern') {
                return (int) $id;
            }
        }
        return 0;
    }

    private function ConfigureTileVisualizationStartCategory(int $visId, int $categoryId, string $moduleId): void
    {
        $newConfig = json_decode(IPS_GetConfiguration($visId), true);
        if (!is_array($newConfig)) {
            $newConfig = [];
        }

        $candidatePath = $this->FindStartCategoryPath($newConfig, false);
        if ($candidatePath === []) {
            foreach (IPS_GetInstanceListByModuleID($moduleId) as $otherId) {
                if ((int) $otherId === $visId) {
                    continue;
                }
                $cfg = json_decode(IPS_GetConfiguration((int) $otherId), true);
                if (!is_array($cfg)) {
                    continue;
                }
                $candidatePath = $this->FindStartCategoryPath($cfg, true);
                if ($candidatePath !== []) {
                    break;
                }
            }
        }

        if ($candidatePath === []) {
            throw new Exception('Startkategorie der Kachel-Visualisierung konnte nicht automatisch erkannt werden. Die Visualisierung "FRITZ Eltern" wurde angelegt; bitte dort einmal manuell als Startkategorie "FRITZ Eltern Ansicht" wählen.');
        }

        $this->SetConfigValueByPath($newConfig, $candidatePath, $categoryId);
        IPS_SetConfiguration($visId, json_encode($newConfig, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
        IPS_ApplyChanges($visId);
    }

    /** @return array<int, string|int> */
    private function FindStartCategoryPath(array $config, bool $preferExistingCategory): array
    {
        $bestPath = [];
        $bestScore = -1;
        $walk = function (mixed $value, array $path) use (&$walk, &$bestPath, &$bestScore, $preferExistingCategory): void {
            if (is_array($value)) {
                foreach ($value as $k => $v) {
                    $walk($v, array_merge($path, [$k]));
                }
                return;
            }
            if (!is_int($value) && !(is_string($value) && ctype_digit($value))) {
                return;
            }
            $num = (int) $value;
            $key = strtolower((string) end($path));
            $score = 0;
            if (str_contains($key, 'start')) $score += 12;
            if (str_contains($key, 'root')) $score += 11;
            if (str_contains($key, 'category')) $score += 10;
            if (str_contains($key, 'base')) $score += 7;
            if (str_contains($key, 'object')) $score += 3;
            if (str_contains($key, 'page')) $score += 2;

            if ($num > 0 && IPS_ObjectExists($num)) {
                $obj = IPS_GetObject($num);
                if ((int) ($obj['ObjectType'] ?? -1) === 0) {
                    $score += 20;
                }
            } elseif ($preferExistingCategory) {
                $score -= 4;
            }

            if ($score > $bestScore && $score >= 8) {
                $bestScore = $score;
                $bestPath = $path;
            }
        };
        $walk($config, []);
        return $bestPath;
    }

    /** @param array<int, string|int> $path */
    private function SetConfigValueByPath(array &$config, array $path, mixed $value): void
    {
        $ref =& $config;
        foreach ($path as $i => $part) {
            if ($i === count($path) - 1) {
                $ref[$part] = $value;
                return;
            }
            if (!isset($ref[$part]) || !is_array($ref[$part])) {
                $ref[$part] = [];
            }
            $ref =& $ref[$part];
        }
    }

    private function BuildStatusPayload(string $message): array
    {
        $devices = $this->GetResolvedConfiguredDevices();
        $result = [];
        $profileNames = [];

        if ($devices !== []) {
            $service = $this->DiscoverHostFilterService(false);
            try {
                $profileNames = $this->GetFilterProfileNames(false);
            } catch (Throwable $ignored) {
            }
            foreach ($devices as $device) {
                if ($device['ip'] === '') {
                    continue;
                }

                $row = [
                    'group' => $device['group'],
                    'name' => $device['name'],
                    'ip' => $device['ip'],
                    'mac' => $device['mac'],
                    'wan' => 'error',
                    'disallow' => null,
                    'profile' => '',
                    'profileId' => '',
                    'timeUsed' => 0,
                    'timeMax' => 0,
                    'ticketsInAdvance' => 0,
                    'ticketValid' => 0,
                    'isTimeShared' => false,
                    'error' => ''
                ];

                try {
                    // Die neuere API liefert Profil und Zeitbudget in einem Aufruf.
                    $entry = $this->SoapAction($service, 'GetHostEntryByIP', ['NewIPv4Address' => $device['ip']]);
                    $row['wan'] = (string) ($entry['NewWANAccess'] ?? 'error');
                    $profileId = (string) ($entry['NewFilterProfileID'] ?? '');
                    $row['profileId'] = $profileId;
                    $row['profile'] = (string) ($profileNames[$profileId] ?? $profileId);
                    $row['timeUsed'] = (int) ($entry['NewTimeUsed'] ?? 0);
                    $row['timeMax'] = (int) ($entry['NewTimeMax'] ?? 0);
                    $row['ticketsInAdvance'] = (int) ($entry['NewTicketsInAdvance'] ?? 0);
                    $row['ticketValid'] = (int) ($entry['NewTicketValid'] ?? 0);
                    $row['isTimeShared'] = $this->ToBool($entry['NewIsTimeShared'] ?? false);

                    // Disallow-Flag separat lesen, falls verfügbar.
                    try {
                        $wan = $this->SoapAction($service, 'GetWANAccessByIP', ['NewIPv4Address' => $device['ip']]);
                        $row['wan'] = (string) ($wan['NewWANAccess'] ?? $row['wan']);
                        $row['disallow'] = isset($wan['NewDisallow']) ? ((string) $wan['NewDisallow'] === '1') : null;
                    } catch (Throwable $ignored) {
                    }
                } catch (Throwable $e) {
                    // Ältere FRITZ!OS-Version: wenigstens WAN-Status versuchen.
                    try {
                        $wan = $this->SoapAction($service, 'GetWANAccessByIP', ['NewIPv4Address' => $device['ip']]);
                        $row['wan'] = (string) ($wan['NewWANAccess'] ?? 'error');
                        $row['disallow'] = isset($wan['NewDisallow']) ? ((string) $wan['NewDisallow'] === '1') : null;
                    } catch (Throwable $fallback) {
                        $row['error'] = $this->ShortError($fallback->getMessage());
                    }
                }
                $result[] = $row;
            }
        }

        $profileList = [];
        foreach ($profileNames as $id => $name) {
            $profileList[] = ['id' => (string) $id, 'name' => (string) $name];
        }
        usort($profileList, static fn(array $a, array $b): int => strnatcasecmp($a['name'], $b['name']));

        $payload = [
            'readOnly' => $this->ReadPropertyBoolean('ReadOnly'),
            'devices' => $result,
            'profiles' => $profileList,
            'ticketTimeMinutes' => 45,
            'issuedTickets' => $this->GetIssuedTicketStatus(),
            'parentVisualizationId' => $this->ReadPropertyInteger('ParentVisualizationID'),
            'autoOpenParentVisualization' => $this->ReadPropertyBoolean('AutoOpenParentVisualization'),
            'message' => $message
        ];
        $json = json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        $this->SetBuffer('LastPayload', $json);
        return $payload;
    }

    private function DiscoverHostFilterService(bool $force): array
    {
        return $this->DiscoverService(self::HOSTFILTER_SERVICE_FRAGMENT, 'HostFilterService', $force);
    }

    private function DiscoverHostsService(bool $force): array
    {
        return $this->DiscoverService(self::HOSTS_SERVICE_FRAGMENT, 'HostsService', $force);
    }

    private function DiscoverService(string $fragment, string $bufferName, bool $force): array
    {
        if (!$force) {
            $cached = $this->GetBuffer($bufferName);
            if ($cached !== '') {
                $service = json_decode($cached, true);
                if (is_array($service) && isset($service['base'], $service['serviceType'], $service['controlURL'])) {
                    return $service;
                }
            }
        }

        $host = trim($this->ReadPropertyString('Host'));
        if ($host === '') {
            throw new Exception('FRITZ!Box Host/IP fehlt.');
        }
        $host = preg_replace('#^https?://#i', '', $host) ?? $host;
        $host = rtrim($host, '/');

        $https = 'https://' . $host . ':49443';
        $http = 'http://' . $host . ':49000';
        $bases = $this->ReadPropertyBoolean('PreferHTTPS') ? [$https, $http] : [$http, $https];
        $lastError = '';

        foreach ($bases as $base) {
            try {
                $xml = $this->HttpRequest($base . '/tr64desc.xml', 'GET', '', []);
                $dom = new DOMDocument();
                if (!@$dom->loadXML($xml)) {
                    throw new Exception('TR-064 Beschreibung ist kein gültiges XML.');
                }
                $xp = new DOMXPath($dom);
                $services = $xp->query('//*[local-name()="service"]');
                if ($services === false) {
                    continue;
                }
                foreach ($services as $node) {
                    $serviceType = $this->XpathChildText($xp, $node, 'serviceType');
                    if (stripos($serviceType, $fragment) === false) {
                        continue;
                    }
                    $controlURL = $this->XpathChildText($xp, $node, 'controlURL');
                    if ($controlURL === '') {
                        continue;
                    }
                    $service = [
                        'base' => $base,
                        'serviceType' => $serviceType,
                        'controlURL' => '/' . ltrim($controlURL, '/')
                    ];
                    $this->SetBuffer($bufferName, json_encode($service, JSON_UNESCAPED_SLASHES));
                    return $service;
                }
                throw new Exception($fragment . ' wurde in tr64desc.xml nicht gefunden.');
            } catch (Throwable $e) {
                $lastError = $e->getMessage();
            }
        }

        throw new Exception('TR-064 nicht erreichbar: ' . $lastError);
    }

    private function GetHostInventory(bool $force, bool $enrich): array
    {
        $cached = $this->GetBuffer('HostInventory');
        $cachedTs = (int) $this->GetBuffer('HostInventoryTs');
        if (!$force && $cached !== '' && (time() - $cachedTs) < self::HOST_INVENTORY_CACHE_SECONDS) {
            $value = json_decode($cached, true);
            if (is_array($value)) {
                return $value;
            }
        }

        $service = $this->DiscoverHostsService($force);
        $countResult = $this->SoapAction($service, 'GetHostNumberOfEntries', []);
        $count = max(0, min(512, (int) ($countResult['NewHostNumberOfEntries'] ?? 0)));
        $profileNames = [];
        if ($enrich) {
            try {
                $profileNames = $this->GetFilterProfileNames(false);
            } catch (Throwable $ignored) {
            }
        }

        $byKey = [];
        for ($i = 0; $i < $count; $i++) {
            try {
                $entry = $this->SoapAction($service, 'GetGenericHostEntry', ['NewIndex' => $i]);
            } catch (Throwable $e) {
                $this->SendDebug('HostImport', 'Index ' . $i . ': ' . $e->getMessage(), 0);
                continue;
            }

            $ip = trim((string) ($entry['NewIPAddress'] ?? ''));
            if ($ip === '' || filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
                continue; // HostFilter arbeitet mit IPv4
            }

            $mac = $this->NormalizeMac((string) ($entry['NewMACAddress'] ?? ''));
            $row = [
                'ip' => $ip,
                'mac' => $mac,
                'hostName' => trim((string) ($entry['NewHostName'] ?? '')),
                'friendlyName' => '',
                'active' => $this->ToBool($entry['NewActive'] ?? false),
                'interface' => trim((string) ($entry['NewInterfaceType'] ?? '')),
                'profileId' => '',
                'profileName' => '',
                'wan' => '',
                'disallow' => null
            ];

            if ($enrich) {
                try {
                    $detail = $this->SoapAction($service, 'X_AVM-DE_GetSpecificHostEntryByIP', ['NewIPAddress' => $ip]);
                    $row['friendlyName'] = trim((string) ($detail['NewX_AVM-DE_FriendlyName'] ?? ''));
                    $row['profileId'] = trim((string) ($detail['NewX_AVM-DE_FilterProfileID'] ?? ''));
                    $row['profileName'] = (string) ($profileNames[$row['profileId']] ?? '');
                    $row['wan'] = trim((string) ($detail['NewX_AVM-DE_WANAccess'] ?? ''));
                    if (isset($detail['NewX_AVM-DE_Disallow'])) {
                        $row['disallow'] = $this->ToBool($detail['NewX_AVM-DE_Disallow']);
                    }
                    if (trim((string) ($detail['NewHostName'] ?? '')) !== '') {
                        $row['hostName'] = trim((string) $detail['NewHostName']);
                    }
                } catch (Throwable $ignored) {
                    // Der Basiseintrag reicht für den Import aus.
                }
            }

            $key = $mac !== '' ? 'mac:' . $mac : 'ip:' . $ip;
            if (!isset($byKey[$key]) || (!$byKey[$key]['active'] && $row['active'])) {
                $byKey[$key] = $row;
            }
        }

        $rows = array_values($byKey);
        $this->SetBuffer('HostInventory', json_encode($rows, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
        $this->SetBuffer('HostInventoryTs', (string) time());
        return $rows;
    }

    private function GetFilterProfileNames(bool $force): array
    {
        $cached = $this->GetBuffer('FilterProfiles');
        $cachedTs = (int) $this->GetBuffer('FilterProfilesTs');
        if (!$force && $cached !== '' && (time() - $cachedTs) < self::FILTER_PROFILE_CACHE_SECONDS) {
            $value = json_decode($cached, true);
            if (is_array($value)) {
                return $value;
            }
        }

        $service = $this->DiscoverHostFilterService(false);
        $result = $this->SoapAction($service, 'GetFilterProfiles', []);
        $xml = trim((string) ($result['NewFilterProfileList'] ?? ''));
        if ($xml === '') {
            return [];
        }

        $dom = new DOMDocument();
        $loaded = @$dom->loadXML($xml);
        if (!$loaded) {
            $withoutDeclaration = preg_replace('/<\?xml[^>]*\?>/i', '', $xml) ?? $xml;
            $loaded = @$dom->loadXML('<Root>' . $withoutDeclaration . '</Root>');
        }
        if (!$loaded) {
            throw new Exception('Filterprofil-Liste ist kein gültiges XML.');
        }

        $xp = new DOMXPath($dom);
        $nodes = $xp->query('//*[local-name()="FilterProfile"]');
        $profiles = [];
        if ($nodes !== false) {
            foreach ($nodes as $node) {
                $id = $this->XpathChildText($xp, $node, 'FilterProfileID');
                $name = $this->XpathChildText($xp, $node, 'Name');
                if ($id !== '') {
                    $profiles[$id] = $name !== '' ? $name : $id;
                }
            }
        }

        $this->SetBuffer('FilterProfiles', json_encode($profiles, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
        $this->SetBuffer('FilterProfilesTs', (string) time());
        return $profiles;
    }

    private function SoapAction(array $service, string $action, array $arguments): array
    {
        $serviceType = (string) $service['serviceType'];
        $body = '';
        foreach ($arguments as $name => $value) {
            $body .= '<' . $name . '>' . htmlspecialchars((string) $value, ENT_XML1 | ENT_QUOTES, 'UTF-8') . '</' . $name . '>';
        }

        $soap = '<?xml version="1.0" encoding="utf-8"?>'
            . '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
            . '<s:Body><u:' . $action . ' xmlns:u="' . htmlspecialchars($serviceType, ENT_XML1 | ENT_QUOTES, 'UTF-8') . '">'
            . $body
            . '</u:' . $action . '></s:Body></s:Envelope>';

        $headers = [
            'Content-Type: text/xml; charset="utf-8"',
            'SOAPACTION: "' . $serviceType . '#' . $action . '"'
        ];
        $xml = $this->HttpRequest((string) $service['base'] . (string) $service['controlURL'], 'POST', $soap, $headers);

        $dom = new DOMDocument();
        if (!@$dom->loadXML($xml)) {
            throw new Exception('Ungültige SOAP-Antwort.');
        }
        $xp = new DOMXPath($dom);

        $fault = $xp->query('//*[local-name()="Fault"]');
        if ($fault !== false && $fault->length > 0) {
            $codeNode = $xp->query('.//*[local-name()="errorCode"]', $fault->item(0));
            $descNode = $xp->query('.//*[local-name()="errorDescription"]', $fault->item(0));
            $code = ($codeNode !== false && $codeNode->length) ? trim($codeNode->item(0)->textContent) : '?';
            $desc = ($descNode !== false && $descNode->length) ? trim($descNode->item(0)->textContent) : 'SOAP Fault';
            throw new Exception($action . ': ' . $code . ' ' . $desc);
        }

        $response = $xp->query('//*[local-name()="' . $action . 'Response"]');
        if ($response === false || $response->length === 0) {
            return [];
        }
        $out = [];
        foreach ($response->item(0)->childNodes as $child) {
            if ($child instanceof DOMElement) {
                $out[$child->localName] = trim($child->textContent);
            }
        }
        return $out;
    }

    private function HttpRequest(string $url, string $method, string $body, array $headers): string
    {
        $ch = curl_init($url);
        if ($ch === false) {
            throw new Exception('cURL konnte nicht gestartet werden.');
        }

        $user = $this->ReadPropertyString('User');
        $password = $this->ReadPropertyString('Password');
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CONNECTTIMEOUT => 4,
            CURLOPT_TIMEOUT => 8,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => 0,
            CURLOPT_HTTPAUTH => CURLAUTH_ANY,
            CURLOPT_USERPWD => $user . ':' . $password,
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_CUSTOMREQUEST => $method
        ]);
        if ($method === 'POST') {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        }

        $response = curl_exec($ch);
        $error = curl_error($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        curl_close($ch);

        if ($response === false || $response === '') {
            throw new Exception('Keine Antwort von ' . $url . ($error !== '' ? ' (' . $error . ')' : ''));
        }
        if ($status >= 400) {
            throw new Exception('HTTP ' . $status . ' von ' . $url);
        }
        return (string) $response;
    }

    private function XpathChildText(DOMXPath $xp, DOMNode $node, string $name): string
    {
        $list = $xp->query('./*[local-name()="' . $name . '"]', $node);
        if ($list === false || $list->length === 0) {
            return '';
        }
        return trim($list->item(0)->textContent);
    }

    private function GetRawDeviceRows(): array
    {
        $decoded = json_decode($this->ReadPropertyString('Devices'), true);
        return is_array($decoded) ? array_values(array_filter($decoded, 'is_array')) : [];
    }

    private function GetConfiguredDevices(): array
    {
        $out = [];
        foreach ($this->GetRawDeviceRows() as $row) {
            if (!((bool) ($row['Enabled'] ?? true))) {
                continue;
            }
            $ip = trim((string) ($row['IP'] ?? ''));
            if ($ip !== '' && filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
                $ip = '';
            }
            $mac = $this->NormalizeMac((string) ($row['MAC'] ?? ''));
            if ($ip === '' && $mac === '') {
                continue;
            }
            $out[] = [
                'group' => trim((string) ($row['Group'] ?? 'Geräte')) ?: 'Geräte',
                'name' => trim((string) ($row['Name'] ?? 'Gerät')) ?: 'Gerät',
                'ip' => $ip,
                'mac' => $mac
            ];
        }
        return $out;
    }

    private function GetResolvedConfiguredDevices(): array
    {
        $devices = $this->GetConfiguredDevices();
        if ($devices === []) {
            return [];
        }

        $needsResolution = false;
        foreach ($devices as $device) {
            if ($device['mac'] !== '') {
                $needsResolution = true;
                break;
            }
        }
        if (!$needsResolution) {
            return $devices;
        }

        try {
            $inventory = $this->GetHostInventory(false, false);
            $byMac = [];
            foreach ($inventory as $host) {
                $mac = $this->NormalizeMac((string) ($host['mac'] ?? ''));
                $ip = trim((string) ($host['ip'] ?? ''));
                if ($mac !== '' && filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
                    $byMac[$mac] = $ip;
                }
            }
            foreach ($devices as &$device) {
                if ($device['mac'] !== '' && isset($byMac[$device['mac']])) {
                    $device['ip'] = $byMac[$device['mac']];
                }
            }
            unset($device);
        } catch (Throwable $e) {
            $this->SendDebug('IP-Auflösung', $e->getMessage(), 0);
        }

        return $devices;
    }

    private function FindMatchingDeviceRow(array $existing, array $host, array $usedExisting): ?int
    {
        $hostMac = $this->NormalizeMac((string) ($host['mac'] ?? ''));
        $hostIp = trim((string) ($host['ip'] ?? ''));

        foreach ($existing as $idx => $row) {
            if (isset($usedExisting[$idx])) {
                continue;
            }
            $rowMac = $this->NormalizeMac((string) ($row['MAC'] ?? ''));
            if ($hostMac !== '' && $rowMac !== '' && hash_equals($hostMac, $rowMac)) {
                return $idx;
            }
        }
        foreach ($existing as $idx => $row) {
            if (isset($usedExisting[$idx])) {
                continue;
            }
            $rowIp = trim((string) ($row['IP'] ?? ''));
            if ($hostIp !== '' && $rowIp !== '' && hash_equals($hostIp, $rowIp)) {
                return $idx;
            }
        }
        return null;
    }

    private function IsConfiguredIP(string $ip): bool
    {
        foreach ($this->GetResolvedConfiguredDevices() as $device) {
            if ($device['ip'] !== '' && hash_equals($device['ip'], $ip)) {
                return true;
            }
        }
        return false;
    }

    private function NormalizeMac(string $mac): string
    {
        $hex = strtoupper(preg_replace('/[^0-9A-Fa-f]/', '', $mac) ?? '');
        if (strlen($hex) !== 12) {
            return '';
        }
        return implode(':', str_split($hex, 2));
    }

    private function ToBool(mixed $value): bool
    {
        if (is_bool($value)) {
            return $value;
        }
        $v = strtolower(trim((string) $value));
        return in_array($v, ['1', 'true', 'yes', 'on'], true);
    }

    /**
     * BUILD14: Erzeugt einen kurzlebigen Einmal-Schlüssel für den Wechsel in die Eltern-Visualisierung.
     * Dadurch muss die neu geladene HTML-Kachel nicht erneut nach der PIN fragen.
     */
    private function CreateParentHandoff(int $parentVisualizationId): string
    {
        $this->CleanupParentHandoffs();
        $token = bin2hex(random_bytes(16));
        $handoffs = $this->GetJsonBuffer('ParentHandoffs');
        $handoffs[$token] = [
            'expires' => time() + 30,
            'parentVisualizationId' => $parentVisualizationId
        ];
        // Puffer klein halten.
        if (count($handoffs) > 20) {
            uasort($handoffs, static fn(array $a, array $b): int => ((int) ($a['expires'] ?? 0)) <=> ((int) ($b['expires'] ?? 0)));
            while (count($handoffs) > 20) {
                array_shift($handoffs);
            }
        }
        $this->SetJsonBuffer('ParentHandoffs', $handoffs);
        return $token;
    }

    private function ConsumeParentHandoff(string $token, string $clientId, int $parentVisualizationId): bool
    {
        if (!preg_match('/^[a-f0-9]{32}$/', $token)) {
            return false;
        }
        $this->CleanupParentHandoffs();
        $handoffs = $this->GetJsonBuffer('ParentHandoffs');
        $entry = is_array($handoffs[$token] ?? null) ? $handoffs[$token] : null;
        if ($entry === null) {
            return false;
        }
        $expectedParentId = (int) ($entry['parentVisualizationId'] ?? 0);
        if ($expectedParentId <= 0 || $parentVisualizationId !== $expectedParentId || (int) ($entry['expires'] ?? 0) < time()) {
            unset($handoffs[$token]);
            $this->SetJsonBuffer('ParentHandoffs', $handoffs);
            return false;
        }

        // Einmal-Schlüssel sofort verbrauchen und den neuen Browser-Client für die normale PIN-Zeit freigeben.
        unset($handoffs[$token]);
        $this->SetJsonBuffer('ParentHandoffs', $handoffs);
        $this->Authorize($clientId);
        return true;
    }

    private function CleanupParentHandoffs(): void
    {
        $handoffs = $this->GetJsonBuffer('ParentHandoffs');
        if ($handoffs === []) {
            return;
        }
        $now = time();
        foreach ($handoffs as $token => $entry) {
            if (!is_array($entry) || (int) ($entry['expires'] ?? 0) < $now) {
                unset($handoffs[$token]);
            }
        }
        $this->SetJsonBuffer('ParentHandoffs', $handoffs);
    }

    private function Authorize(string $clientId): int
    {
        $clients = $this->GetJsonBuffer('AuthClients');
        $expires = time() + max(30, $this->ReadPropertyInteger('UnlockSeconds'));
        $clients[$clientId] = $expires;
        $this->SetJsonBuffer('AuthClients', $clients);
        return $expires;
    }

    private function TouchAuthorization(string $clientId): void
    {
        if (!$this->IsAuthorized($clientId)) {
            return;
        }
        $this->Authorize($clientId);
    }

    private function RemoveAuthorization(string $clientId): void
    {
        $clients = $this->GetJsonBuffer('AuthClients');
        unset($clients[$clientId]);
        $this->SetJsonBuffer('AuthClients', $clients);
    }

    private function IsAuthorized(string $clientId): bool
    {
        $clients = $this->GetJsonBuffer('AuthClients');
        return (int) ($clients[$clientId] ?? 0) >= time();
    }

    private function GetAuthorizationExpiry(string $clientId): int
    {
        $clients = $this->GetJsonBuffer('AuthClients');
        return (int) ($clients[$clientId] ?? 0);
    }

    private function HasAuthorizedClients(): bool
    {
        $this->CleanupAuthClients();
        return $this->GetJsonBuffer('AuthClients') !== [];
    }

    private function CleanupAuthClients(): void
    {
        $clients = $this->GetJsonBuffer('AuthClients');
        $now = time();
        foreach ($clients as $id => $expires) {
            if ((int) $expires < $now) {
                unset($clients[$id]);
            }
        }
        $this->SetJsonBuffer('AuthClients', $clients);
    }

    private function GetJsonBuffer(string $name): array
    {
        $raw = $this->GetBuffer($name);
        if ($raw === '') {
            return [];
        }
        $value = json_decode($raw, true);
        return is_array($value) ? $value : [];
    }

    private function SetJsonBuffer(string $name, array $value): void
    {
        $this->SetBuffer($name, json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
    }

    private function SendToTile(array $data): void
    {
        $this->UpdateVisualizationValue(json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
    }

    private function ShortError(string $message): string
    {
        return mb_strlen($message) > 100 ? mb_substr($message, 0, 97) . '…' : $message;
    }
}
