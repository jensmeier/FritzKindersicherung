<?php

declare(strict_types=1);

class OnlinezeitKinder extends IPSModuleStrict
{
    private const SOURCE_MODULE_ID = '{8FD44702-1516-4F0D-A8A2-50F8840D6946}';

    public function Create(): void
    {
        parent::Create();

        // Stabiler HTML-SDK-Kachelmodus, ideal für eine kleine reine Anzeige.
        $this->SetVisualizationType(1);

        $this->RegisterPropertyInteger('SourceInstance', 0);
        $this->RegisterPropertyInteger('RotateSeconds', 5);
        $this->RegisterPropertyBoolean('ShowTickets', true);
        $this->RegisterPropertyBoolean('ShowOnlineCount', true);
        $this->RegisterPropertyString('Groups', '[]');

        // Statusquelle der Hauptinstanz wird typischerweise alle 60 s aktualisiert.
        // Die 1x1-Kachel pollt nur den lokalen Symcon-Status, nicht die FRITZ!Box.
        $this->RegisterTimer('RefreshTimer', 0, 'OZK_Refresh($_IPS["TARGET"]);');
    }

    public function ApplyChanges(): void
    {
        parent::ApplyChanges();
        $this->SetVisualizationType(1);
        $this->SetTimerInterval('RefreshTimer', 15000);
        $this->SetSummary($this->ReadPropertyInteger('RotateSeconds') . ' s Wechsel');
    }

    public function GetVisualizationTile(): string
    {
        return (string) file_get_contents(__DIR__ . '/module.html');
    }

    public function GetConfigurationForm(): string
    {
        $form = json_decode((string) file_get_contents(__DIR__ . '/form.json'), true);
        if (!is_array($form)) {
            return '{}';
        }

        $available = $this->GetAvailableGroupNames();
        $saved = $this->GetSavedGroupSelection();
        $rows = [];

        foreach ($available as $group) {
            $rows[] = [
                'Enabled' => array_key_exists($group, $saved) ? $saved[$group] : true,
                'Group' => $group
            ];
        }

        // Gespeicherte Gruppen, die gerade nicht in den Daten vorkommen, nicht stillschweigend verlieren.
        foreach ($saved as $group => $enabled) {
            if (!in_array($group, $available, true)) {
                $rows[] = ['Enabled' => $enabled, 'Group' => $group];
            }
        }

        foreach ($form['elements'] as &$element) {
            if (($element['name'] ?? '') === 'Groups') {
                $element['values'] = $rows;
                break;
            }
        }
        unset($element);

        return json_encode($form, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
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

        if (($cmd['op'] ?? '') === 'hello' || ($cmd['op'] ?? '') === 'refresh') {
            $this->SendCurrentStatus();
        }
    }

    public function Refresh(): void
    {
        $this->SendCurrentStatus();
    }

    private function SendCurrentStatus(): void
    {
        $payload = $this->BuildTilePayload();
        $this->UpdateVisualizationValue(json_encode([
            'kind' => 'status',
            'payload' => $payload
        ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
    }

    private function BuildTilePayload(): array
    {
        $source = $this->ReadPropertyInteger('SourceInstance');
        $data = $this->ReadSourcePayload($source);
        $summaries = $this->BuildSummaries($data['devices'] ?? []);
        $selection = $this->GetSavedGroupSelection();

        // Leere Auswahl = alle aktuell vorhandenen Gruppen anzeigen.
        if ($selection !== []) {
            $summaries = array_values(array_filter($summaries, static function (array $row) use ($selection): bool {
                return (bool) ($selection[$row['group']] ?? false);
            }));
        }

        $globalTicketCodes = 0;
        foreach ((array) ($data['issuedTickets'] ?? []) as $ticket) {
            if (is_array($ticket) && (string) ($ticket['status'] ?? '') === 'marked') {
                $globalTicketCodes++;
            }
        }

        return [
            'rotateSeconds' => max(2, min(60, $this->ReadPropertyInteger('RotateSeconds'))),
            'showTickets' => $this->ReadPropertyBoolean('ShowTickets'),
            'showOnlineCount' => $this->ReadPropertyBoolean('ShowOnlineCount'),
            'groups' => $summaries,
            'globalTicketCodes' => $globalTicketCodes,
            'updated' => date('H:i:s'),
            'message' => (string) ($data['message'] ?? '')
        ];
    }

    private function ReadSourcePayload(int $source): array
    {
        if ($source <= 0 || !IPS_InstanceExists($source)) {
            return ['devices' => [], 'message' => 'Keine Kindersicherung ausgewählt.'];
        }

        $instance = IPS_GetInstance($source);
        if (($instance['ModuleInfo']['ModuleID'] ?? '') !== self::SOURCE_MODULE_ID) {
            return ['devices' => [], 'message' => 'Ausgewählte Instanz ist keine FRITZ!Box Kindersicherung.'];
        }

        // BUILD9: Status direkt aus dem Modul-Buffer der Hauptinstanz abrufen.
        // Die BUILD8-Zwischenvariable war auf dem Zielsystem schreibgeschützt.
        $fn = 'FKS_GetPublicStatus';
        if (function_exists($fn)) {
            try {
                $json = (string) $fn($source);
                $decoded = json_decode($json, true);
                if (is_array($decoded)) {
                    return $decoded;
                }
            } catch (Throwable $ignored) {
            }
        }

        return ['devices' => [], 'message' => 'Noch keine Statusdaten vorhanden. Hauptinstanz einmal aktualisieren.'];
    }

    private function BuildSummaries(array $devices): array
    {
        $byGroup = [];
        foreach ($devices as $device) {
            if (!is_array($device)) {
                continue;
            }
            $group = trim((string) ($device['group'] ?? ''));
            if ($group === '') {
                $group = 'Geräte';
            }
            $byGroup[$group][] = $device;
        }

        $rows = [];
        foreach ($byGroup as $group => $devs) {
            $valid = array_values(array_filter($devs, static fn(array $d): bool => trim((string) ($d['error'] ?? '')) === ''));
            $online = count(array_filter($valid, static fn(array $d): bool => (string) ($d['wan'] ?? '') === 'granted'));

            $rest = null;
            $profile = '';
            $shared = array_values(array_filter($valid, static fn(array $d): bool => (bool) ($d['isTimeShared'] ?? false) && (int) ($d['timeMax'] ?? 0) > 0));
            if ($shared !== []) {
                $profileKeys = [];
                foreach ($shared as $d) {
                    $profileKeys[(string) ($d['profileId'] ?? $d['profile'] ?? '')] = true;
                }
                if (count($profileKeys) === 1) {
                    $d = $shared[0];
                    $rest = max(0, (int) ($d['timeMax'] ?? 0) - (int) ($d['timeUsed'] ?? 0));
                    $profile = (string) ($d['profile'] ?? '');
                }
            }

            if ($rest === null) {
                $timed = array_values(array_filter($valid, static fn(array $d): bool => (int) ($d['timeMax'] ?? 0) > 0));
                if (count($timed) === 1) {
                    $d = $timed[0];
                    $rest = max(0, (int) ($d['timeMax'] ?? 0) - (int) ($d['timeUsed'] ?? 0));
                    $profile = (string) ($d['profile'] ?? '');
                }
            }

            $queuedExtra = 0;
            $activeExtraMax = 0;
            foreach ($valid as $d) {
                $queuedExtra += (int) ($d['ticketsInAdvance'] ?? 0);
                $activeExtraMax = max($activeExtraMax, (int) ($d['ticketValid'] ?? 0));
            }

            $rows[] = [
                'group' => (string) $group,
                'rest' => $rest,
                'profile' => $profile,
                'queuedExtra' => $queuedExtra,
                'activeExtraMax' => $activeExtraMax,
                'online' => $online,
                'total' => count($devs)
            ];
        }

        usort($rows, static fn(array $a, array $b): int => strnatcasecmp($a['group'], $b['group']));
        return $rows;
    }

    private function GetSavedGroupSelection(): array
    {
        $raw = json_decode($this->ReadPropertyString('Groups'), true);
        if (!is_array($raw)) {
            return [];
        }

        $result = [];
        foreach ($raw as $row) {
            if (!is_array($row)) {
                continue;
            }
            $group = trim((string) ($row['Group'] ?? ''));
            if ($group === '') {
                continue;
            }
            $result[$group] = (bool) ($row['Enabled'] ?? false);
        }
        return $result;
    }

    private function GetAvailableGroupNames(): array
    {
        $data = $this->ReadSourcePayload($this->ReadPropertyInteger('SourceInstance'));
        $groups = [];
        foreach (($data['devices'] ?? []) as $device) {
            if (!is_array($device)) {
                continue;
            }
            $group = trim((string) ($device['group'] ?? ''));
            if ($group === '') {
                $group = 'Geräte';
            }
            $groups[$group] = true;
        }
        $result = array_keys($groups);
        natcasesort($result);
        return array_values($result);
    }
}
