<?php

declare(strict_types=1);

class FritzKindersicherung extends IPSModuleStrict
{
    private const HOSTFILTER_SERVICE_FRAGMENT = 'X_AVM-DE_HostFilter';

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

        $this->RegisterTimer('RefreshTimer', 0, 'FKS_Refresh($_IPS["TARGET"]);');
    }

    public function ApplyChanges(): void
    {
        parent::ApplyChanges();

        $refresh = max(15, $this->ReadPropertyInteger('RefreshSeconds'));
        $this->SetTimerInterval('RefreshTimer', $refresh * 1000);
        $this->SetSummary($this->ReadPropertyBoolean('ReadOnly') ? 'TEST · PIN geschützt' : 'AKTIV · PIN geschützt');

        // Alte Anmeldungen und Service-Cache bei Konfigurationsänderungen verwerfen.
        $this->SetBuffer('AuthClients', '{}');
        $this->SetBuffer('FailedClients', '{}');
        $this->SetBuffer('HostFilterService', '');
        $this->SetBuffer('LastPayload', '');
    }

    public function GetVisualizationTile(): string
    {
        return (string) file_get_contents(__DIR__ . '/module.html');
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
                if ($this->IsAuthorized($clientId)) {
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

        if ($op === 'group_disallow') {
            $group = (string) ($cmd['group'] ?? '');
            $disallow = (bool) ($cmd['disallow'] ?? false);
            $this->HandleGroupDisallow($clientId, $group, $disallow);
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

    public function TestConnection(): string
    {
        try {
            $service = $this->DiscoverHostFilterService(true);
            $devices = $this->GetConfiguredDevices();
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

            return 'OK – TR-064 HostFilter gefunden. Bitte jetzt IPv4-Adressen der Geräte eintragen.';
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

        $this->SendToTile([
            'kind' => 'auth', 'target' => $clientId, 'ok' => true,
            'expires' => $expires, 'payload' => $payload
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

        $targets = array_values(array_filter($this->GetConfiguredDevices(), static fn(array $d): bool => $d['group'] === $group && $d['ip'] !== ''));
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

    private function BuildStatusPayload(string $message): array
    {
        $devices = $this->GetConfiguredDevices();
        $result = [];

        if ($devices !== []) {
            $service = $this->DiscoverHostFilterService(false);
            foreach ($devices as $device) {
                if ($device['ip'] === '') {
                    continue;
                }

                $row = [
                    'group' => $device['group'],
                    'name' => $device['name'],
                    'ip' => $device['ip'],
                    'wan' => 'error',
                    'disallow' => null,
                    'profile' => '',
                    'timeUsed' => 0,
                    'timeMax' => 0,
                    'error' => ''
                ];

                try {
                    // Die neuere API liefert Profil und Zeitbudget in einem Aufruf.
                    $entry = $this->SoapAction($service, 'GetHostEntryByIP', ['NewIPv4Address' => $device['ip']]);
                    $row['wan'] = (string) ($entry['NewWANAccess'] ?? 'error');
                    $row['profile'] = (string) ($entry['NewFilterProfileID'] ?? '');
                    $row['timeUsed'] = (int) ($entry['NewTimeUsed'] ?? 0);
                    $row['timeMax'] = (int) ($entry['NewTimeMax'] ?? 0);

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

        $payload = [
            'readOnly' => $this->ReadPropertyBoolean('ReadOnly'),
            'devices' => $result,
            'message' => $message
        ];
        $this->SetBuffer('LastPayload', json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
        return $payload;
    }

    private function DiscoverHostFilterService(bool $force): array
    {
        if (!$force) {
            $cached = $this->GetBuffer('HostFilterService');
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
                    if (stripos($serviceType, self::HOSTFILTER_SERVICE_FRAGMENT) === false) {
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
                    $this->SetBuffer('HostFilterService', json_encode($service, JSON_UNESCAPED_SLASHES));
                    return $service;
                }
                throw new Exception('X_AVM-DE_HostFilter wurde in tr64desc.xml nicht gefunden.');
            } catch (Throwable $e) {
                $lastError = $e->getMessage();
            }
        }

        throw new Exception('TR-064 nicht erreichbar: ' . $lastError);
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

    private function GetConfiguredDevices(): array
    {
        $decoded = json_decode($this->ReadPropertyString('Devices'), true);
        if (!is_array($decoded)) {
            return [];
        }
        $out = [];
        foreach ($decoded as $row) {
            if (!is_array($row) || !((bool) ($row['Enabled'] ?? true))) {
                continue;
            }
            $ip = trim((string) ($row['IP'] ?? ''));
            if ($ip !== '' && filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
                continue;
            }
            $out[] = [
                'group' => trim((string) ($row['Group'] ?? 'Geräte')) ?: 'Geräte',
                'name' => trim((string) ($row['Name'] ?? 'Gerät')) ?: 'Gerät',
                'ip' => $ip
            ];
        }
        return $out;
    }

    private function IsConfiguredIP(string $ip): bool
    {
        foreach ($this->GetConfiguredDevices() as $device) {
            if ($device['ip'] !== '' && hash_equals($device['ip'], $ip)) {
                return true;
            }
        }
        return false;
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
