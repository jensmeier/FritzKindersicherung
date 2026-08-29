<?php

declare(strict_types=1);

class Elternansicht extends IPSModuleStrict
{
    private const SOURCE_MODULE_ID = '{8FD44702-1516-4F0D-A8A2-50F8840D6946}';

    public function Create(): void
    {
        parent::Create();
        $this->SetVisualizationType(1);
        $this->RegisterPropertyInteger('SourceInstance', 0);
        $this->RegisterPropertyInteger('UnlockSeconds', 180);
        $this->RegisterPropertyInteger('RefreshSeconds', 15);
        $this->RegisterTimer('RefreshTimer', 0, 'FKSE_Refresh($_IPS["TARGET"]);');
        $this->SetBuffer('AuthClients', '{}');
        $this->SetBuffer('FailedClients', '{}');
    }

    public function ApplyChanges(): void
    {
        parent::ApplyChanges();
        $this->SetVisualizationType(1);
        $seconds = max(5, min(300, $this->ReadPropertyInteger('RefreshSeconds')));
        $this->SetTimerInterval('RefreshTimer', $seconds * 1000);
        $this->SetSummary('PIN geschützt · Eltern');
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

        if ($op === 'hello') {
            if ($this->IsAuthorized($clientId)) {
                $this->SendStatus($clientId, $this->ReadSourceStatus(), '');
            } else {
                $this->Send(['kind' => 'locked', 'target' => $clientId]);
            }
            return;
        }
        if ($op === 'unlock') {
            $this->HandleUnlock($clientId, (string) ($cmd['pin'] ?? ''));
            return;
        }
        if ($op === 'lock') {
            $this->RemoveAuthorization($clientId);
            $this->Send(['kind' => 'locked', 'target' => $clientId, 'message' => 'Gesperrt.']);
            return;
        }

        if (!$this->IsAuthorized($clientId)) {
            $this->Send(['kind' => 'locked', 'target' => $clientId, 'message' => 'PIN-Sitzung abgelaufen.']);
            return;
        }
        $this->TouchAuthorization($clientId);

        if ($op === 'refresh') {
            $data = $this->ExecuteSource(['op' => 'refresh']);
            $this->SendStatus($clientId, $data, '');
            return;
        }

        if (in_array($op, ['set_disallow', 'set_profile', 'group_disallow', 'group_profile', 'add_ticket_time', 'mark_ticket'], true)) {
            $allowed = ['op' => $op];
            foreach (['ip', 'disallow', 'profileId', 'group'] as $key) {
                if (array_key_exists($key, $cmd)) {
                    $allowed[$key] = $cmd[$key];
                }
            }
            $data = $this->ExecuteSource($allowed);
            $this->SendStatus($clientId, $data, '');
        }
    }

    public function Refresh(): void
    {
        if (!$this->HasAuthorizedClients()) {
            return;
        }
        $data = $this->ReadSourceStatus();
        $this->Send(['kind' => 'status', 'target' => '*', 'payload' => $data]);
    }

    private function HandleUnlock(string $clientId, string $pin): void
    {
        $failed = $this->GetJsonBuffer('FailedClients');
        $now = time();
        $entry = is_array($failed[$clientId] ?? null) ? $failed[$clientId] : ['count' => 0, 'until' => 0];
        if ((int) ($entry['until'] ?? 0) > $now) {
            $this->Send(['kind' => 'auth', 'target' => $clientId, 'ok' => false, 'message' => 'Zu viele Fehlversuche. Noch ' . ((int)$entry['until'] - $now) . ' s gesperrt.']);
            return;
        }

        $source = $this->GetSourceInstance();
        $ok = false;
        $fn = 'FKS_CheckPin';
        if ($source > 0 && function_exists($fn)) {
            try {
                $ok = (bool) $fn($source, $pin);
            } catch (Throwable $ignored) {
            }
        }
        if (!$ok) {
            $count = (int) ($entry['count'] ?? 0) + 1;
            $until = $count >= 3 ? $now + 30 : 0;
            if ($count >= 3) {
                $count = 0;
            }
            $failed[$clientId] = ['count' => $count, 'until' => $until];
            $this->SetJsonBuffer('FailedClients', $failed);
            $this->Send(['kind' => 'auth', 'target' => $clientId, 'ok' => false, 'message' => $until > 0 ? '3 falsche PINs – 30 s gesperrt.' : 'PIN falsch.']);
            return;
        }

        unset($failed[$clientId]);
        $this->SetJsonBuffer('FailedClients', $failed);
        $expires = $this->Authorize($clientId);
        $this->Send(['kind' => 'auth', 'target' => $clientId, 'ok' => true, 'expires' => $expires, 'payload' => $this->ReadSourceStatus()]);
    }

    private function ReadSourceStatus(): array
    {
        $source = $this->GetSourceInstance();
        if ($source <= 0) {
            return ['readOnly' => true, 'devices' => [], 'profiles' => [], 'issuedTickets' => [], 'message' => 'Keine FRITZ!Box Kindersicherung ausgewählt.'];
        }
        $fn = 'FKS_GetPublicStatus';
        if (!function_exists($fn)) {
            return ['readOnly' => true, 'devices' => [], 'profiles' => [], 'issuedTickets' => [], 'message' => 'Hauptmodul unterstützt die Elternansicht noch nicht.'];
        }
        try {
            $decoded = json_decode((string) $fn($source), true);
            return is_array($decoded) ? $decoded : ['readOnly' => true, 'devices' => [], 'message' => 'Status konnte nicht gelesen werden.'];
        } catch (Throwable $e) {
            return ['readOnly' => true, 'devices' => [], 'message' => 'Statusfehler: ' . $e->getMessage()];
        }
    }

    private function ExecuteSource(array $command): array
    {
        $source = $this->GetSourceInstance();
        if ($source <= 0) {
            return ['readOnly' => true, 'devices' => [], 'message' => 'Keine Hauptinstanz gewählt.'];
        }
        $fn = 'FKS_ExecuteExternal';
        if (!function_exists($fn)) {
            return ['readOnly' => true, 'devices' => [], 'message' => 'Hauptmodul ist zu alt für die Elternansicht.'];
        }
        try {
            $json = (string) $fn($source, json_encode($command, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
            $decoded = json_decode($json, true);
            return is_array($decoded) ? $decoded : ['readOnly' => true, 'devices' => [], 'message' => 'Ungültige Antwort der Hauptinstanz.'];
        } catch (Throwable $e) {
            return ['readOnly' => true, 'devices' => [], 'message' => 'Steuerfehler: ' . $e->getMessage()];
        }
    }

    private function GetSourceInstance(): int
    {
        $source = $this->ReadPropertyInteger('SourceInstance');
        if ($source <= 0 || !IPS_InstanceExists($source)) {
            return 0;
        }
        $instance = IPS_GetInstance($source);
        return (($instance['ModuleInfo']['ModuleID'] ?? '') === self::SOURCE_MODULE_ID) ? $source : 0;
    }

    private function SendStatus(string $clientId, array $payload, string $message): void
    {
        if ($message !== '') {
            $payload['message'] = $message;
        }
        $this->Send(['kind' => 'status', 'target' => $clientId, 'expires' => $this->GetAuthorizationExpiry($clientId), 'payload' => $payload]);
    }

    private function Send(array $data): void
    {
        $this->UpdateVisualizationValue(json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
    }

    private function Authorize(string $clientId): int
    {
        $expires = time() + max(30, min(1800, $this->ReadPropertyInteger('UnlockSeconds')));
        $clients = $this->GetJsonBuffer('AuthClients');
        $clients[$clientId] = $expires;
        $this->SetJsonBuffer('AuthClients', $clients);
        return $expires;
    }

    private function TouchAuthorization(string $clientId): void
    {
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
        return $this->GetAuthorizationExpiry($clientId) >= time();
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
        $decoded = json_decode($raw, true);
        return is_array($decoded) ? $decoded : [];
    }

    private function SetJsonBuffer(string $name, array $value): void
    {
        $this->SetBuffer($name, json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
    }
}
