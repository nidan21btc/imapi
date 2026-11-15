<?php
declare(strict_types=1);

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\SMTP;
use Webklex\PHPIMAP\Client;
use Webklex\PHPIMAP\ClientManager;
use Webklex\PHPIMAP\Connection\Protocols\ImapProtocol;
use Webklex\PHPIMAP\Folder;
use Webklex\PHPIMAP\Message;

// Never emit library exceptions, arguments, protocol traces or credentials.
ini_set('display_errors', '0');
ini_set('log_errors', '0');
ini_set('zend.exception_ignore_args', '1');
require __DIR__ . '/../vendor/autoload.php';

final class ApiError extends RuntimeException {
    public function __construct(public int $status, public string $errorCode, string $message) {
        parent::__construct($message);
    }
}

// A later recipient/QUIT error must never turn an accepted DATA into a failed send.
final class TrackedSMTP extends SMTP {
    public bool $accepted = false;
    public bool $dataStarted = false;
    public int $dataFailureCode = 0;

    public function data($msg_data): bool {
        $this->dataStarted = true;
        $this->accepted = parent::data($msg_data);
        if (!$this->accepted) { $this->dataFailureCode = (int)($this->getError()['smtp_code'] ?? 0); }
        return $this->accepted;
    }
}

function fail(int $status, string $code, string $message): never { throw new ApiError($status, $code, $message); }
/** @param array<string, mixed> $data */
function respond(int $status, array $data): void {
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    header('X-Content-Type-Options: nosniff');
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR);
}
/** @param array<string, mixed> $p */
function strparam(array $p, string $key, ?string $default = null, int $max = 1024): string {
    $value = $p[$key] ?? $default;
    if (!is_string($value) || strlen($value) > $max || str_contains($value, "\0")) {
        fail(400, 'invalid_parameter', "Ungültiger Parameter: $key.");
    }
    return $value;
}
/** @param array<string, mixed> $p */
function lineparam(array $p, string $key, ?string $default = null, int $max = 1024): string {
    $v = strparam($p, $key, $default, $max);
    if (preg_match('/[\x00-\x1f\x7f]/', $v)) { fail(400, 'invalid_parameter', "Ungültiger Parameter: $key."); }
    return $v;
}
/** @param array<string, mixed> $p */
function boolparam(array $p, string $key, bool $default = false): bool {
    if (array_key_exists($key, $p) && !is_bool($p[$key])) { fail(400, 'invalid_parameter', "Ungültiger Parameter: $key."); }
    return $p[$key] ?? $default;
}
/** @param array<string, mixed> $p */
function intparam(array $p, string $key, int $min, int $max, ?int $default = null): int {
    $v = $p[$key] ?? $default;
    if (!is_int($v) || $v < $min || $v > $max) { fail(400, 'invalid_parameter', "Ungültiger Parameter: $key."); }
    return $v;
}
/** @param list<string> $patterns */
function allowedMailbox(string $user, array $patterns): bool {
    if (!filter_var($user, FILTER_VALIDATE_EMAIL)) { return false; }
    if (!$patterns) { return true; }
    foreach ($patterns as $pattern) {
        if (str_starts_with($pattern, '*@')) {
            if (strcasecmp(substr($user, strrpos($user, '@') + 1), substr($pattern, 2)) === 0) { return true; }
        } elseif (strcasecmp($user, $pattern) === 0) { return true; }
    }
    return false;
}
/** @return array<string, mixed> */
function config(): array {
    $path = getenv('IMAPI_CONFIG') ?: __DIR__ . '/../private/config.php';
    $c = is_file($path) ? require $path : null;
    if (!is_array($c) || empty($c['api_key_hash']) || !password_get_info($c['api_key_hash'])['algo']
        || empty($c['state_dir']) || empty($c['mail_host']) || !in_array($c['smtp_port'] ?? 0, [465, 587], true)) {
        fail(503, 'configuration_error', 'Serverkonfiguration unvollständig.');
    }
    $c += ['sent_folder' => 'Sent', 'create_sent_folder_if_missing' => true,
        'allowed_mail_hosts' => ['cloud3-vm338.de-nserver.de'], 'local_only' => false];
    mailTransport($c);
    autoCreateSentFolder($c);
    $root = realpath(__DIR__) . DIRECTORY_SEPARATOR;
    foreach ([$path, $c['state_dir']] as $private) {
        // State directory must already exist, so containment checks cannot be bypassed by '..'.
        $real = realpath($private);
        if (!$real || $real === rtrim($root, DIRECTORY_SEPARATOR) || str_starts_with($real, $root)) {
            fail(503, 'configuration_error', 'Config und Statusverzeichnis müssen außerhalb des Webroots liegen.');
        }
    }
    return $c;
}
/** @param array<string, mixed> $c */
function mailHost(array $c): string {
    $host = $c['mail_host'] ?? null;
    $allowed = $c['allowed_mail_hosts'] ?? ['cloud3-vm338.de-nserver.de'];
    if (!is_string($host) || !is_array($allowed) || !array_is_list($allowed)
        || !filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
        fail(503, 'mail_server_forbidden', 'Mailserver nicht freigegeben.');
    }
    foreach ($allowed as $entry) {
        if (is_string($entry) && strcasecmp($host, $entry) === 0) { return $host; }
    }
    fail(503, 'mail_server_forbidden', 'Mailserver nicht freigegeben.');
}
/**
 * @param array<string, mixed> $c
 * @return array{host: string, ssl: array{peer_name: string, verify_peer: true, verify_peer_name: true, allow_self_signed: false, SNI_enabled: true}}
 */
function mailTransport(array $c): array {
    $host = mailHost($c);
    $localOnly = $c['local_only'] ?? false;
    if (!is_bool($localOnly)) { fail(503, 'configuration_error', 'local_only muss ein boolescher Wert sein.'); }
    return ['host' => $localOnly ? '127.0.0.1' : $host,
        'ssl' => ['peer_name' => $host, 'verify_peer' => true, 'verify_peer_name' => true,
            'allow_self_signed' => false, 'SNI_enabled' => true]];
}
/** Normalize IPv6 clients to /64; IPv4-mapped IPv6 shares the IPv4 bucket. */
function clientNetwork(string $ip): string {
    $packed = @inet_pton($ip);
    if ($packed === false) { return 'unknown'; }
    if (strlen($packed) === 16 && substr($packed, 0, 12) === str_repeat("\0", 10) . "\xff\xff") {
        return (string)inet_ntop(substr($packed, 12));
    }
    if (strlen($packed) === 16) { return bin2hex(substr($packed, 0, 8)) . '/64'; }
    return (string)inet_ntop($packed);
}
/** @param array<string, mixed> $c */
function limiterOption(array $c, string $name, int $default, int $max = 86400): int {
    $value = $c[$name] ?? $default;
    if (!is_int($value) || $value < 1 || $value > $max) { fail(503, 'configuration_error', 'Ungültige Limiter-Konfiguration.'); }
    return $value;
}
/**
 * Fixed 64 shards per scope, at most 128 records and 2 MiB per file. Never
 * evict live bans to admit a new identity. No filenames depend on raw input.
 * @param array<string, mixed> $c
 * @param callable(array<string, mixed>): mixed $update
 */
function limiterUpdate(array $c, string $scope, string $key, callable $update): mixed {
    if (!in_array($scope, ['ip', 'mail'], true)) { fail(503, 'rate_limit_unavailable', 'Rate-Limit nicht verfügbar.'); }
    $digest = hash('sha256', $key);
    $shard = sprintf('%02x', hexdec(substr($digest, 0, 2)) % 64);
    $path = $c['state_dir'] . '/v2-' . $scope . '-' . $shard . '.json';
    $f = @fopen($path, 'c+');
    if (!$f) { fail(503, 'rate_limit_unavailable', 'Rate-Limit nicht verfügbar.'); }
    $deadline = hrtime(true) + 250_000_000;
    do {
        $locked = flock($f, LOCK_EX | LOCK_NB);
        if (!$locked) { usleep(1000); }
    } while (!$locked && hrtime(true) < $deadline);
    if (!$locked) {
        fclose($f); header('Retry-After: 1');
        fail(503, 'rate_limit_unavailable', 'Rate-Limit derzeit ausgelastet.');
    }
    try {
        $raw = stream_get_contents($f, 2 * 1024 * 1024 + 1);
        if ($raw === false || strlen($raw) > 2 * 1024 * 1024) { fail(503, 'rate_limit_unavailable', 'Rate-Limit nicht verfügbar.'); }
        try { $records = $raw === '' ? [] : json_decode($raw, true, 16, JSON_THROW_ON_ERROR); }
        catch (JsonException) { fail(503, 'rate_limit_unavailable', 'Rate-Limit nicht verfügbar.'); }
        if (!is_array($records) || count($records) > 128) { fail(503, 'rate_limit_unavailable', 'Rate-Limit nicht verfügbar.'); }
        $now = time();
        foreach ($records as $id => $record) {
            if (!is_array($record) || ($record['expires'] ?? 0) <= $now) { unset($records[$id]); }
        }
        if (!isset($records[$key]) && count($records) >= 128) {
            fail(503, 'rate_limit_capacity', 'Rate-Limit-Kapazität derzeit ausgeschöpft.');
        }
        $state = $records[$key] ?? [];
        $error = null; $result = null;
        try { $result = $update($state); }
        catch (Throwable $e) { $error = $e; }
        $state['expires'] = max($now + 900, ($state['blocked'] ?? 0) + 60);
        $records[$key] = $state;
        $json = json_encode($records, JSON_THROW_ON_ERROR);
        if (strlen($json) > 2 * 1024 * 1024) { fail(503, 'rate_limit_unavailable', 'Rate-Limit nicht verfügbar.'); }
        rewind($f);
        if (!ftruncate($f, 0) || fwrite($f, $json) !== strlen($json) || !fflush($f)) {
            fail(503, 'rate_limit_unavailable', 'Rate-Limit nicht verfügbar.');
        }
        if ($error !== null) { throw $error; }
        return $result;
    } finally { flock($f, LOCK_UN); fclose($f); }
}
function throttled(int $seconds, string $code = 'rate_limited'): never {
    header('Retry-After: ' . max(1, $seconds));
    fail(429, $code, 'Zu viele Anfragen oder fehlgeschlagene Anmeldungen. Bitte später erneut versuchen.');
}
/**
 * @param array<string, mixed> $c
 * @param array<string, mixed> $server
 */
function authenticate(array $c, array $server): void {
    $keyId = hash('sha256', clientNetwork($server['REMOTE_ADDR'] ?? 'unknown'));
    $valid = limiterUpdate($c, 'ip', $keyId, static function (array &$state) use ($c, $server): bool {
        $now = time();
        $requests = array_values(array_filter($state['requests'] ?? [], fn($t) => $t > $now - 60));
        $failures = array_values(array_filter($state['failures'] ?? [], fn($t) => $t > $now - 900));
        $blocked = $state['blocked'] ?? 0;
        if ($blocked > $now) { throttled($blocked - $now); }
        if (count($requests) >= limiterOption($c, 'requests_per_minute', 60, 1000)) { throttled($requests[0] + 60 - $now); }
        $requests[] = $now;
        $auth = $server['HTTP_AUTHORIZATION'] ?? '';
        // Reject malformed credentials cheaply; generated keys are 64 hex chars.
        // Keep the documented token alphabet for existing manually provisioned keys.
        $wellFormed = preg_match('/^Bearer ([A-Za-z0-9_-]{32,72})$/D', $auth, $m) === 1;
        $valid = $wellFormed && password_verify($m[1], $c['api_key_hash']);
        if (!$valid) {
            $failures[] = $now;
            if (count($failures) >= limiterOption($c, 'failed_keys_before_block', 5, 100)) {
                $blocked = $now + limiterOption($c, 'block_seconds', 900);
                $failures = [];
            }
        }
        $state = ['requests' => $requests, 'failures' => $failures, 'blocked' => $blocked];
        return $valid;
    });
    if (!$valid) { header('WWW-Authenticate: Bearer'); fail(401, 'unauthorized', 'Ungültiger API-Key.'); }
}
/**
 * @param array<string, mixed> $c
 * @param callable(): array<string, mixed> $operation
 * @return array<string, mixed>
 */
function mailAuthentication(array $c, string $user, callable $operation): array {
    $ip = hash('sha256', clientNetwork($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
    $mailbox = hash_hmac('sha256', strtolower($user), $c['api_key_hash']);
    $guards = [
        ['key' => 'ip:' . $ip, 'limit' => limiterOption($c, 'failed_mail_logins_before_block', 5, 100),
            'block' => limiterOption($c, 'mail_auth_block_seconds', 900)],
        ['key' => 'mailbox:' . $mailbox, 'limit' => limiterOption($c, 'failed_mail_logins_per_mailbox', 10, 100),
            'block' => limiterOption($c, 'mailbox_auth_block_seconds', 60)],
    ];
    $lease = bin2hex(random_bytes(16));
    $reserved = []; $failed = false; $result = null;
    try {
        foreach ($guards as $guard) {
            limiterUpdate($c, 'mail', $guard['key'], static function (array &$s) use ($guard, $lease): void {
                $now = time();
                $s['failures'] = array_values(array_filter($s['failures'] ?? [], fn($t) => $t > $now - 900));
                $s['pending'] = array_filter($s['pending'] ?? [], fn($t) => $t > $now);
                if (($s['blocked'] ?? 0) > $now) { throttled($s['blocked'] - $now, 'mail_auth_rate_limited'); }
                if (count($s['failures']) + count($s['pending']) >= $guard['limit']) {
                    throttled(1, 'mail_auth_rate_limited');
                }
                // Count in-flight attempts before releasing the lock to stop parallel guessing.
                $s['pending'][$lease] = $now + 180;
            });
            $reserved[] = $guard;
        }
        try { $result = $operation(); }
        catch (\Webklex\PHPIMAP\Exceptions\AuthFailedException $e) { $failed = true; throw $e; }
        catch (ApiError $e) { $failed = $e->errorCode === 'mail_auth_failed'; throw $e; }
    } finally {
        foreach ($reserved as $guard) {
            try {
                limiterUpdate($c, 'mail', $guard['key'], static function (array &$s) use ($guard, $lease, $failed): void {
                    unset($s['pending'][$lease]);
                    if ($failed) {
                        $now = time();
                        $s['failures'] = array_values(array_filter($s['failures'] ?? [], fn($t) => $t > $now - 900));
                        $s['failures'][] = $now;
                        if (count($s['failures']) >= $guard['limit']) {
                            $s['blocked'] = $now + $guard['block'];
                            $s['failures'] = [];
                        }
                    }
                });
            } catch (Throwable $e) {
                // Never turn confirmed SMTP acceptance into a retryable failed send.
                if (is_array($result) && ($result['sent'] ?? false) === true) { $result['security_warning'] = 'Rate-Limit-Status konnte nicht aktualisiert werden.'; }
                else { throw $e; }
            }
        }
    }
    return $result;
}
/** @return array<string, mixed> */
function imapOptions(): array {
    return ['options' => ['debug' => false, 'fetch' => \Webklex\PHPIMAP\IMAP::FT_PEEK,
        'fetch_body' => false, 'soft_fail' => false],
        'decoding' => ['options' => ['header' => 'iconv']]];
}
/** @param array<string, mixed> $c */
function connectMailbox(array $c, string $user, #[SensitiveParameter] string $password): Client {
    $transport = mailTransport($c);
    $client = (new ClientManager(imapOptions()))->make([
        'host' => $transport['host'], 'ssl_options' => $transport['ssl'], 'port' => 993, 'encryption' => 'ssl', 'validate_cert' => true,
        'protocol' => 'imap', 'username' => $user, 'password' => $password, 'timeout' => 20,
    ]);
    $client->connect();
    return $client;
}
function getFolder(Client $client, string $name): Folder {
    $folder = $client->getFolderByPath($name);
    if (!$folder || $folder->no_select) { fail(404, 'folder_not_found', 'Ordner nicht gefunden oder nicht auswählbar.'); }
    return $folder;
}
function folderName(Folder $f): string { return mb_convert_encoding($f->path, 'UTF-8', 'UTF7-IMAP'); }
function imapConnection(Client $client): ImapProtocol {
    $connection = $client->getConnection();
    if (!$connection instanceof ImapProtocol) {
        fail(503, 'configuration_error', 'Webklex-IMAP-Protokollzugriff ist erforderlich.');
    }
    return $connection;
}
function validateFolderName(string $name): string {
    if ($name === '' || strlen($name) > 1024 || !mb_check_encoding($name, 'UTF-8') || trim($name) !== $name
        || preg_match('/[\p{C}\\\\*%"]|^#|^\/|\/$|\/\//u', $name)) {
        fail(400, 'invalid_parameter', 'Ungültiger Ordnerpfad.');
    }
    foreach (explode('/', $name) as $part) {
        if ($part === '.' || $part === '..' || trim($part) !== $part) { fail(400, 'invalid_parameter', 'Ungültiger Ordnerpfad.'); }
    }
    return $name;
}
/** @return array{folder: string, created: bool} */
function createMailFolder(Client $client, string $name): array {
    validateFolderName($name);
    $connection = imapConnection($client);
    $roots = $connection->folders('', '')->validatedData();
    if (!isset($roots['']) || !array_key_exists('delimiter', $roots[''])) {
        fail(502, 'folder_create_failed', 'Ordnertrennzeichen konnte nicht ermittelt werden.');
    }
    $delimiter = $roots['']['delimiter'];
    // Accept '/' as portable hierarchy notation, or the server's actual separator.
    if ($delimiter === null || $delimiter === '') {
        if (str_contains($name, '/')) { fail(400, 'invalid_parameter', 'Mailserver unterstützt keine Unterordner.'); }
    } elseif (is_string($delimiter)) {
        if ($delimiter !== '/' && str_contains($name, '/')) {
            if (str_contains($name, $delimiter)) { fail(400, 'invalid_parameter', 'Gemischte Ordnertrennzeichen sind unzulässig.'); }
            $name = str_replace('/', $delimiter, $name);
        }
        foreach (explode($delimiter, $name) as $part) {
            if ($part === '' || $part === '.' || $part === '..' || trim($part) !== $part) {
                fail(400, 'invalid_parameter', 'Ungültige Ordnertrennzeichen.');
            }
        }
    } else { fail(502, 'folder_create_failed', 'Ungültiges Ordnertrennzeichen des Mailservers.'); }
    $wireName = mb_convert_encoding($name, 'UTF7-IMAP', 'UTF-8');
    $created = false;
    if (!$client->getFolderByPath($name)) {
        try {
            $connection->createFolder($wireName)->validatedData();
            $created = true;
        } catch (\Webklex\PHPIMAP\Exceptions\ImapServerErrorException) {
            // A concurrent caller may have created the folder after our LIST.
            $current = $connection->folders('', $wireName)->validatedData();
            if (!isset($current[$wireName])) { fail(502, 'folder_create_failed', 'Ordner konnte nicht angelegt werden.'); }
        }
    }
    try { $connection->subscribeFolder($wireName)->validatedData(); }
    catch (Throwable) { fail(502, 'folder_subscribe_failed', 'Ordner vorhanden, Abonnieren fehlgeschlagen. Erneuter Aufruf ist möglich.'); }
    return ['folder' => $name, 'created' => $created];
}
/** @param array<string, mixed> $p
 *  @param array<string, mixed> $c
 */
function sentFolder(array $p, array $c): ?string {
    $value = array_key_exists('sent_folder', $p) ? $p['sent_folder'] : ($c['sent_folder'] ?? 'Sent');
    if ($value === null || $value === '') { return null; }
    if (!is_string($value)) { fail(400, 'invalid_parameter', 'Ungültiger Parameter: sent_folder.'); }
    return validateFolderName($value);
}
/** @param array<string, mixed> $c */
function autoCreateSentFolder(array $c): bool {
    $value = $c['create_sent_folder_if_missing'] ?? true;
    if (!is_bool($value)) { fail(503, 'configuration_error', 'create_sent_folder_if_missing muss ein boolescher Wert sein.'); }
    return $value;
}
/** @param array<string, mixed> $c */
function prepareSentFolder(Client $client, string $folder, array $c): Folder {
    $existing = $client->getFolderByPath($folder);
    if ($existing && !$existing->no_select) { return $existing; }
    if (!$existing && autoCreateSentFolder($c) && $folder === ($c['sent_folder'] ?? 'Sent')) {
        try {
            $created = createMailFolder($client, $folder);
            return getFolder($client, $created['folder']);
        } catch (Throwable) {
            fail(502, 'sent_folder_prepare_failed', 'Gesendet-Ordner konnte nicht vorbereitet werden; nichts versendet.');
        }
    }
    fail(404, 'sent_folder_not_found', 'Gesendet-Ordner fehlt oder ist nicht auswählbar; nichts versendet.');
}
/**
 * @param callable(string, string): void $saveCopy
 * @return array<string, mixed>
 */
function deliverMessage(PHPMailer $mail, ?string $folder, callable $saveCopy): array {
    $smtp = $mail->getSMTPInstance();
    if (!$smtp instanceof TrackedSMTP) { fail(503, 'configuration_error', 'SMTP-Statusprüfung nicht verfügbar.'); }
    $sendError = false;
    try { $sendError = !$mail->postSend(); }
    catch (Throwable) { $sendError = true; }
    if (!$smtp->accepted) {
        $code = (int)($smtp->getError()['smtp_code'] ?? 0);
        if (in_array($code, [534, 535], true)) { fail(403, 'mail_auth_failed', 'Mail-Anmeldung fehlgeschlagen; nichts versendet.'); }
        if ($smtp->dataStarted && $smtp->dataFailureCode < 400) {
            fail(502, 'smtp_status_unknown', 'SMTP-Bestätigung fehlt; Zustellstatus unklar. Vor erneutem Versand prüfen.');
        }
        fail(502, 'smtp_failed', 'SMTP hat die Nachricht nicht angenommen; nichts versendet.');
    }
    $result = ['sent' => true, 'message_id' => $mail->getLastMessageID(), 'saved_to_sent' => false];
    if ($sendError) { $result['smtp_warning'] = 'SMTP hat die Nachricht angenommen; weitere Empfänger- oder Abschlussfehler. Nicht erneut senden.'; }
    if ($folder !== null) {
        try {
            $saveCopy($folder, $mail->getSentMIMEMessage());
            $result['saved_to_sent'] = true;
        } catch (ApiError $e) {
            $result['sent_folder_error'] = $e->errorCode === 'folder_not_found' ? 'Ordner nicht gefunden' : 'Ablage im Gesendet-Ordner fehlgeschlagen';
        } catch (Throwable) { $result['sent_folder_error'] = 'Ablage im Gesendet-Ordner fehlgeschlagen'; }
        if (!$result['saved_to_sent']) { $result['warning'] = 'sent_copy_failed'; }
    }
    return $result;
}
function loadMessage(Client $client, Folder $folder, int $uid, int $maxBytes, bool $body): Message {
    $client->openFolder($folder->path);
    $sizes = $client->getConnection()->sizes([$uid])->validatedData();
    if (!isset($sizes[$uid])) { fail(404, 'message_not_found', 'Nachricht nicht gefunden.'); }
    if ($body && $sizes[$uid] > $maxBytes) { fail(413, 'message_too_large', 'Nachricht überschreitet die Größenbegrenzung.'); }
    $connection = imapConnection($client);
    $headers = $connection->headers([$uid])->validatedData();
    $flags = $connection->flags([$uid])->validatedData();
    if (!isset($headers[$uid])) { fail(404, 'message_not_found', 'Nachricht nicht gefunden.'); }
    $text = '';
    if ($body) {
        // Multiple fetch items let Webklex parse the server's BODY[TEXT] response
        // to BODY.PEEK[TEXT]. No temporary Seen flag changes, even with concurrent clients.
        $parts = $connection->fetch(['UID', 'BODY.PEEK[TEXT]'], [$uid])->validatedData();
        if (!isset($parts[$uid]['BODY[TEXT]'])) { fail(502, 'fetch_failed', 'Nachricht konnte nicht gelesen werden.'); }
        $text = $parts[$uid]['BODY[TEXT]'];
    }
    $m = Message::fromString(rtrim($headers[$uid], "\r\n") . "\r\n\r\n" . $text, $client->getConfig());
    $m->setFolderPath($folder->path);
    $m->setClient($client);
    $m->setEvents(['message' => $client->getDefaultEvents('message'), 'flag' => $client->getDefaultEvents('flag')]);
    $m->setSequence(\Webklex\PHPIMAP\IMAP::ST_UID);
    $m->setUid($uid);
    $m->size = (int)$sizes[$uid];
    $m->parseRawFlags($flags[$uid] ?? []);
    return $m;
}
/** @return list<array{index: int, name: string, type: string, size: int, content_id: string|null, disposition: string|null, content_base64?: string}> */
function attachments(Message $m, bool $content = false): array {
    $out = [];
    foreach ($m->getAttachments() as $a) {
        $item = ['index' => count($out), 'name' => $a->name ?: $a->filename ?: 'attachment',
            'type' => $a->content_type ?: 'application/octet-stream', 'size' => strlen($a->content),
            'content_id' => $a->id, 'disposition' => $a->disposition];
        if ($content) { $item['content_base64'] = base64_encode($a->content); }
        $out[] = $item;
    }
    return $out;
}
/** @return array<string, mixed> */
function summary(Message $m, bool $bodyLoaded = true): array {
    $addresses = static function ($attr): array {
        $out = [];
        foreach ($attr->all() as $a) { $out[] = ['email' => $a->mail, 'name' => $a->personal ?? '']; }
        return $out;
    };
    return ['uid' => (int)$m->getUid(), 'date' => (string)$m->getDate(),
        'from' => $addresses($m->getFrom()), 'to' => $addresses($m->getTo()), 'cc' => $addresses($m->getCc()),
        'subject' => (string)$m->getSubject(), 'seen' => $m->hasFlag('Seen'),
        'flagged' => $m->hasFlag('Flagged'), 'size' => (int)$m->getSize(),
        'attachment_count' => $bodyLoaded ? $m->getAttachments()->count() : null];
}
/**
 * @param array<string, mixed> $c
 * @return array{messages: list<array<string, mixed>>, truncated: bool}
 */
function listMessages(Client $client, Folder $folder, int $limit, string $since, bool $unseen, array $c): array {
    $query = $folder->query()->all();
    if ($since !== '') { $query->since($since); }
    if ($unseen) { $query->unseen(); }
    $uids = $query->search()->all();
    rsort($uids, SORT_NUMERIC);
    $uids = array_slice($uids, 0, $limit);
    $out = []; $total = 0; $truncated = false;
    foreach ($uids as $uid) {
        $m = loadMessage($client, $folder, (int)$uid, $c['max_message_bytes'], false);
        $size = (int)$m->getSize();
        $tooLarge = $size > $c['max_message_bytes'];
        $bodyLoaded = !$tooLarge && $size <= $c['max_list_bytes'] - $total;
        if ($bodyLoaded) {
            $m = loadMessage($client, $folder, (int)$uid, $c['max_message_bytes'], true);
            $total += $size;
        } else { $truncated = true; }
        $out[] = summary($m, $bodyLoaded) + ['too_large' => $tooLarge, 'body_loaded' => $bodyLoaded];
    }
    // Size limits restrict MIME enrichment, never the visibility of subsequent headers.
    return ['messages' => $out, 'truncated' => $truncated];
}
/**
 * @param array<string, mixed> $p
 * @return list<string>
 */
function recipients(array $p, string $field, bool $required = false): array {
    $list = $p[$field] ?? [];
    if (is_string($list)) { $list = [$list]; }
    if (!is_array($list) || !array_is_list($list) || count($list) > 50 || ($required && !$list)) {
        fail(400, 'invalid_parameter', "Ungültiger Parameter: $field.");
    }
    foreach ($list as $email) {
        if (!is_string($email) || strlen($email) > 254 || !filter_var($email, FILTER_VALIDATE_EMAIL)
            || preg_match('/[\r\n]/', $email)) { fail(400, 'invalid_parameter', "Ungültiger Parameter: $field."); }
    }
    return $list;
}
/**
 * @param array<string, mixed> $p
 * @param array<string, mixed> $c
 */
function buildMail(array $p, array $c, string $user, #[SensitiveParameter] string $password): PHPMailer {
    $transport = mailTransport($c);
    $mail = new PHPMailer(true);
    $mail->setSMTPInstance(new TrackedSMTP());
    $mail->isSMTP();
    $mail->Host = $transport['host'];
    $mail->SMTPOptions = ['ssl' => $transport['ssl']];
    $mail->Port = $c['smtp_port'];
    $mail->SMTPSecure = $mail->Port === 465 ? PHPMailer::ENCRYPTION_SMTPS : PHPMailer::ENCRYPTION_STARTTLS;
    $mail->SMTPAuth = true;
    $mail->SMTPDebug = 0;
    $mail->Timeout = 20;
    $mail->Username = $user;
    $mail->Password = $password;
    $mail->CharSet = 'UTF-8';
    $mail->setFrom($user);
    foreach (['to' => 'addAddress', 'cc' => 'addCC', 'bcc' => 'addBCC', 'reply_to' => 'addReplyTo'] as $field => $method) {
        foreach (recipients($p, $field, $field === 'to') as $email) { $mail->$method($email); }
    }
    $mail->Subject = lineparam($p, 'subject', null, 998);
    $text = strparam($p, 'text', null, $c['max_message_bytes']);
    if (isset($p['html'])) {
        $mail->isHTML(true);
        $mail->Body = strparam($p, 'html', null, $c['max_message_bytes']);
        $mail->AltBody = $text;
    } else { $mail->Body = $text; }
    $mail->AllowEmpty = true;
    foreach (['in_reply_to' => 'In-Reply-To', 'references' => 'References'] as $field => $header) {
        if (isset($p[$field])) {
            $v = lineparam($p, $field, null, 4096);
            if (!preg_match('/^<[^<>\s@]+@[^<>\s@]+>(?: +<[^<>\s@]+@[^<>\s@]+>)*$/D', $v)
                || ($field === 'in_reply_to' && str_contains($v, ' '))) {
                fail(400, 'invalid_parameter', "Ungültiger Parameter: $field.");
            }
            $mail->addCustomHeader($header, $v);
        }
    }
    $items = $p['attachments'] ?? [];
    if (!is_array($items) || !array_is_list($items) || count($items) > 20) { fail(400, 'invalid_parameter', 'Ungültige Anhänge.'); }
    $total = strlen($mail->Body) + strlen($mail->AltBody);
    foreach ($items as $a) {
        if (!is_array($a)) { fail(400, 'invalid_parameter', 'Ungültiger Anhang.'); }
        $name = lineparam($a, 'name', null, 255);
        if ($name === '' || strpbrk($name, '/\\') !== false) { fail(400, 'invalid_parameter', 'Ungültiger Anhangname.'); }
        $type = lineparam($a, 'type', 'application/octet-stream', 127);
        if (!preg_match('~^[a-zA-Z0-9!#$&^_.+-]+/[a-zA-Z0-9!#$&^_.+-]+$~D', $type)) { fail(400, 'invalid_parameter', 'Ungültiger MIME-Typ.'); }
        $encoded = strparam($a, 'content_base64', null, $c['max_request_bytes']);
        $data = base64_decode($encoded, true);
        if ($data === false || base64_encode($data) !== $encoded) { fail(400, 'invalid_parameter', 'Ungültiges Base64.'); }
        $total += strlen($data);
        if ($total > $c['max_message_bytes']) { fail(413, 'message_too_large', 'Nachricht zu groß.'); }
        $mail->addStringAttachment($data, $name, 'base64', $type);
    }
    $mail->preSend();
    if (strlen($mail->getSentMIMEMessage()) > $c['max_message_bytes']) { fail(413, 'message_too_large', 'Nachricht zu groß.'); }
    return $mail;
}
/**
 * @param array<string, mixed> $p
 * @param array<string, mixed> $c
 * @return array<string, mixed>
 */
function dispatch(array $p, array $c, string $user, #[SensitiveParameter] string $password): array {
    $action = lineparam($p, 'action', null, 32);
    if (!in_array($action, ['folders', 'create_folder', 'list', 'get', 'attachment', 'send', 'flag'], true)) { fail(400, 'invalid_action', 'Unbekannte Aktion.'); }
    $name = lineparam($p, 'folder', $action === 'create_folder' ? null : 'INBOX');
    if ($action === 'create_folder') { validateFolderName($name); }
    $uid = in_array($action, ['get', 'attachment', 'flag'], true) ? intparam($p, 'uid', 1, 4294967295) : 0;
    $limit = $action === 'list' ? intparam($p, 'limit', 1, 100, 20) : 0;
    $since = $action === 'list' ? lineparam($p, 'since', '') : '';
    if ($since !== '') {
        $date = DateTimeImmutable::createFromFormat('!Y-m-d', $since);
        if (!$date || $date->format('Y-m-d') !== $since) { fail(400, 'invalid_parameter', 'since muss YYYY-MM-DD sein.'); }
    }
    $unseen = boolparam($p, 'unseen_only');
    $mark = boolparam($p, 'mark_seen');
    $index = $action === 'attachment' ? intparam($p, 'index', 0, 10000) : 0;
    if ($action === 'flag') {
        foreach (['seen', 'flagged'] as $field) { boolparam($p, $field); }
        if (!isset($p['seen']) && !isset($p['flagged']) && !isset($p['move_to'])) { fail(400, 'invalid_parameter', 'Keine Änderung angegeben.'); }
        if (isset($p['move_to'])) { lineparam($p, 'move_to'); }
    }
    $mail = $action === 'send' ? buildMail($p, $c, $user, $password) : null;
    if ($mail !== null) {
        $sentFolder = sentFolder($p, $c);
        $client = null;
        try {
            $preparedFolder = null;
            if ($sentFolder !== null) {
                $client = connectMailbox($c, $user, $password);
                $preparedFolder = prepareSentFolder($client, $sentFolder, $c);
            }
            return deliverMessage($mail, $sentFolder, static function (string $folder, string $mime) use ($preparedFolder): void {
                if ($preparedFolder === null) { fail(503, 'configuration_error', 'Gesendet-Ordner nicht vorbereitet.'); }
                $preparedFolder->appendMessage($mime, ['\\Seen']);
            });
        } finally {
            if ($client !== null) { try { $client->disconnect(); } catch (Throwable) { /* Keep accepted SMTP result. */ } }
        }
    }
    $client = connectMailbox($c, $user, $password);
    try {
        if ($action === 'folders') {
            $out = [];
            foreach ($client->getFolders(false) as $f) { $out[] = ['path' => folderName($f), 'name' => $f->name, 'selectable' => !$f->no_select]; }
            return ['folders' => $out];
        }
        if ($action === 'create_folder') { return createMailFolder($client, $name); }
        $folder = getFolder($client, $name);
        if ($action === 'list') {
            return ['folder' => $name] + listMessages($client, $folder, $limit, $since, $unseen, $c);
        }
        $m = loadMessage($client, $folder, $uid, $c['max_message_bytes'], $action !== 'flag');
        if ($action === 'get') {
            if ($mark && !$m->setFlag('Seen')) { fail(502, 'flag_failed', 'Markierung fehlgeschlagen.'); }
            return summary($m) + ['headers' => $m->getHeader()->raw, 'text' => $m->getTextBody(),
                'html' => $m->getHTMLBody(), 'attachments' => attachments($m)];
        }
        if ($action === 'attachment') {
            $items = attachments($m, true);
            if (!isset($items[$index])) { fail(404, 'attachment_not_found', 'Anhang nicht gefunden.'); }
            return $items[$index];
        }
        $target = isset($p['move_to']) ? getFolder($client, $p['move_to']) : null;
        if ($target && $target->path === $folder->path) { fail(400, 'invalid_parameter', 'Zielordner entspricht dem Quellordner.'); }
        if ($target) {
            $capabilities = $client->getConnection()->getCapabilities()->validatedData();
            if (!in_array('MOVE', array_map('strtoupper', $capabilities), true)) {
                fail(409, 'move_unsupported', 'Mailserver unterstützt sicheres UID MOVE nicht.');
            }
        }
        foreach (['seen' => 'Seen', 'flagged' => 'Flagged'] as $field => $flag) {
            if (array_key_exists($field, $p)) {
                $ok = $p[$field] ? $m->setFlag($flag) : $m->unsetFlag($flag);
                if (!$ok) { fail(502, 'flag_failed', 'Markierung fehlgeschlagen; Zustand vor Wiederholung prüfen.'); }
            }
        }
        if ($target) {
            $client->openFolder($folder->path);
            $connection = imapConnection($client);
            // Do not use Webklex move(): its fallback can expunge unrelated deleted mail.
            $response = $connection->requestAndResponse('UID MOVE', [(string)$uid, $connection->escapeString($target->path)], true);
            if (!$response->boolean()) { fail(502, 'move_failed', 'Verschieben fehlgeschlagen; Zustand vor Wiederholung prüfen.'); }
        }
        return ['updated' => true, 'moved_to' => $target ? folderName($target) : null];
    } finally {
        try { $client->disconnect(); } catch (Throwable) { /* Never expose library errors. */ }
    }
}
function main(): void {
    umask(0077);
    try {
        // Forwarded headers are intentionally not trusted. TLS terminator must set HTTPS on the server.
        if (!in_array(strtolower((string)($_SERVER['HTTPS'] ?? '')), ['on', '1'], true)) { fail(426, 'https_required', 'HTTPS erforderlich.'); }
        header('Strict-Transport-Security: max-age=31536000');
        if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') { header('Allow: POST'); fail(405, 'method_not_allowed', 'Nur POST erlaubt.'); }
        $c = config();
        authenticate($c, $_SERVER);
        if (strtolower(trim(explode(';', $_SERVER['CONTENT_TYPE'] ?? '')[0])) !== 'application/json') { fail(415, 'json_required', 'Content-Type application/json erforderlich.'); }
        if ((int)($_SERVER['CONTENT_LENGTH'] ?? 0) > $c['max_request_bytes']) { fail(413, 'request_too_large', 'Anfrage zu groß.'); }
        $raw = file_get_contents('php://input', false, null, 0, $c['max_request_bytes'] + 1);
        if ($raw === false || strlen($raw) > $c['max_request_bytes']) { fail(413, 'request_too_large', 'Anfrage zu groß.'); }
        try { $object = json_decode($raw, false, 32, JSON_THROW_ON_ERROR); }
        catch (JsonException) { fail(400, 'invalid_json', 'Ungültiges JSON.'); }
        if (!$object instanceof stdClass) { fail(400, 'invalid_json', 'JSON-Objekt erforderlich.'); }
        $p = json_decode($raw, true, 32, JSON_THROW_ON_ERROR);
        $user = $_SERVER['HTTP_X_MAIL_USER'] ?? '';
        $password = $_SERVER['HTTP_X_MAIL_PASSWORD'] ?? '';
        if (strlen($user) > 254 || !allowedMailbox($user, $c['allowed_mailboxes'])) { fail(403, 'mailbox_forbidden', 'Postfach nicht erlaubt.'); }
        if ($password === '' || strlen($password) > 4096 || preg_match('/[\r\n\x00]/', $password)) { fail(403, 'mail_auth_failed', 'Mail-Anmeldung fehlgeschlagen.'); }
        respond(200, ['ok' => true, 'data' => mailAuthentication($c, $user, static fn() => dispatch($p, $c, $user, $password))]);
    } catch (ApiError $e) { respond($e->status, ['ok' => false, 'error' => ['code' => $e->errorCode, 'message' => $e->getMessage()]]); }
    catch (\Webklex\PHPIMAP\Exceptions\AuthFailedException) { respond(403, ['ok' => false, 'error' => ['code' => 'mail_auth_failed', 'message' => 'Mail-Anmeldung fehlgeschlagen.']]); }
    catch (\Webklex\PHPIMAP\Exceptions\MessageNotFoundException) { respond(404, ['ok' => false, 'error' => ['code' => 'message_not_found', 'message' => 'Nachricht nicht gefunden.']]); }
    catch (Throwable) { respond(502, ['ok' => false, 'error' => ['code' => 'upstream_error', 'message' => 'Maildienst oder Serverkonfiguration derzeit nicht verfügbar.']]); }
}
if (!defined('IMAPI_TEST')) { main(); }
