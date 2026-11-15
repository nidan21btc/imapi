<?php
declare(strict_types=1);
define('IMAPI_TEST', true);
require __DIR__ . '/../public/index.php';
ini_set('display_errors', '1');
$checks = 0;
function verify(bool $ok, string $message): void {
    global $checks;
    if (!$ok) { throw new RuntimeException($message); }
    $checks++;
}
function expectError(callable $operation, int $status, string $code): void {
    try { $operation(); }
    catch (ApiError $e) { verify($e->status === $status && $e->errorCode === $code, 'Unexpected security error.'); return; }
    throw new RuntimeException('Expected security rejection.');
}
/** @param array<string, mixed> $base
 *  @return array<string, mixed>
 */
function securityConfig(array $base, string $parent, string $name): array {
    $dir = $parent . '/' . $name;
    mkdir($dir, 0700);
    return array_replace($base, ['state_dir' => $dir]);
}
/** @return list<string> */
function stateFiles(string $dir): array { return glob($dir . '/*.json') ?: []; }
$root = sys_get_temp_dir() . '/imapi-security-' . bin2hex(random_bytes(6));
mkdir($root, 0700);
$base = require __DIR__ . '/../config.example.php';
$token = bin2hex(random_bytes(32));
$base['api_key_hash'] = password_hash($token, PASSWORD_BCRYPT);
try {
    verify(clientNetwork('2001:db8:1234:abcd::1') === clientNetwork('2001:db8:1234:abcd:ffff::9'), 'IPv6 /64 not normalized.');
    verify(clientNetwork('2001:db8:1234:abce::1') !== clientNetwork('2001:db8:1234:abcd::1'), 'Distinct IPv6 networks merged.');
    verify(clientNetwork('::ffff:192.0.2.1') === clientNetwork('192.0.2.1'), 'Mapped IPv4 bypassed IP limit.');
    $c = securityConfig($base, $root, 'ipv6');
    for ($i = 1; $i <= 400; $i++) {
        $server = ['REMOTE_ADDR' => '2001:db8:1234:abcd::' . dechex($i)];
        expectError(fn() => authenticate($c, $server), $i <= 5 ? 401 : 429, $i <= 5 ? 'unauthorized' : 'rate_limited');
    }
    $files = stateFiles($c['state_dir']);
    verify(count($files) === 1 && count(json_decode(file_get_contents($files[0]), true)) === 1, 'IPv6 identities created unbounded files or records.');

    $c = securityConfig($base, $root, 'expiry');
    $ip = '192.0.2.50';
    $key = hash('sha256', clientNetwork($ip));
    limiterUpdate($c, 'ip', $key, static function (array &$state): void { $state = ['blocked' => 0]; });
    $file = stateFiles($c['state_dir'])[0];
    $records = json_decode(file_get_contents($file), true);
    $records['expired-record'] = ['expires' => time() - 1];
    file_put_contents($file, json_encode($records, JSON_THROW_ON_ERROR));
    expectError(fn() => authenticate($c, ['REMOTE_ADDR' => $ip]), 401, 'unauthorized');
    verify(!isset(json_decode(file_get_contents($file), true)['expired-record']), 'Invalid Bearer skipped cleanup.');
    $records = json_decode(file_get_contents($file), true);
    $records['expired-on-429'] = ['expires' => time() - 1];
    $records[$key]['blocked'] = time() + 600;
    file_put_contents($file, json_encode($records, JSON_THROW_ON_ERROR));
    expectError(fn() => authenticate($c, ['REMOTE_ADDR' => $ip]), 429, 'rate_limited');
    verify(!isset(json_decode(file_get_contents($file), true)['expired-on-429']), 'Rate-limited request skipped cleanup.');

    $c = securityConfig($base, $root, 'lock-busy');
    $ip = '192.0.2.51';
    expectError(fn() => authenticate($c, ['REMOTE_ADDR' => $ip]), 401, 'unauthorized');
    $handle = fopen(stateFiles($c['state_dir'])[0], 'r+');
    if (!$handle || !flock($handle, LOCK_EX)) { throw new RuntimeException('Could not hold fixture lock.'); }
    $started = microtime(true);
    try { expectError(fn() => authenticate($c, ['REMOTE_ADDR' => $ip]), 503, 'rate_limit_unavailable'); }
    finally { flock($handle, LOCK_UN); fclose($handle); }
    verify(microtime(true) - $started < 2, 'Busy lock indefinitely occupied request worker.');

    $c = securityConfig($base, $root, 'capacity');
    $identities = [];
    for ($i = 0; count($identities) < 129; $i++) {
        $ip = inet_ntop(pack('N', 0xc6120000 + $i));
        $id = hash('sha256', clientNetwork($ip));
        if (hexdec(substr(hash('sha256', $id), 0, 2)) % 64 === 0) { $identities[] = $ip; }
    }
    foreach ($identities as $i => $ip) {
        expectError(fn() => authenticate($c, ['REMOTE_ADDR' => $ip]), $i < 128 ? 401 : 503, $i < 128 ? 'unauthorized' : 'rate_limit_capacity');
    }
    $files = stateFiles($c['state_dir']);
    verify(count($files) === 1 && count(json_decode(file_get_contents($files[0]), true)) === 128, 'Capacity grew or an active identity was evicted.');
    // Full unauthenticated storage must not consume authenticated-mail storage.
    $_SERVER['REMOTE_ADDR'] = $identities[128];
    verify(mailAuthentication($c, 'fixture@sann.gmbh', static fn() => ['test' => true])['test'], 'Unauthenticated flood filled mail-auth storage.');

    $c = securityConfig($base, $root, 'files');
    for ($i = 0; $i < 600; $i++) {
        expectError(fn() => authenticate($c, ['REMOTE_ADDR' => (string)inet_ntop(pack('N', 0xc6330000 + $i))]), 401, 'unauthorized');
    }
    verify(count(stateFiles($c['state_dir'])) <= 64, 'More than 64 IP shard files.');

    $c = array_replace(securityConfig($base, $root, 'mail'), ['failed_mail_logins_before_block' => 2, 'failed_mail_logins_per_mailbox' => 3]);
    $_SERVER['REMOTE_ADDR'] = '192.0.2.1';
    $attempts = 0;
    $imapFailure = static function () use (&$attempts): array {
        $attempts++;
        throw new \Webklex\PHPIMAP\Exceptions\AuthFailedException('fixture-only');
    };
    for ($i = 0; $i < 2; $i++) {
        try { mailAuthentication($c, 'fixture@sann.gmbh', $imapFailure); }
        catch (\Webklex\PHPIMAP\Exceptions\AuthFailedException) { /* Counted. */ }
    }
    expectError(fn() => mailAuthentication($c, 'other@sann.gmbh', $imapFailure), 429, 'mail_auth_rate_limited');
    verify($attempts === 2, 'IP block still reached IMAP.');
    $_SERVER['REMOTE_ADDR'] = '192.0.2.2';
    expectError(fn() => mailAuthentication($c, 'FIXTURE@SANN.GMBH', static fn() => fail(403, 'mail_auth_failed', 'SMTP fixture')), 403, 'mail_auth_failed');
    $_SERVER['REMOTE_ADDR'] = '192.0.2.3';
    expectError(fn() => mailAuthentication($c, 'fixture@sann.gmbh', $imapFailure), 429, 'mail_auth_rate_limited');
    verify($attempts === 2, 'Distributed guessing reached blocked mailbox.');
    verify(mailAuthentication($c, 'other@sann.gmbh', static fn() => ['test' => true])['test'], 'Mailbox block affected unrelated user/IP.');

    $c = array_replace(securityConfig($base, $root, 'parallel'), ['failed_mail_logins_before_block' => 1]);
    $_SERVER['REMOTE_ADDR'] = '192.0.2.10';
    $result = mailAuthentication($c, 'fixture@sann.gmbh', static function () use ($c): array {
        expectError(fn() => mailAuthentication($c, 'other@sann.gmbh', static fn() => ['unexpected' => true]), 429, 'mail_auth_rate_limited');
        return ['test' => true];
    });
    verify($result['test'] && mailAuthentication($c, 'fixture@sann.gmbh', static fn() => ['test' => true])['test'], 'Pending reservation was not enforced or released.');

    $c = securityConfig($base, $root, 'after-send');
    $result = mailAuthentication($c, 'fixture@sann.gmbh', static function () use ($c): array {
        foreach (stateFiles($c['state_dir']) as $file) { file_put_contents($file, 'invalid-state-fixture'); }
        return ['sent' => true, 'saved_to_sent' => true];
    });
    verify($result['sent'] && isset($result['security_warning']), 'Limiter failure turned accepted SMTP into failed send.');
    expectError(fn() => mailAuthentication($c, 'fixture@sann.gmbh', static fn() => ['unexpected' => true]), 503, 'rate_limit_unavailable');

    $c = securityConfig($base, $root, 'migration');
    $ip = '192.0.2.70';
    $legacy = $c['state_dir'] . '/' . hash('sha256', $ip) . '.json';
    file_put_contents($legacy, json_encode(['requests' => [time()], 'failures' => [], 'blocked' => time() + 600], JSON_THROW_ON_ERROR));
    $configFile = $c['state_dir'] . '/config.php';
    file_put_contents($configFile, '<?php return ' . var_export($c, true) . ';');
    $oldEnv = getenv('IMAPI_CONFIG');
    putenv('IMAPI_CONFIG=' . $configFile);
    try {
        $process = proc_open([PHP_BINARY, __DIR__ . '/../bin/limiter-migrate.php', $root . '/migration-backup'],
            [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        if (!is_resource($process)) { throw new RuntimeException('Could not start migration.'); }
        stream_get_contents($pipes[1]); stream_get_contents($pipes[2]);
        fclose($pipes[1]); fclose($pipes[2]);
        verify(proc_close($process) === 0 && !is_file($legacy), 'Legacy state migration failed.');
        expectError(fn() => authenticate($c, ['REMOTE_ADDR' => $ip, 'HTTP_AUTHORIZATION' => 'Bearer ' . $token]), 429, 'rate_limited');
    } finally {
        putenv($oldEnv === false ? 'IMAPI_CONFIG' : 'IMAPI_CONFIG=' . $oldEnv);
        unlink($configFile);
    }

    foreach (new DirectoryIterator($root) as $dir) {
        if ($dir->isDot()) { continue; }
        foreach (stateFiles($dir->getPathname()) as $file) {
            $data = file_get_contents($file);
            verify(strlen($data) <= 2 * 1024 * 1024 && !str_contains($data, 'fixture@sann.gmbh') && !str_contains($data, $token), 'State exceeded bounds or stored credentials.');
        }
    }
    echo "$checks security checks passed: IPv6, bounded state, cleanup on 401/429, mail auth bans and in-flight reservations.\n";
} finally {
    foreach (new DirectoryIterator($root) as $dir) {
        if ($dir->isDot()) { continue; }
        foreach (stateFiles($dir->getPathname()) as $file) { unlink($file); }
        rmdir($dir->getPathname());
    }
    rmdir($root);
}
