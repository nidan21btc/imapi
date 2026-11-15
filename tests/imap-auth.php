<?php
declare(strict_types=1);

// Redirect only the test process's library socket to a local protocol server.
// The production connectMailbox() and Webklex LOGIN parser run unchanged.
namespace Webklex\PHPIMAP\Connection\Protocols {
    function stream_socket_client(string $address, ?int &$error_code = null, ?string &$error_message = null,
        ?float $timeout = null, int $flags = STREAM_CLIENT_CONNECT, mixed $context = null): mixed {
        if ($address !== 'ssl://127.0.0.1:993') { throw new \RuntimeException('Unexpected IMAP destination.'); }
        $GLOBALS['fixture_connections']++;
        return \stream_socket_client('tcp://127.0.0.1:' . $GLOBALS['fixture_port'], $error_code, $error_message, 5);
    }
}
namespace {
    define('IMAPI_TEST', true);
    require __DIR__ . '/../public/index.php';
    ini_set('display_errors', '1');
    $socket = stream_socket_server('tcp://127.0.0.1:0', $errno, $error);
    if (!$socket) { throw new RuntimeException('Could not start LOGIN rejection fixture.'); }
    $GLOBALS['fixture_port'] = (int)substr(strrchr(stream_socket_get_name($socket, false), ':'), 1);
    $GLOBALS['fixture_connections'] = 0;
    $pid = pcntl_fork();
    if ($pid === -1) { throw new RuntimeException('Could not fork LOGIN fixture.'); }
    if ($pid === 0) {
        // Five IP failures, five IPv6-/64 failures, ten distributed mailbox failures.
        for ($i = 0; $i < 20; $i++) {
            $peer = stream_socket_accept($socket, 10);
            if (!$peer) { exit(2); }
            stream_set_timeout($peer, 5);
            fwrite($peer, "* OK fixture ready\r\n");
            $login = false;
            while (($line = fgets($peer)) !== false) {
                if (!preg_match('/^(\S+) (.+)\r\n$/', $line, $m)) { exit(3); }
                [$unused, $tag, $command] = $m;
                if (str_starts_with($command, 'LOGIN ')) {
                    if ($login) { exit(4); }
                    $login = true;
                    fwrite($peer, "$tag NO [AUTHENTICATIONFAILED] Authentication failed.\r\n");
                } elseif ($command === 'CAPABILITY') {
                    fwrite($peer, "* CAPABILITY IMAP4rev1\r\n$tag OK completed\r\n");
                } elseif ($command === 'NOOP') { fwrite($peer, "$tag OK completed\r\n"); }
                elseif ($command === 'LOGOUT') {
                    fwrite($peer, "* BYE closing\r\n$tag OK LOGOUT complete\r\n"); break;
                } else { exit(5); }
            }
            fclose($peer);
            if (!$login) { exit(6); }
        }
        fclose($socket); exit(0);
    }
    fclose($socket);
    $dir = sys_get_temp_dir() . '/imapi-login-' . bin2hex(random_bytes(6));
    mkdir($dir, 0700);
    $c = require __DIR__ . '/../config.example.php';
    $c['state_dir'] = $dir;
    $token = bin2hex(random_bytes(32));
    $c['api_key_hash'] = password_hash($token, PASSWORD_BCRYPT);
    $c['local_only'] = true;
    try {
        $attempt = static function (string $ip, string $user, int $expected) use ($c, $token): void {
            $_SERVER['REMOTE_ADDR'] = $ip;
            authenticate($c, ['REMOTE_ADDR' => $ip, 'HTTP_AUTHORIZATION' => 'Bearer ' . $token]);
            $before = $GLOBALS['fixture_connections'];
            try {
                mailAuthentication($c, $user, static fn() => ['client' => connectMailbox($c, $user, 'wrong-fixture-password')]);
                throw new RuntimeException('Rejected LOGIN unexpectedly succeeded.');
            } catch (ApiError $e) {
                $code = $expected === 403 ? 'mail_auth_failed' : 'mail_auth_rate_limited';
                if ($e->status !== $expected || $e->errorCode !== $code
                    || $GLOBALS['fixture_connections'] - $before !== ($expected === 403 ? 1 : 0)) {
                    throw new RuntimeException('LOGIN rejection was not mapped/counted or a blocked attempt opened a socket.');
                }
            }
        };
        for ($i = 0; $i < 7; $i++) { $attempt('192.0.2.1', 'ipv4@sann.gmbh', $i < 5 ? 403 : 429); }
        for ($i = 0; $i < 7; $i++) { $attempt('2001:db8:1:2::' . ($i + 1), 'ipv6@sann.gmbh', $i < 5 ? 403 : 429); }
        for ($i = 0; $i < 14; $i++) {
            $attempt('198.51.100.' . ($i + 1), $i % 2 ? 'Distributed@SANN.GMBH' : 'distributed@sann.gmbh', $i < 10 ? 403 : 429);
        }
        pcntl_waitpid($pid, $status);
        if (!pcntl_wifexited($status) || pcntl_wexitstatus($status) !== 0 || $GLOBALS['fixture_connections'] !== 20) {
            throw new RuntimeException('Unexpected LOGIN count or fixture failure.');
        }
        echo "IMAP LOGIN NO fixture passed: 403 mapping, IP/IPv6-/64/mailbox bans; blocked attempts open no sockets.\n";
    } finally {
        if (pcntl_waitpid($pid, $status, WNOHANG) === 0) { posix_kill($pid, SIGTERM); pcntl_waitpid($pid, $status); }
        foreach (glob($dir . '/*') ?: [] as $file) { unlink($file); }
        rmdir($dir);
    }
}
