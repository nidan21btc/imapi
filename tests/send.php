<?php
// Test the unchanged dispatch/build/deliver path with loopback protocol servers.
declare(strict_types=1);
namespace Webklex\PHPIMAP\Connection\Protocols {
    function stream_socket_client(string $address, ?int &$error_code = null, ?string &$error_message = null,
        ?float $timeout = null, int $flags = STREAM_CLIENT_CONNECT, mixed $context = null): mixed {
        return \sendFixtureConnect($address, 'imap');
    }
}
namespace PHPMailer\PHPMailer {
    function stream_socket_client(string $address, ?int &$error_code = null, ?string &$error_message = null,
        ?float $timeout = null, int $flags = STREAM_CLIENT_CONNECT, mixed $context = null): mixed {
        return \sendFixtureConnect($address, 'smtp');
    }
}
namespace {
    define('IMAPI_TEST', true);
    require __DIR__ . '/../public/index.php';
    ini_set('display_errors', '1');
    $GLOBALS['send_sockets'] = [];
    function sendFixtureConnect(string $address, string $protocol): mixed {
        $GLOBALS['send_sockets'][] = $protocol;
        $expected = $protocol === 'imap' ? 'ssl://127.0.0.1:993' : 'ssl://127.0.0.1:465';
        if ($address !== $expected || !isset($GLOBALS['send_ports'][$protocol])) {
            throw new RuntimeException('Unexpected mail connection.');
        }
        return \stream_socket_client('tcp://127.0.0.1:' . $GLOBALS['send_ports'][$protocol], $errno, $error, 5);
    }
    function sendCheck(bool $ok, string $message): void { if (!$ok) { throw new RuntimeException($message); } }
    /** @param array<string, mixed> $p
     *  @param array<string, mixed> $c
     */
    function recipientRejected(array $p, array $c, string $domain): void {
        $before = $GLOBALS['send_sockets'];
        try { dispatch($p, $c, 'fixture@sann.gmbh', 'fixture-only'); throw new RuntimeException('Recipient unexpectedly allowed.'); }
        catch (ApiError $e) {
            sendCheck($e->status === 403 && $e->errorCode === 'recipient_not_allowed', 'Wrong recipient error.');
            sendCheck(str_contains($e->getMessage(), $domain) && !str_contains($e->getMessage(), 'fixture-only'), 'Domain missing or credentials exposed.');
        }
        sendCheck($GLOBALS['send_sockets'] === $before, 'Rejected recipient opened a mail socket.');
    }
    $c = require __DIR__ . '/../config.example.php';
    $c['allowed_recipient_domains'] = ['essenzenladen.de', 'sann.gmbh', 'bücher.de'];
    $c['sent_folder'] = 'INBOX.Gesendet';
    $c['local_only'] = true;
    $p = ['action' => 'send', 'to' => 'recipient@sann.gmbh', 'subject' => 'Fixture', 'text' => 'Fixture body'];
    foreach (['foreign.example', 'mail.sann.gmbh', 'sann.gmbh.evil.com'] as $domain) {
        recipientRejected(array_replace($p, ['to' => 'recipient@' . $domain]), $c, $domain);
    }
    recipientRejected(array_replace($p, ['to' => ['recipient@sann.gmbh', 'other@foreign.example']]), $c, 'foreign.example');
    foreach (['cc', 'bcc', 'reply_to'] as $field) {
        recipientRejected($p + [$field => ['allowed@essenzenladen.de', 'other@foreign.example']], $c, 'foreign.example');
    }
    recipientRejected($p, array_replace($c, ['allowed_recipient_domains' => []]), 'sann.gmbh');
    $missing = $c; unset($missing['allowed_recipient_domains']);
    recipientRejected($p, $missing, 'sann.gmbh');
    buildMail($p + ['cc' => 'copy@ESSENZENLADEN.DE', 'bcc' => ['hidden@sann.gmbh'], 'reply_to' => ['reply@essenzenladen.de']], $c, 'fixture@sann.gmbh', 'fixture-only');
    $override = $c + ['allowed_recipient_domains_by_mailbox' => []];
    $override['allowed_recipient_domains_by_mailbox'] = ['FIXTURE@SANN.GMBH' => ['essenzenladen.de']];
    recipientRejected($p, $override, 'sann.gmbh');
    $override['allowed_recipient_domains_by_mailbox'] = ['fixture@sann.gmbh' => []];
    recipientRejected($p, $override, 'sann.gmbh');
    buildMail($p, array_replace($c, ['allowed_recipient_domains_by_mailbox' => ['other@sann.gmbh' => []]]), 'fixture@sann.gmbh', 'fixture-only');
    $override['allowed_recipient_domains_by_mailbox'] = ['fixture@sann.gmbh' => ['essenzenladen.de']];
    buildMail(array_replace($p, ['to' => 'recipient@essenzenladen.de']), $override, 'fixture@sann.gmbh', 'fixture-only');
    foreach ([['allowed' => 'bücher.de', 'address' => 'recipient@xn--bcher-kva.de'],
        ['allowed' => 'xn--bcher-kva.de', 'address' => 'recipient@BÜCHER.de'],
        ['allowed' => 'SANN.GMBH', 'address' => 'recipient@SANN.GmbH']] as $idn) {
        $mail = buildMail(array_replace($p, ['to' => $idn['address']]), array_replace($c, ['allowed_recipient_domains' => [$idn['allowed']]]), 'fixture@sann.gmbh', 'fixture-only');
        sendCheck($mail->getToAddresses()[0][0] === ($idn['allowed'] === 'SANN.GMBH' ? 'recipient@sann.gmbh' : 'recipient@xn--bcher-kva.de'), 'IDN/case normalization mismatch.');
    }
    recipientRejected(array_replace($p, ['to' => 'recipient@bücher.de']), array_replace($c, ['allowed_recipient_domains' => ['sann.gmbh']]), 'xn--bcher-kva.de');
    sendCheck($GLOBALS['send_sockets'] === [], 'Validation opened a socket.');

    $sockets = []; $pids = [];
    foreach (['imap', 'smtp'] as $protocol) {
        $socket = stream_socket_server('tcp://127.0.0.1:0', $errno, $error);
        if (!$socket) { throw new RuntimeException('Could not start send fixture.'); }
        $sockets[$protocol] = $socket;
        $GLOBALS['send_ports'][$protocol] = (int)substr(strrchr(stream_socket_get_name($socket, false), ':'), 1);
    }
    try {
        foreach (['imap', 'smtp'] as $protocol) {
            $pid = pcntl_fork();
            if ($pid === -1) { throw new RuntimeException('Could not fork send fixture.'); }
            if ($pid === 0) {
                $peer = stream_socket_accept($sockets[$protocol], 15);
                if (!$peer) { exit(2); }
                stream_set_timeout($peer, 10);
                $saved = false; $delivered = false; $auth = false;
                fwrite($peer, $protocol === 'imap' ? "* OK fixture ready\r\n" : "220 fixture ESMTP ready\r\n");
                while (($line = fgets($peer)) !== false) {
                    if ($protocol === 'imap') {
                        if (!preg_match('/^(\S+) (.+)\r\n$/', $line, $m)) { exit(3); }
                        [$unused, $tag, $command] = $m;
                        if (str_starts_with($command, 'LOGIN ') || $command === 'NOOP') { /* OK */ }
                        elseif ($command === 'CAPABILITY') { fwrite($peer, "* CAPABILITY IMAP4rev1\r\n"); }
                        elseif (str_starts_with($command, 'LIST ')) { fwrite($peer, '* LIST (\\HasNoChildren) "." "INBOX.Gesendet"' . "\r\n"); }
                        elseif (preg_match('/^APPEND "INBOX\.Gesendet" .*\{(\d+)\}$/', $command, $literal)) {
                            fwrite($peer, "+ ready\r\n");
                            $bytes = (int)$literal[1]; $mime = '';
                            while (strlen($mime) < $bytes) {
                                $chunk = fread($peer, $bytes - strlen($mime));
                                if ($chunk === false || $chunk === '') { exit(4); }
                                $mime .= $chunk;
                            }
                            if (fread($peer, 2) !== "\r\n" || !str_contains($mime, 'Subject: Fixture') || !str_contains($mime, 'Fixture body')) { exit(5); }
                            $saved = true;
                        } elseif ($command === 'LOGOUT') {
                            fwrite($peer, "* BYE closing\r\n$tag OK complete\r\n"); break;
                        } else { exit(6); } // No CREATE or alternative folder is accepted.
                        fwrite($peer, "$tag OK completed\r\n");
                    } else {
                        if (str_starts_with($line, 'EHLO ')) { fwrite($peer, "250-fixture\r\n250 AUTH PLAIN\r\n"); }
                        elseif (str_starts_with($line, 'AUTH PLAIN')) { fwrite($peer, "334 \r\n"); $auth = true; }
                        elseif ($auth) { fwrite($peer, "235 authentication successful\r\n"); $auth = false; }
                        elseif (str_starts_with($line, 'MAIL FROM:') || str_starts_with($line, 'RCPT TO:')) { fwrite($peer, "250 accepted\r\n"); }
                        elseif ($line === "DATA\r\n") {
                            fwrite($peer, "354 send message\r\n");
                            while (($body = fgets($peer)) !== false && $body !== ".\r\n") { /* Synthetic message only. */ }
                            fwrite($peer, "250 queued\r\n"); $delivered = true;
                        } elseif ($line === "QUIT\r\n") { fwrite($peer, "221 goodbye\r\n"); break; }
                        else { exit(7); }
                    }
                }
                fclose($peer);
                exit(($protocol === 'imap' ? $saved : $delivered) ? 0 : 8);
            }
            $pids[] = $pid;
        }
        foreach ($sockets as $socket) { fclose($socket); }
        $result = dispatch($p, $c, 'fixture@sann.gmbh', 'fixture-only');
        sendCheck($result['sent'] && $result['saved_to_sent'] && !isset($result['sent_folder_error']), 'Default configured INBOX.Gesendet copy failed.');
        sendCheck($GLOBALS['send_sockets'] === ['imap', 'smtp'], 'Unexpected connection order.');
        foreach ($pids as $pid) {
            pcntl_waitpid($pid, $status);
            sendCheck(pcntl_wifexited($status) && pcntl_wexitstatus($status) === 0, 'Send protocol fixture failed.');
        }
        echo "Send policy fixture passed: exact domains, all address fields, fail-closed defaults, per-mailbox overrides, IDN; default INBOX.Gesendet APPEND after SMTP accepted.\n";
    } finally {
        foreach ($pids as $pid) { if (pcntl_waitpid($pid, $status, WNOHANG) === 0) { posix_kill($pid, SIGTERM); pcntl_waitpid($pid, $status); } }
        foreach ($sockets as $socket) { if (is_resource($socket)) { fclose($socket); } }
    }
}
