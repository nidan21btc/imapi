<?php
// Actual PHPMailer SMTP dialogue against a loopback-only fixture; no real mail.
declare(strict_types=1);
define('IMAPI_TEST', true);
require __DIR__ . '/../public/index.php';
ini_set('display_errors', '1');
if (!function_exists('pcntl_fork')) { throw new RuntimeException('CLI pcntl is required.'); }
$socket = stream_socket_server('tcp://127.0.0.1:0', $errno, $error);
if (!$socket) { throw new RuntimeException('Could not start SMTP fixture.'); }
$port = (int)substr(strrchr(stream_socket_get_name($socket, false), ':'), 1);
$pid = pcntl_fork();
if ($pid === -1) { throw new RuntimeException('Could not fork fixture.'); }
if ($pid === 0) {
    foreach (['ok', 'ok', 'ok', 'ok', 'reject', 'partial', 'data_reject', 'lost_ack'] as $mode) {
        $peer = stream_socket_accept($socket, 15);
        if (!$peer) { exit(2); }
        stream_set_timeout($peer, 10);
        fwrite($peer, "220 fixture ESMTP ready\r\n");
        $recipients = 0;
        while (($line = fgets($peer)) !== false) {
            if (str_starts_with($line, 'EHLO ')) { fwrite($peer, "250-fixture\r\n250 SIZE 1000000\r\n"); }
            elseif (str_starts_with($line, 'MAIL FROM:')) { fwrite($peer, "250 sender accepted\r\n"); }
            elseif (str_starts_with($line, 'RCPT TO:')) {
                $recipients++;
                fwrite($peer, $mode === 'reject' || ($mode === 'partial' && $recipients === 2)
                    ? "550 recipient rejected\r\n" : "250 recipient accepted\r\n");
            } elseif ($line === "DATA\r\n") {
                fwrite($peer, "354 send message\r\n");
                while (($data = fgets($peer)) !== false && $data !== ".\r\n") { /* Discard fixture MIME. */ }
                if ($mode === 'lost_ack') { break; }
                fwrite($peer, $mode === 'data_reject' ? "550 message rejected\r\n" : "250 queued as fixture\r\n");
            } elseif ($line === "QUIT\r\n") { fwrite($peer, "221 goodbye\r\n"); break; }
            else { exit(3); } // No AUTH, STARTTLS or unexpected destinations in this fixture.
        }
        fclose($peer);
    }
    fclose($socket);
    exit(0);
}
fclose($socket);
$c = require __DIR__ . '/../config.example.php';
$c['allowed_recipient_domains'] = ['example.org'];
$request = ['to' => ['recipient@example.org', 'second@example.org'], 'subject' => 'Fixture', 'text' => 'Fixture body'];
/** @param array<string, mixed> $c
 *  @param array<string, mixed> $request
 */
function fixtureMailer(array $request, array $c, int $port): \PHPMailer\PHPMailer\PHPMailer {
    $mail = buildMail($request, $c, 'fixture@sann.gmbh', 'fixture-only');
    // Override transport only inside this test. No equivalent client API parameters exist.
    $mail->Host = '127.0.0.1'; $mail->Port = $port;
    $mail->SMTPAuth = false; $mail->SMTPAutoTLS = false; $mail->SMTPSecure = '';
    $mail->Timeout = 5;
    return $mail;
}
function ensure(bool $condition, string $message): void { if (!$condition) { throw new RuntimeException($message); } }
try {
    $mail = fixtureMailer($request, $c, $port);
    $result = deliverMessage($mail, 'Missing', static function (string $folder, string $mime): void {
        fail(404, 'folder_not_found', 'Ordner nicht gefunden.');
    });
    ob_start(); respond(200, ['ok' => true, 'data' => $result]); $json = json_decode((string)ob_get_clean(), true);
    ensure($json['ok'] && $json['data']['sent'] && !$json['data']['saved_to_sent'] && $result['sent_folder_error'] === 'Ordner nicht gefunden', 'Missing folder changed successful SMTP result.');
    ensure($result['message_id'] === $mail->getLastMessageID() && str_starts_with($result['message_id'], '<'), 'Message-ID was not preserved.');

    $result = deliverMessage(fixtureMailer($request, $c, $port), 'Sent', static function (): void { throw new RuntimeException('secret fixture upstream error'); });
    ensure($result['sent'] && !$result['saved_to_sent'] && !str_contains(json_encode($result, JSON_THROW_ON_ERROR), 'secret fixture'), 'APPEND failure was not isolated or sanitized.');

    $saved = false;
    $mail = fixtureMailer($request, $c, $port);
    $result = deliverMessage($mail, 'Sent', static function (string $folder, string $mime) use (&$saved, $mail): void {
        ensure($folder === 'Sent' && $mime === $mail->getSentMIMEMessage(), 'Wrong folder or MIME saved.');
        $saved = true;
    });
    ensure($saved && $result['saved_to_sent'] && !isset($result['sent_folder_error']), 'Successful save failed.');

    $unexpectedSave = static function (): void { throw new RuntimeException('Save callback must not run.'); };
    $result = deliverMessage(fixtureMailer($request, $c, $port), null, $unexpectedSave);
    ensure($result['sent'] && !$result['saved_to_sent'] && !isset($result['sent_folder_error']), 'Skipped save must have no error.');

    try { deliverMessage(fixtureMailer($request, $c, $port), 'Sent', $unexpectedSave); throw new RuntimeException('Rejected SMTP send accepted.'); }
    catch (ApiError $e) { ensure($e->errorCode === 'smtp_failed' && $e->status === 502, 'Wrong SMTP rejection error.'); }

    $result = deliverMessage(fixtureMailer($request, $c, $port), null, $unexpectedSave);
    ensure($result['sent'] && isset($result['smtp_warning']), 'Partial recipient rejection hid accepted SMTP DATA.');

    try { deliverMessage(fixtureMailer($request, $c, $port), 'Sent', $unexpectedSave); throw new RuntimeException('Rejected DATA accepted.'); }
    catch (ApiError $e) { ensure($e->errorCode === 'smtp_failed', 'Wrong DATA rejection status.'); }

    try { deliverMessage(fixtureMailer($request, $c, $port), null, $unexpectedSave); throw new RuntimeException('Missing SMTP confirmation accepted.'); }
    catch (ApiError $e) { ensure($e->errorCode === 'smtp_status_unknown', 'Missing SMTP confirmation must not claim nothing was sent.'); }

    pcntl_waitpid($pid, $status);
    ensure(pcntl_wifexited($status) && pcntl_wexitstatus($status) === 0, 'SMTP fixture failed.');
    echo "SMTP wire fixture passed: missing sent folder, APPEND failure, skipped save, SMTP rejection, partial recipients and lost confirmation.\n";
} catch (Throwable $e) {
    posix_kill($pid, SIGTERM); pcntl_waitpid($pid, $status); throw $e;
}
