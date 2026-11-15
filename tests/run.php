<?php
declare(strict_types=1);
define('IMAPI_TEST', true);
require __DIR__ . '/../public/index.php';
ini_set('display_errors', '1');

$passed = 0;
function check(bool $ok, string $label): void {
    global $passed;
    if (!$ok) { throw new RuntimeException("FAILED: $label"); }
    $passed++;
}
function rejects(callable $f, int $status): void {
    try { $f(); } catch (ApiError $e) { check($e->status === $status, "Expected HTTP $status"); return; }
    throw new RuntimeException("Expected HTTP $status");
}

$c = require __DIR__ . '/../config.example.php';
check(allowedMailbox('user@sann.gmbh', $c['allowed_mailboxes']), 'whitelist domain');
check(allowedMailbox('User@SANN.GMBH', $c['allowed_mailboxes']), 'case insensitive domain');
check(!allowedMailbox('user@evil-sann.gmbh', $c['allowed_mailboxes']), 'domain suffix bypass');
check(!allowedMailbox('user@sann.gmbh.evil.test', $c['allowed_mailboxes']), 'domain prefix bypass');
check(!allowedMailbox("user@sann.gmbh\r\nBcc: x@evil.test", []), 'credential header injection');
rejects(fn() => boolparam(['seen' => 'false'], 'seen'), 400);
rejects(fn() => intparam(['uid' => '42'], 'uid', 1, 100), 400);
rejects(fn() => lineparam(['subject' => "Hello\r\nBcc: evil@test.example"], 'subject'), 400);
rejects(fn() => recipients(['to' => ['a@example.com', "b@example.com\r\nX: y"]], 'to'), 400);
check(mailHost($c) === 'cloud3-vm338.de-nserver.de', 'mail host explicitly allowed');
rejects(fn() => mailHost(array_replace($c, ['mail_host' => 'evil.example.org'])), 503);
rejects(fn() => connectMailbox(array_replace($c, ['mail_host' => 'evil.example.org']), 'fixture@sann.gmbh', 'fixture-only'), 503);
rejects(fn() => mailHost(array_replace($c, ['allowed_mail_hosts' => []])), 503);
$local = mailTransport(array_replace($c, ['local_only' => true]));
check($local['host'] === '127.0.0.1', 'local-only transport is pinned to IPv4 loopback');
check($local['ssl'] === ['peer_name' => $c['mail_host'], 'verify_peer' => true, 'verify_peer_name' => true,
    'allow_self_signed' => false, 'SNI_enabled' => true], 'local-only retains hostname and certificate verification');
rejects(fn() => mailTransport(array_replace($c, ['local_only' => 'true'])), 503);
rejects(fn() => mailTransport(array_replace($c, ['local_only' => true, 'mail_host' => 'evil.example.org'])), 503);
foreach (['', ' ', "Bad\r\nCREATE Foo", 'Archiv//2026', '/Archiv', 'Archiv/', 'Archiv/../2026', 'Bad*', 'Bad%', 'Bad\\Name', 'Archiv/ 2026'] as $invalid) {
    rejects(fn() => validateFolderName($invalid), 400);
}
check(validateFolderName('Archiv/2026') === 'Archiv/2026', 'portable folder hierarchy');
check(validateFolderName('Gesendet') === 'Gesendet', 'simple folder');
check(sentFolder([], []) === 'Sent', 'default sent folder');
check(sentFolder([], ['sent_folder' => 'Gesendet']) === 'Gesendet', 'configured sent folder');
check(sentFolder(['sent_folder' => 'Archiv'], $c) === 'Archiv', 'per-request sent folder');
check(sentFolder(['sent_folder' => null], $c) === null, 'null skips sent copy');
check(sentFolder(['sent_folder' => ''], $c) === null, 'empty string skips sent copy');
rejects(fn() => sentFolder(['sent_folder' => false], $c), 400);
check(autoCreateSentFolder($c), 'configured Sent folder is prepared automatically');
check(!autoCreateSentFolder(['create_sent_folder_if_missing' => false]), 'automatic Sent creation can be disabled');
rejects(fn() => autoCreateSentFolder(['create_sent_folder_if_missing' => 'yes']), 503);

$request = ['to' => ['to@example.com'], 'bcc' => ['hidden@example.com'], 'subject' => 'Grüße', 'text' => 'Hallo Welt',
    'html' => '<p>Hallo Welt</p>', 'in_reply_to' => '<original@example.com>',
    'references' => '<first@example.com> <original@example.com>',
    'attachments' => [['name' => 'grüße.txt', 'type' => 'text/plain', 'content_base64' => base64_encode('Testä')]]];
$mail = buildMail($request, $c, 'user@sann.gmbh', 'not-stored');
$mime = $mail->getSentMIMEMessage();
check($mail->From === 'user@sann.gmbh', 'fixed sender');
check(!str_contains($mime, 'hidden@example.com'), 'Bcc absent from MIME');
check(str_contains($mime, 'In-Reply-To: <original@example.com>'), 'reply threading');
$parsed = \Webklex\PHPIMAP\Message::fromString($mime, \Webklex\PHPIMAP\Config::make(imapOptions()));
$parsed->size = strlen($mime);
$parsed->parseRawFlags(['\\Seen', '\\Flagged']);
$data = summary($parsed);
check($data['subject'] === 'Grüße', 'UTF-8 MIME subject');
check($data['seen'] && $data['flagged'], 'read and star flags');
check($data['from'][0]['email'] === 'user@sann.gmbh', 'sender decoding');
check(trim($parsed->getTextBody()) === 'Hallo Welt', 'text MIME decoding');
check(str_contains($parsed->getHTMLBody(), '<p>Hallo Welt</p>'), 'HTML MIME decoding');
$a = attachments($parsed, true);
check(count($a) === 1 && base64_decode($a[0]['content_base64']) === 'Testä', 'attachment round trip');
check($a[0]['size'] === strlen('Testä'), 'decoded attachment size');
rejects(fn() => buildMail(array_replace($request, ['in_reply_to' => "<x@example.com>\r\nX: x"]), $c, 'user@sann.gmbh', 'secret'), 400);
rejects(fn() => buildMail(array_replace($request, ['attachments' => [['name' => '../bad', 'content_base64' => 'WA==']]]), $c, 'user@sann.gmbh', 'secret'), 400);
rejects(fn() => buildMail(array_replace($request, ['attachments' => [['name' => 'x', 'content_base64' => '%%%']]]), $c, 'user@sann.gmbh', 'secret'), 400);
rejects(fn() => buildMail($request, array_replace($c, ['max_message_bytes' => 100]), 'user@sann.gmbh', 'secret'), 413);

// Real locked-file limiter; no mail connection or persisted mailbox credentials.
$dir = sys_get_temp_dir() . '/imapi-tests-' . bin2hex(random_bytes(6));
mkdir($dir, 0700);
$key = bin2hex(random_bytes(32));
$c['state_dir'] = $dir;
$c['api_key_hash'] = password_hash($key, PASSWORD_BCRYPT);
$server = ['REMOTE_ADDR' => '192.0.2.1', 'HTTP_AUTHORIZATION' => 'Bearer ' . $key];
try {
    $c['requests_per_minute'] = 2;
    authenticate($c, $server); authenticate($c, $server);
    rejects(fn() => authenticate($c, $server), 429);
    $server['REMOTE_ADDR'] = '192.0.2.2';
    $c['requests_per_minute'] = 60;
    $server['HTTP_AUTHORIZATION'] = 'Bearer ' . str_repeat('x', 64);
    for ($i = 0; $i < 5; $i++) { rejects(fn() => authenticate($c, $server), 401); }
    $server['HTTP_AUTHORIZATION'] = 'Bearer ' . $key;
    rejects(fn() => authenticate($c, $server), 429);
    $stored = implode('', array_map('file_get_contents', glob($dir . '/*.json')));
    check(!str_contains($stored, $key) && !str_contains($stored, 'Bearer'), 'limiter contains no key');
    $server['REMOTE_ADDR'] = '192.0.2.3';
    authenticate($c, $server);
    check(true, 'independent IP');
} finally {
    foreach (glob($dir . '/*.json') as $file) { unlink($file); }
    rmdir($dir);
}
echo "$passed checks passed.\n";
