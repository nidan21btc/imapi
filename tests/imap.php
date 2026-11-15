<?php
// Local protocol fixture only; never connects to a real mailbox or sends mail.
declare(strict_types=1);
define('IMAPI_TEST', true);
require __DIR__ . '/../public/index.php';
ini_set('display_errors', '1');
if (!function_exists('pcntl_fork')) { fwrite(STDERR, "IMAP fixture requires CLI pcntl.\n"); exit(1); }

$headers = "Date: Sun, 15 Nov 2026 12:00:00 +0100\r\nFrom: Sender <sender@example.org>\r\nTo: user@sann.gmbh\r\nSubject: =?ISO-8859-1?Q?Gr=FC=DFe?=\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=ISO-8859-1\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n";
$body = 'Gr=FC=DFe aus dem Test';
$size = strlen($headers . $body);
$socket = stream_socket_server('tcp://127.0.0.1:0', $errno, $error);
if (!$socket) { throw new RuntimeException('Could not create fixture socket.'); }
$port = (int)substr(strrchr(stream_socket_get_name($socket, false), ':'), 1);
$pid = pcntl_fork();
if ($pid === -1) { throw new RuntimeException('Could not fork fixture.'); }
if ($pid === 0) {
    $peer = stream_socket_accept($socket, 10);
    if (!$peer) { exit(2); }
    stream_set_timeout($peer, 10);
    fwrite($peer, "* OK fixture ready\r\n");
    $seen = false;
    $peekReads = 0;
    $createdFolders = [];
    $subscriptions = 0;
    $listSearches = 0;
    while (($line = fgets($peer)) !== false) {
        if (!preg_match('/^(\S+) (.+)\r\n$/', $line, $match)) { exit(3); }
        [$unused, $tag, $command] = $match;
        if (str_starts_with($command, 'CAPABILITY')) { fwrite($peer, "* CAPABILITY IMAP4rev1 MOVE UIDPLUS\r\n"); }
        elseif (str_starts_with($command, 'LOGIN ')) { /* Only synthetic credentials. */ }
        elseif ($command === 'NOOP') { /* Connection health check. */ }
        elseif (str_starts_with($command, 'LIST ')) {
            if ($command === 'LIST "" ""') { fwrite($peer, '* LIST (\\Noselect) "." ""' . "\r\n"); }
            else {
                fwrite($peer, '* LIST (\\HasNoChildren) "." "INBOX"' . "\r\n");
                foreach ($createdFolders as $name) { fwrite($peer, '* LIST (\\HasNoChildren) "." "' . $name . '"' . "\r\n"); }
            }
        } elseif (str_starts_with($command, 'CREATE ')) {
            $name = trim(substr($command, 7), '"');
            if (!in_array($name, ['Archiv.2026', 'Gr&APwA3w-e', 'Gesendet'], true)) { exit(9); }
            if (in_array($name, $createdFolders, true)) { exit(10); }
            $createdFolders[] = $name;
        } elseif (str_starts_with($command, 'SUBSCRIBE ')) { $subscriptions++; }
        elseif (str_starts_with($command, 'SELECT ')) {
            fwrite($peer, "* FLAGS (\\Seen \\Flagged)\r\n* 1 EXISTS\r\n* 0 RECENT\r\n* OK [UIDVALIDITY 1]\r\n* OK [UIDNEXT 43]\r\n");
        } elseif (str_starts_with($command, 'UID SEARCH ')) {
            $listSearches++;
            fwrite($peer, "* SEARCH 42 43 44\r\n");
        } elseif (str_starts_with($command, 'UID FETCH ')) {
            if (!preg_match('/^UID FETCH (\d+)/', $command, $uidMatch)) { exit(11); }
            $messageUid = (int)$uidMatch[1];
            $reportedSize = $listSearches === 0 ? $size : (($listSearches === 1 && $messageUid === 44 ? 13 : 11) * 1024 * 1024);
            if (str_contains($command, 'RFC822.SIZE')) { fwrite($peer, "* 1 FETCH (UID $messageUid RFC822.SIZE $reportedSize)\r\n"); }
            elseif (str_contains($command, 'RFC822.HEADER')) { fwrite($peer, '* 1 FETCH (UID ' . $messageUid . ' RFC822.HEADER {' . strlen($headers) . "}\r\n" . $headers . ")\r\n"); }
            elseif (str_contains($command, 'BODY.PEEK[TEXT]')) {
                if (($listSearches === 1 && $messageUid === 44) || ($listSearches === 2 && $messageUid === 42)) { exit(12); }
                $peekReads++;
                fwrite($peer, '* 1 FETCH (UID ' . $messageUid . ' BODY[TEXT] {' . strlen($body) . "}\r\n" . $body . ")\r\n");
            } elseif (str_contains($command, 'FLAGS')) { fwrite($peer, '* 1 FETCH (UID ' . $messageUid . ' FLAGS (' . ($seen ? '\\Seen' : '') . "))\r\n"); }
            else { fwrite(STDERR, "Unexpected fetch in fixture.\n"); exit(4); }
        } elseif (str_starts_with($command, 'UID STORE ')) {
            // One explicit marking is allowed only after both PEEK reads.
            if ($peekReads !== 2 || $seen || !str_contains($command, '+FLAGS') || !str_contains($command, '\\Seen')) { exit(5); }
            $seen = true;
        } elseif ($command === 'LOGOUT') {
            fwrite($peer, "* BYE closing\r\n$tag OK LOGOUT complete\r\n");
            fclose($peer); fclose($socket);
            exit($peekReads === 6 && $seen && $listSearches === 2 && count($createdFolders) === 3 && $subscriptions === 5 ? 0 : 6);
        } else { fwrite(STDERR, "Unexpected command in fixture: $command\n"); exit(7); }
        fwrite($peer, "$tag OK completed\r\n");
    }
    exit(8);
}
fclose($socket);
$client = (new \Webklex\PHPIMAP\ClientManager(imapOptions()))->make([
    'host' => '127.0.0.1', 'port' => $port, 'encryption' => false, 'protocol' => 'imap',
    'username' => 'fixture@example.org', 'password' => 'fixture-only', 'timeout' => 5,
]);
try {
    $client->connect();
    $folder = new \Webklex\PHPIMAP\Folder($client, 'INBOX', '/', []);
    $m = loadMessage($client, $folder, 42, 1024 * 1024, true);
    if ($m->hasFlag('Seen') || summary($m)['subject'] !== 'Grüße' || $m->getTextBody() !== 'Grüße aus dem Test') {
        throw new RuntimeException('PEEK / ISO-8859-1 decoding failed.');
    }
    $m = loadMessage($client, $folder, 42, 1024 * 1024, true);
    if ($m->hasFlag('Seen')) { throw new RuntimeException('Reading changed Seen flag.'); }
    if (!$m->setFlag('Seen')) { throw new RuntimeException('Explicit mark_seen failed.'); }
    $existing = createMailFolder($client, 'INBOX');
    if ($existing !== ['folder' => 'INBOX', 'created' => false]) { throw new RuntimeException('Existing folder must return created=false.'); }
    $created = createMailFolder($client, 'Archiv/2026');
    if ($created !== ['folder' => 'Archiv.2026', 'created' => true]) { throw new RuntimeException('Native hierarchy delimiter was not used.'); }
    if (createMailFolder($client, 'Archiv/2026')['created'] !== false) { throw new RuntimeException('Repeated create must be idempotent.'); }
    if (!createMailFolder($client, 'Grüße')['created']) { throw new RuntimeException('UTF-7 folder creation failed.'); }
    foreach (['Archiv..2026', 'Archiv.2026/Mixed'] as $invalid) {
        try { createMailFolder($client, $invalid); throw new RuntimeException('Invalid separator accepted.'); }
        catch (ApiError $e) { if ($e->status !== 400) { throw $e; } }
    }
    $prepared = prepareSentFolder($client, 'Gesendet', ['sent_folder' => 'Gesendet', 'create_sent_folder_if_missing' => true]);
    if (folderName($prepared) !== 'Gesendet') { throw new RuntimeException('Configured Sent folder not prepared.'); }
    foreach ([['sent_folder' => 'Other'], ['sent_folder' => 'Missing', 'create_sent_folder_if_missing' => false]] as $c) {
        try { prepareSentFolder($client, 'Missing', $c); throw new RuntimeException('Missing folder must stop send preparation.'); }
        catch (ApiError $e) { if ($e->errorCode !== 'sent_folder_not_found') { throw $e; } }
    }
    $limits = ['max_message_bytes' => 12 * 1024 * 1024, 'max_list_bytes' => 32 * 1024 * 1024];
    $large = listMessages($client, $folder, 3, '', false, $limits);
    if (count($large['messages']) !== 3 || !$large['truncated'] || !$large['messages'][0]['too_large']
        || $large['messages'][0]['attachment_count'] !== null || $large['messages'][0]['body_loaded']
        || !$large['messages'][1]['body_loaded'] || $large['messages'][1]['attachment_count'] !== 0) {
        throw new RuntimeException('Large message hid subsequent headers or invented an attachment count.');
    }
    $budget = listMessages($client, $folder, 3, '', false, $limits);
    if (count($budget['messages']) !== 3 || !$budget['truncated'] || $budget['messages'][2]['body_loaded']
        || $budget['messages'][2]['attachment_count'] !== null || $budget['messages'][2]['too_large']) {
        throw new RuntimeException('Combined body budget blocked the mailbox listing.');
    }
    $client->disconnect();
    pcntl_waitpid($pid, $status);
    if (!pcntl_wifexited($status) || pcntl_wexitstatus($status) !== 0) { throw new RuntimeException('Unexpected protocol operation.'); }
    echo "IMAP wire fixture passed: PEEK, UTF-8, explicit Seen, CREATE/SUBSCRIBE, existing folders and delimiter validation; no EXPUNGE.\n";
} catch (Throwable $e) {
    posix_kill($pid, SIGTERM);
    pcntl_waitpid($pid, $status);
    throw $e;
}
