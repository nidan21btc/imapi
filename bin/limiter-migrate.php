<?php
declare(strict_types=1);
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
define('IMAPI_TEST', true);
require __DIR__ . '/../public/index.php';
umask(0077);
try {
    $c = config();
    $backup = $argv[1] ?? dirname($c['state_dir']) . '/limiter-v1-backup-' . bin2hex(random_bytes(6));
    $parent = realpath(dirname($backup));
    $webroot = realpath(__DIR__ . '/../public');
    if (!$parent || $parent === $webroot || str_starts_with($parent, $webroot . '/') || file_exists($backup)
        || !mkdir($backup, 0700)) { throw new RuntimeException('Invalid or existing private backup directory.'); }
    $migrated = 0;
    foreach (new DirectoryIterator($c['state_dir']) as $entry) {
        $name = $entry->getFilename();
        if (!$entry->isFile() || $entry->isLink() || !preg_match('/^([a-f0-9]{64})\.json$/D', $name, $match)) { continue; }
        $file = @fopen($entry->getPathname(), 'r+');
        if (!$file || !flock($file, LOCK_EX)) { throw new RuntimeException('Could not lock legacy state.'); }
        try {
            $raw = stream_get_contents($file, 131073);
            if ($raw === false || strlen($raw) > 131072) { throw new RuntimeException('Invalid legacy state.'); }
            $old = json_decode($raw, true, 16, JSON_THROW_ON_ERROR);
            if (!is_array($old)) { throw new RuntimeException('Invalid legacy state.'); }
            $now = time();
            $requests = array_values(array_filter($old['requests'] ?? [], fn($t) => is_int($t) && $t > $now - 60));
            $failures = array_values(array_filter($old['failures'] ?? [], fn($t) => is_int($t) && $t > $now - 900));
            $blocked = is_int($old['blocked'] ?? null) ? $old['blocked'] : 0;
            if ($requests || $failures || $blocked > $now) {
                // Legacy filenames retain IPv4 identity hashes, without exposing client IPs.
                limiterUpdate($c, 'ip', $match[1], static function (array &$s) use ($requests, $failures, $blocked): void {
                    $allRequests = array_merge($s['requests'] ?? [], $requests);
                    sort($allRequests, SORT_NUMERIC);
                    $s['requests'] = array_slice($allRequests, -1000);
                    $s['failures'] = array_slice(array_merge($s['failures'] ?? [], $failures), -100);
                    $s['blocked'] = max($s['blocked'] ?? 0, $blocked);
                });
            }
            if (!rename($entry->getPathname(), $backup . '/' . $name)) { throw new RuntimeException('Could not archive legacy state.'); }
            $migrated++;
        } finally { flock($file, LOCK_UN); fclose($file); }
    }
    echo "Legacy state files migrated/archived: $migrated.\n";
} catch (Throwable) {
    fwrite(STDERR, "Limiter migration failed; keep the private backup and inspect configuration/permissions.\n");
    exit(1);
}
