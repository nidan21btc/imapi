<?php
declare(strict_types=1);
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
$ok = PHP_VERSION_ID >= 80200;
echo 'PHP >= 8.2: ' . ($ok ? 'OK' : 'MISSING') . "\n";
foreach (['openssl', 'mbstring', 'iconv', 'dom', 'fileinfo', 'filter', 'zip', 'intl'] as $extension) {
    $present = extension_loaded($extension);
    echo "$extension: " . ($present ? 'OK' : 'MISSING') . "\n";
    $ok = $ok && $present;
}
echo 'Native IMAP: ' . (extension_loaded('imap') ? 'available' : 'absent; using Webklex') . "\n";
echo 'Composer: ' . (is_file(__DIR__ . '/../vendor/autoload.php') ? 'OK' : 'run composer install') . "\n";
exit($ok && is_file(__DIR__ . '/../vendor/autoload.php') ? 0 : 1);
