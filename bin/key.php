<?php
declare(strict_types=1);

if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
umask(0077);
$path = $argv[1] ?? '';
if (!$path || !is_file($path) || !is_writable($path)) {
    fwrite(STDERR, "Usage: php bin/key.php /absolute/private/config.php\n"); exit(1);
}
$config = require $path;
if (!is_array($config)) { fwrite(STDERR, "Invalid config.\n"); exit(1); }
$key = bin2hex(random_bytes(32));
$config['api_key_hash'] = password_hash($key, PASSWORD_BCRYPT);
$tmp = tempnam(dirname($path), '.imapi-key-');
if ($tmp === false || file_put_contents($tmp, "<?php\nreturn " . var_export($config, true) . ";\n") === false
    || !chmod($tmp, 0600) || !rename($tmp, $path)) {
    if ($tmp && is_file($tmp)) { unlink($tmp); }
    fwrite(STDERR, "Could not update config.\n"); exit(1);
}
fwrite(STDOUT, "API key (shown once; old key is now invalid):\n$key\n");
