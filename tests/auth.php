<?php
declare(strict_types=1);

namespace ImapiTests {
    final class NetworkProbe {
        /** @var list<array{address: string, options: array<string, mixed>}> */
        private static array $connections = [];
        /** @return list<array{address: string, options: array<string, mixed>}>
         *  @phpstan-impure Reads state changed by indirect library callbacks.
         */
        public static function snapshot(): array { return self::$connections; }
        public static function blocked(string $address, mixed $context): never {
            self::$connections[] = ['address' => $address, 'options' => is_resource($context) ? stream_context_get_options($context) : []];
            throw new \RuntimeException('Network blocked by test fixture.');
        }
    }
}
// Intercept the actual libraries' socket calls. No outbound connection is possible.
namespace Webklex\PHPIMAP\Connection\Protocols {
    function stream_socket_client(string $address, ?int &$error_code = null, ?string &$error_message = null,
        ?float $timeout = null, int $flags = STREAM_CLIENT_CONNECT, mixed $context = null): never {
        \ImapiTests\NetworkProbe::blocked($address, $context);
    }
}
namespace PHPMailer\PHPMailer {
    function stream_socket_client(string $address, ?int &$error_code = null, ?string &$error_message = null,
        ?float $timeout = null, int $flags = STREAM_CLIENT_CONNECT, mixed $context = null): never {
        \ImapiTests\NetworkProbe::blocked($address, $context);
    }
}
namespace {
    define('IMAPI_TEST', true);
    require __DIR__ . '/../public/index.php';
    ini_set('display_errors', '1');
    $dir = sys_get_temp_dir() . '/imapi-auth-' . bin2hex(random_bytes(6));
    mkdir($dir, 0700);
    $c = require __DIR__ . '/../config.example.php';
    $c['api_key_hash'] = password_hash(bin2hex(random_bytes(32)), PASSWORD_BCRYPT);
    $c['state_dir'] = $dir;
    $path = $dir . '/config.php';
    file_put_contents($path, '<?php return ' . var_export($c, true) . ';');
    $oldConfig = getenv('IMAPI_CONFIG');
    putenv('IMAPI_CONFIG=' . $path);
    try {
        foreach (['', 'Bearer ' . str_repeat('x', 64)] as $auth) {
            $_SERVER = ['HTTPS' => 'on', 'REQUEST_METHOD' => 'POST', 'REMOTE_ADDR' => '192.0.2.10',
                'CONTENT_TYPE' => 'application/json', 'HTTP_AUTHORIZATION' => $auth,
                'HTTP_X_MAIL_USER' => 'fixture@sann.gmbh', 'HTTP_X_MAIL_PASSWORD' => 'fixture-only'];
            ob_start(); main(); $response = json_decode((string)ob_get_clean(), true);
            if (http_response_code() !== 401 || $response['ok'] !== false || count(\ImapiTests\NetworkProbe::snapshot()) !== 0) {
                throw new RuntimeException('Bearer authentication must precede all outbound socket calls.');
            }
        }
        // Positive controls prove that both library network paths are intercepted.
        $c['local_only'] = true;
        try { connectMailbox($c, 'fixture@sann.gmbh', 'fixture-only'); } catch (Throwable) { /* Expected. */ }
        if (count(\ImapiTests\NetworkProbe::snapshot()) !== 1) { throw new RuntimeException('IMAP probe failed.'); }
        $mail = buildMail(['to' => 'recipient@example.org', 'subject' => 'Fixture', 'text' => 'Fixture'], $c, 'fixture@sann.gmbh', 'fixture-only');
        try { $mail->postSend(); } catch (Throwable) { /* Expected. */ }
        $connections = \ImapiTests\NetworkProbe::snapshot();
        if (count($connections) !== 2 || $connections[0]['address'] !== 'ssl://127.0.0.1:993' || $connections[1]['address'] !== 'ssl://127.0.0.1:465') {
            throw new RuntimeException('Loopback socket pinning failed.');
        }
        foreach ($connections as $connection) {
            $ssl = $connection['options']['ssl'] ?? [];
            if (($ssl['peer_name'] ?? '') !== $c['mail_host'] || !($ssl['verify_peer'] ?? false) || !($ssl['verify_peer_name'] ?? false)) {
                throw new RuntimeException('Local-only transport lost TLS verification.');
            }
        }
        $request = ['action' => 'send', 'to' => 'recipient@example.org', 'subject' => 'Fixture', 'text' => 'Fixture'];
        try { dispatch($request, $c, 'fixture@sann.gmbh', 'fixture-only'); } catch (Throwable) { /* Preflight IMAP fails at probe. */ }
        $afterPreflight = \ImapiTests\NetworkProbe::snapshot();
        if (count($afterPreflight) !== 3 || $afterPreflight[2]['address'] !== 'ssl://127.0.0.1:993') {
            throw new RuntimeException('Failed Sent preflight must not start SMTP.');
        }
        try { dispatch($request + ['sent_folder' => null], $c, 'fixture@sann.gmbh', 'fixture-only'); } catch (Throwable) { /* SMTP fails at probe. */ }
        $afterSkip = \ImapiTests\NetworkProbe::snapshot();
        if (count($afterSkip) !== 4 || $afterSkip[3]['address'] !== 'ssl://127.0.0.1:465') {
            throw new RuntimeException('Explicit null Sent folder must skip IMAP entirely.');
        }
        echo "Authentication gate passed: missing/invalid Bearer tokens cause zero socket calls; local-only pins IMAP/SMTP sockets and preserves TLS.\n";
    } finally {
        putenv($oldConfig === false ? 'IMAPI_CONFIG' : 'IMAPI_CONFIG=' . $oldConfig);
        foreach (glob($dir . '/*') as $file) { unlink($file); }
        rmdir($dir);
    }
}
