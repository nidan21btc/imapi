<?php
declare(strict_types=1);

// Copy outside the document root. Never add mailbox credentials here.
return [
    'api_key_hash' => '', // Set with: php bin/key.php /absolute/path/config.php
    'mail_host' => 'cloud3-vm338.de-nserver.de',
    'smtp_port' => 465, // 465 = implicit TLS, 587 = required STARTTLS
    'allowed_mailboxes' => ['*@sann.gmbh'], // [] permits all accounts on this fixed server
    'sent_folder' => 'Gesendet', // Exact UTF-8 path from the folders endpoint
    'state_dir' => __DIR__ . '/rate-limit', // Private, writable by PHP; local filesystem
    'requests_per_minute' => 60,
    'failed_keys_before_block' => 5,
    'block_seconds' => 900,
    'max_request_bytes' => 20 * 1024 * 1024,
    'max_message_bytes' => 12 * 1024 * 1024,
    'max_list_bytes' => 32 * 1024 * 1024,
];
