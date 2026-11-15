<?php
declare(strict_types=1);

// Copy outside the document root. Never add mailbox credentials here.
return [
    'api_key_hash' => '', // Set with: php bin/key.php /absolute/path/config.php
    'mail_host' => 'cloud3-vm338.de-nserver.de',
    'allowed_mail_hosts' => ['cloud3-vm338.de-nserver.de'], // Exact hostnames; no client-selected host
    'local_only' => false, // true pins IMAP/SMTP to 127.0.0.1, TLS still verifies mail_host
    'smtp_port' => 465, // 465 = implicit TLS, 587 = required STARTTLS
    'allowed_mailboxes' => ['*@sann.gmbh'], // [] permits all accounts on this fixed server
    'sent_folder' => 'Sent', // Exact UTF-8 path; per-request sent_folder overrides this
    'create_sent_folder_if_missing' => true, // Only configured sent_folder; prepare before SMTP
    'state_dir' => __DIR__ . '/rate-limit', // Private, writable by PHP; local filesystem
    'requests_per_minute' => 60,
    'failed_keys_before_block' => 5,
    'block_seconds' => 900,
    'failed_mail_logins_before_block' => 5, // Per IP network; includes simultaneous attempts
    'mail_auth_block_seconds' => 900,
    'failed_mail_logins_per_mailbox' => 10, // Across IPs; short block to limit account lockout
    'mailbox_auth_block_seconds' => 60,
    'max_request_bytes' => 20 * 1024 * 1024,
    'max_message_bytes' => 12 * 1024 * 1024,
    'max_list_bytes' => 32 * 1024 * 1024,
];
