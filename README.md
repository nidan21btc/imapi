# imapi

Kleine HTTPS-Schnittstelle für IMAP und SMTP, PHP **8.2 oder neuer**. Ein öffentlicher Einstiegspunkt, sechs Aktionen. Mail-Zugangsdaten kommen bei jeder Anfrage über Header und werden weder in Dateien noch in Logs gespeichert. SMTP verwendet PHPMailer, IMAP Webklex ohne native IMAP-Erweiterung.

## Einrichtung auf Webhosting

1. Voraussetzungen prüfen: `php bin/check.php`. Benötigt werden OpenSSL, mbstring, iconv, DOM, fileinfo, filter und ZIP. Die CLI- und Web-PHP-Version sowie Erweiterungen müssen übereinstimmen. Auf dieser Entwicklungsumgebung fehlt `ext-imap`; daher verwendet das Projekt den Webklex-Fallback. Auch bei vorhandener Erweiterung bleibt derselbe getestete Webklex-Zugriff aktiv.
2. `composer install --no-dev --prefer-dist --optimize-autoloader` ausführen. Gibt es auf dem Hosting kein Composer, lokal mit PHP 8.2+ ausführen und `vendor/` mit hochladen. `composer.lock` gehört zum Deployment. `composer check-platform-reqs --no-dev` prüft die tatsächlichen Anforderungen.
3. Verzeichnisstruktur anlegen, etwa:

   ```text
   /home/ACCOUNT/imapi/
     public/index.php         ← DocumentRoot der API-Domain
     vendor/
     private/config.php       ← nicht per HTTP erreichbar
     private/rate-limit/      ← privat, für PHP schreibbar
     bin/key.php
     composer.json
     composer.lock
   ```

4. `mkdir -p private/rate-limit && cp config.example.php private/config.php`. Private Verzeichnisse mit `0700`, Config mit `0600` absichern, wenn PHP unter demselben Benutzer läuft. Bei separatem PHP-Benutzer gezielt Gruppenrechte vergeben: private Verzeichnisse `0750`, Config `0640`, das für PHP schreibbare Statusverzeichnis `0770`. Nur `rate-limit/` braucht Schreibrechte für den Webprozess. Keine `0777`-Rechte.
5. `php bin/key.php /home/ACCOUNT/imapi/private/config.php` erzeugt einen zufälligen 256-Bit-Key, zeigt ihn einmal an und schreibt ausschließlich einen bcrypt-Hash atomar in die Config. Rotation erfolgt mit demselben Befehl; der alte Key wird sofort ungültig. Das Skript setzt die Config auf `0600`; bei separatem Web-Benutzer anschließend die passende Gruppe und `0640` erneut setzen.
6. In der Config `allowed_mailboxes`, `sent_folder` und gegebenenfalls `smtp_port` anpassen. Der Host bleibt fest `cloud3-vm338.de-nserver.de`: IMAP 993 mit TLS; SMTP 465 mit TLS oder 587 mit verpflichtendem STARTTLS. Zertifikatsprüfung bleibt eingeschaltet. Keine Mail-Passwörter eintragen. Den exakten UTF-8-Pfad des Gesendet-Ordners über `folders` ermitteln (z. B. `Gesendet`, `Sent` oder `INBOX.Sent`). Der Ordner muss bereits existieren; es werden keine Ordner automatisch angelegt.
7. API-Domain mit gültigem TLS-Zertifikat auf `public/` richten. Bei unveränderlichem `public_html` nur `index.php` dorthin kopieren und dessen Autoloader-Pfad auf das private `vendor/autoload.php` ändern. `IMAPI_CONFIG` als serverseitige Umgebungsvariable auf den absoluten Config-Pfad setzen. Ohne diese Variable wird `../private/config.php` relativ zum Einstiegspunkt verwendet. Config, Composer-Dateien, Tests und `vendor/` niemals öffentlich bereitstellen.
8. Authorization-Header an PHP weiterreichen, unter Apache etwa mit `CGIPassAuth On` im VHost/Directory oder, falls vom Hoster unterstützt, `.htaccess` mit `SetEnvIf Authorization "(.+)" HTTP_AUTHORIZATION=$1`. Requests dürfen im Webserver, Proxy, CDN, WAF oder APM **nicht mit Headern oder Body aufgezeichnet** werden. Normale Access-Logs ohne diese Daten sind möglich. Zugangsdaten gehören ausschließlich in Header, niemals in URL/Querystring. PHP unterdrückt rohe Bibliotheksfehler und Fehlerlogs für diesen Einstiegspunkt.

Die API prüft das serverseitige `HTTPS=on/1` und lehnt HTTP mit 426 ab. Hinter einem TLS-Proxy muss der Webserver diese Variable ausschließlich für einen vertrauenswürdigen Proxy setzen; vom Client gesendete Forwarded-Header werden nicht ausgewertet. Die IP für Rate-Limits ist `REMOTE_ADDR`: hinter einem Proxy muss der Webserver die echte IP vertrauenswürdig auflösen, sonst teilen alle Clients ein Limit.

Ausgehende Verbindungen vom Webhosting zu 993 und 465 bzw. 587 müssen erlaubt sein. Es ist kein Daemon, Framework, Datenbankserver oder Cronjob erforderlich. Rate-Limit-Dateien nutzen `flock` auf einem lokalen Dateisystem; für mehrere Webserver braucht es einen gemeinsamen atomaren Limiter. Alte Dateien werden gelegentlich bereinigt.

## API und Beispiele

Alle Aufrufe gehen als **POST an dieselbe URL**, die Aktion steht im JSON-Feld `action`. Erfolg: `{"ok":true,"data":{...}}`. Fehler: `{"ok":false,"error":{"code":"…","message":"…"}}`.

Für Bash eine kurzlebige Header-Datei statt sichtbarer Passwörter in Prozessargumenten verwenden:

```bash
URL='https://imapi.test/'
read -r -s -p 'API-Key: ' API_KEY; echo
read -r -p 'Mail-Benutzer: ' MAIL_USER
read -r -s -p 'Mail-Passwort: ' MAIL_PASSWORD; echo
umask 077
HEADERS=$(mktemp)
trap 'rm -f "$HEADERS"; unset API_KEY MAIL_USER MAIL_PASSWORD' EXIT
printf 'Authorization: Bearer %s\nX-Mail-User: %s\nX-Mail-Password: %s\nContent-Type: application/json\n' \
  "$API_KEY" "$MAIL_USER" "$MAIL_PASSWORD" > "$HEADERS"
unset API_KEY MAIL_USER MAIL_PASSWORD
# Entwicklung: eigenes Zertifikat ausdrücklich vertrauen. Produktion: CA-Option weglassen.
api() { curl --silent --show-error --fail-with-body --cacert .dev/imapi.test.crt \
  --header @"$HEADERS" --data-binary "$1" "$URL"; echo; }
```

Diese Datei liegt nur vorübergehend **auf dem Client**, nicht auf dem API-Server. Nach Abschluss `exit` verwenden oder Datei löschen und Variablen entfernen. Keine Shell-Traces (`set -x`) oder curl-Debugausgaben mit echten Zugangsdaten aktivieren.

1. Ordner auflisten:

   ```bash
   api '{"action":"folders"}'
   ```

   Rückgabe `folders` mit `path`, `name`, `selectable`. Pfade genauso für weitere Anfragen verwenden.

2. Nachrichten auflisten, neueste UID zuerst:

   ```bash
   api '{"action":"list","folder":"INBOX","limit":20,"since":"2026-11-01","unseen_only":true}'
   ```

   Standard: `folder=INBOX`, `limit=20` (1–100), kein Datumsfilter, `unseen_only=false`. `since` ist ein inklusives IMAP-Datum (`YYYY-MM-DD`, Kalendertag des Mailservers). `messages` enthält UID, Datum, Absender/Empfänger als `{email,name}`, Betreff, `seen`, `flagged`, `size` in Bytes und `attachment_count`. Für die genaue Anhangzahl werden die begrenzten Nachrichtenkörper mit PEEK gelesen. Eine übergroße Nachricht oder Liste liefert 413; dann `limit` reduzieren bzw. `since` setzen. UIDs gelten jeweils nur innerhalb des Ordners und seiner UIDVALIDITY; nach einem Server-Reset neu auflisten.

3. Nachricht lesen, ohne sie als gelesen zu markieren:

   ```bash
   api '{"action":"get","folder":"INBOX","uid":123,"mark_seen":false}'
   ```

   Zusätzlich zu den Listendaten: vollständige rohe `headers`, UTF-8-dekodiertes `text` und `html`, `attachments` mit nullbasiertem `index`, Name, MIME-Typ, dekodierter Größe, Content-ID und Disposition. Für gelesen markieren `mark_seen=true`. Fehlende Text-/HTML-Teile sind leere Strings. HTML ist unvertrauenswürdiger Mailinhalt und muss in einer anzeigenden Anwendung isoliert bzw. bereinigt werden.

4. Anhang herunterladen:

   ```bash
   api '{"action":"attachment","folder":"INBOX","uid":123,"index":0}'
   ```

   Liefert die Metadaten sowie `content_base64`. Inline-Anhänge zählen mit. Der Gelesen-Status bleibt unverändert.

5. Nachricht senden, einschließlich optionalem HTML, Thread-Headern und Anhang:

   ```bash
   api '{"action":"send","to":["empfaenger@example.org"],"cc":[],"bcc":[],"subject":"Antwort","text":"Hallo!","html":"<p>Hallo!</p>","reply_to":"antwort@sann.gmbh","in_reply_to":"<original@example.org>","references":"<thread-start@example.org> <original@example.org>","attachments":[{"name":"hallo.txt","type":"text/plain","content_base64":"SGFsbG8h"}]}'
   ```

   Erforderlich: `to`, `subject`, `text`. Adressfelder akzeptieren eine einzelne Mailadresse oder ein Array (je maximal 50), ohne Anzeigenamen. `cc`, `bcc`, `html`, `reply_to`, Thread-Header und Anhänge sind optional. `references` ist eine durch Leerzeichen getrennte Message-ID-Liste. Anhänge verwenden kanonisches Base64 ohne Zeilenumbrüche, maximal 20 Stück. Absender und Envelope-Sender sind stets der angemeldete Benutzer. Bcc-Adressen stehen nicht in den MIME-Headern.

   Erfolg liefert `sent=true`, `message_id`, `saved_to_sent=true`. Schlägt nach erfolgreicher SMTP-Übergabe nur IMAP-APPEND fehl, bleibt die Antwort HTTP 200 mit `sent=true`, `saved_to_sent=false`, `warning="sent_copy_failed"`. **Dann keinesfalls erneut senden.** SMTP und IMAP sind nicht atomar. Bei Timeout/Verbindungsabbruch kann der Zustellstatus unklar sein; vor Wiederholung prüfen. Es gibt keine automatische Wiederholung und keine Idempotenz-Datenbank.

6. Gelesen-/Stern-Markierung setzen oder entfernen und optional verschieben:

   ```bash
   api '{"action":"flag","folder":"INBOX","uid":123,"seen":true,"flagged":true}'
   api '{"action":"flag","folder":"INBOX","uid":123,"seen":false,"flagged":false}'
   api '{"action":"flag","folder":"INBOX","uid":123,"move_to":"Archiv"}'
   ```

   Nicht angegebene Markierungen bleiben erhalten. Kombination mit `move_to` ist möglich; einzelne IMAP-Operationen sind nicht atomar. Nach Fehlern den Zustand neu lesen. Zielordner muss existieren. Verschieben verwendet ausschließlich RFC-6851-`UID MOVE`, ohne COPY/DELETE/EXPUNGE-Fallback. Unterstützt der Server MOVE nicht, kommt 409 vor jeder Änderung. Die UID im Zielordner kann sich ändern; dort neu auflisten. Es gibt keinen Lösch-Endpunkt und keine frei wählbaren IMAP-Flags.

## Limits und Statuscodes

Standard: 60 Anfragen je Minute/IP (gleitendes Fenster). Fünf falsche API-Keys innerhalb von 15 Minuten sperren die IP für 15 Minuten. Prüfung erfolgt mit `password_verify`, ohne zeitabhängigen Stringvergleich des Keys. Auch falsche Keys zählen zum Anfragelimit. Statusdateien enthalten nur Zeitstempel und Zähler; Postfachdaten oder Keys werden nicht gespeichert.

| HTTP | Bedeutung |
| --- | --- |
| 400 | Ungültiges JSON, Aktion oder Parameter |
| 401 | API-Key fehlt oder ist falsch |
| 403 | Mail-Anmeldung fehlgeschlagen oder Postfach nicht erlaubt |
| 404 | Ordner, UID oder Anhang fehlt |
| 405 | Methode außer POST |
| 409 | Sichere Verschiebung vom Mailserver nicht unterstützt |
| 413 | Anfrage, Nachricht oder Liste zu groß |
| 415 | Content-Type ist nicht application/json |
| 426 | HTTPS erforderlich |
| 429 | Rate-Limit oder temporäre IP-Sperre; Retry-After beachten |
| 502 | Mailserver-/Transportfehler, interner Fehler ohne Details |
| 503 | Config oder Rate-Limit nicht verfügbar |

Standardgrößen: 20 MiB JSON-Anfrage, 12 MiB vollständige MIME-Nachricht, 32 MiB gelesene Nachrichten pro Liste. Webhosting-Limits (`memory_limit`, `post_max_size`, Webserver-Bodylimit) entsprechend einstellen, z. B. 256 MiB PHP-Speicher und 24 MiB `post_max_size`. Base64 und MIME-Decodierung benötigen zusätzlichen Speicher. Vorgeschaltete Serverlimits können eigene Fehlerseiten liefern, bevor PHP ausgeführt wird. Netzwerk-Timeout jeweils 20 Sekunden; Laufzeitlimit des Hosters beachten.

## Entwicklung

Lokaler Apache-VHost: `dev/imapi.test.conf`, ausschließlich `public/` als DocumentRoot. `imapi.test` muss auf dem verwendeten Rechner zum Dev-Server auflösen; `.test` ist keine öffentliche Domain. Das Entwicklungszertifikat liegt unversioniert unter `.dev/`, der private Schlüssel wird nicht veröffentlicht. In der laufenden Umgebung: **https://imapi.test/**. Auf einem anderen Rechner Hosts/DNS-Eintrag und Zertifikatsvertrauen ergänzen.

```bash
composer install  # Mit Entwicklungsabhängigkeiten einschließlich PHPStan
composer validate --strict
composer check-platform-reqs --no-dev
php bin/check.php
composer analyse # PHPStan Level 6 für public/, bin/, tests/ und Beispielconfig
php tests/run.php
php tests/imap.php  # Lokaler IMAP-Testserver; CLI pcntl/posix erforderlich
```

`composer check` führt Composer-Validierung, PHPStan und beide PHP-Tests zusammen aus; `composer test` nur die Tests. Die GitHub-Actions-CI führt die Analyse und Tests bei jedem Push und Pull Request unter PHP 8.2, 8.3, 8.4 und 8.5 aus. PHPStan ist ausschließlich eine Entwicklungsabhängigkeit und wird beim Produktionsdeployment mit `composer install --no-dev` nicht installiert. Die Analyse verwendet keine Baseline und keine unterdrückten Fehler. Der lokale Analysecache wird nicht versioniert.

Die Tests prüfen MIME/UTF-8, Anhänge, Bcc, Thread-Header, Eingabevalidierung, Größenlimit, Postfach-Whitelist und Rate-Limit/IP-Sperre. Der IMAP-Protokolltest verwendet ausschließlich einen lokalen Testserver und prüft, dass wiederholtes Lesen keine Flag-Schreibbefehle auslöst; erst explizites Markieren setzt Seen. Optional prüft `IMAPI_TEST_KEY=… python3 tests/gateway.py` die laufende lokale HTTPS-API ohne echte Postfachzugänge; den Key dabei über eine geschützte Shellvariable setzen. Für den echten Postfach-Smoke-Test die sechs obigen Aufrufe mit einem Testpostfach ausführen; dafür werden keine Zugangsdaten im Projekt hinterlegt.

Öffentliches Repository vorbereiten: ausschließlich versionierte Dateien hochladen, niemals `private/`, `.dev/`, Header-Dateien oder Maildaten. GitHub CLI nach Anmeldung etwa: `gh repo create imapi --public --source=. --remote=origin --push`. Die Lizenz ist MIT; siehe `LICENSE`.

Bibliotheken: [PHPMailer](https://github.com/PHPMailer/PHPMailer), [Webklex PHP-IMAP](https://github.com/Webklex/php-imap). Hintergrund: Die [native PHP-IMAP-Erweiterung](https://www.php.net/manual/en/imap.installation.php) ist seit PHP 8.4 in PECL und wird hier nicht benötigt.
