# imapi

Kleine HTTPS-Schnittstelle für IMAP und SMTP, PHP **8.2 oder neuer**. Ein öffentlicher Einstiegspunkt, sieben Aktionen. Mail-Zugangsdaten kommen bei jeder Anfrage über Header und werden weder in Dateien noch in Logs gespeichert. SMTP verwendet PHPMailer, IMAP Webklex ohne native IMAP-Erweiterung.

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
6. In der Config `allowed_mailboxes`, `sent_folder` und gegebenenfalls `smtp_port` anpassen. Der Zielhost kommt ausschließlich aus `mail_host` in der privaten Config und muss in `allowed_mail_hosts` stehen (exakte Hostnamen, keine Wildcards). Standard ist `cloud3-vm338.de-nserver.de`: IMAP 993 mit TLS; SMTP 465 mit TLS oder 587 mit verpflichtendem STARTTLS. Ein vom Client übergebener Host wird nicht verwendet. Zertifikatsprüfung bleibt eingeschaltet. Keine Mail-Passwörter eintragen. Den exakten UTF-8-Pfad des Gesendet-Ordners über `folders` ermitteln (z. B. `Gesendet`, `Sent` oder `INBOX.Sent`). Der konfigurierte Standard ist `Sent`; vorhandene individuelle Einstellungen bleiben bestehen. Mit `create_sent_folder_if_missing=true` (Standard) wird ausschließlich dieser konfigurierte Gesendet-Ordner vor dem SMTP-Versand bei Bedarf angelegt und abonniert. Schlägt die Vorbereitung fehl, wird nichts versendet. Bei `false` muss er bereits existieren. Andere Ordner werden nur explizit mit `create_folder` angelegt; Lesen und Verschieben legen niemals Ordner an.
7. API-Domain mit gültigem TLS-Zertifikat auf `public/` richten. Bei unveränderlichem `public_html` nur `index.php` dorthin kopieren und dessen Autoloader-Pfad auf das private `vendor/autoload.php` ändern. `IMAPI_CONFIG` als serverseitige Umgebungsvariable auf den absoluten Config-Pfad setzen. Ohne diese Variable wird `../private/config.php` relativ zum Einstiegspunkt verwendet. Config, Composer-Dateien, Tests und `vendor/` niemals öffentlich bereitstellen.
8. Authorization-Header an PHP weiterreichen, unter Apache etwa mit `CGIPassAuth On` im VHost/Directory oder, falls vom Hoster unterstützt, `.htaccess` mit `SetEnvIf Authorization "(.+)" HTTP_AUTHORIZATION=$1`. Requests dürfen im Webserver, Proxy, CDN, WAF oder APM **nicht mit Headern oder Body aufgezeichnet** werden. Normale Access-Logs ohne diese Daten sind möglich. Zugangsdaten gehören ausschließlich in Header, niemals in URL/Querystring. PHP unterdrückt rohe Bibliotheksfehler und Fehlerlogs für diesen Einstiegspunkt.

Die API prüft das serverseitige `HTTPS=on/1` und lehnt HTTP mit 426 ab. Clients müssen direkt HTTPS verwenden: Ein Redirect oder eine 426-Antwort kann bereits unverschlüsselt gesendete Header nicht schützen. HTTP-Prüfungen daher immer ohne Zugangsdaten ausführen. Wenn vom Hoster unterstützt, eingehende Klartextverbindungen für diese API bereits vor PHP ablehnen. Hinter einem TLS-Proxy muss der Webserver diese Variable ausschließlich für einen vertrauenswürdigen Proxy setzen; vom Client gesendete Forwarded-Header werden nicht ausgewertet. Die IP für Rate-Limits ist `REMOTE_ADDR`: hinter einem Proxy muss der Webserver die echte IP vertrauenswürdig auflösen, sonst teilen alle Clients ein Limit.

Ausgehende Verbindungen vom Webhosting zu 993 und 465 bzw. 587 müssen erlaubt sein. Es ist kein Daemon, Framework, Datenbankserver oder Cronjob erforderlich. Rate-Limit-Dateien nutzen `flock` auf einem lokalen Dateisystem; für mehrere Webserver braucht es einen gemeinsamen atomaren Limiter. Der Limiter verwendet eine feste Anzahl begrenzter Statusdateien; abgelaufene Datensätze werden bei jedem Zugriff auf die jeweilige Datei bereinigt, auch bei ungültigen oder bereits gesperrten Anfragen.

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

   Standard: `folder=INBOX`, `limit=20` (1–100), kein Datumsfilter, `unseen_only=false`. `since` ist ein inklusives IMAP-Datum (`YYYY-MM-DD`, Kalendertag des Mailservers). `messages` enthält UID, Datum, Absender/Empfänger als `{email,name}`, Betreff, `seen`, `flagged`, `size` in Bytes und `attachment_count`. Für die genaue Anhangzahl werden Nachrichtenkörper innerhalb der Größenbudgets mit PEEK gelesen. Eine übergroße Mail bricht die Liste nicht ab: Header, UID und Größe bleiben sichtbar, `too_large:true`, `body_loaded:false` und `attachment_count:null` kennzeichnen die nicht geladene Mail. Reicht das gesamte Ladebudget nicht aus, bleiben auch die Header aller übrigen ausgewählten Mails sichtbar; deren `body_loaded` ist ebenfalls `false` und die Anhangzahl unbekannt (`null`, ausdrücklich nicht 0). Andere noch ins Budget passende Mails können weiterhin vollständig ausgewertet werden. Das Listenfeld `truncated:true` bedeutet, dass die MIME-/Anhang-Auswertung aus Größenlimitgründen unvollständig ist; es werden deshalb keine Header-Einträge entfernt. `get` und `attachment` behalten für zu große Nachrichten HTTP 413 bei. Zum Verschieben einer übergroßen Mail kann deren UID aus der Liste verwendet werden. UIDs gelten jeweils nur innerhalb des Ordners und seiner UIDVALIDITY; nach einem Server-Reset neu auflisten.

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

   Vor dem SMTP-Versand wird der Gesendet-Ordner per IMAP geprüft. Fehlt der Ordner aus der privaten Config und ist `create_sent_folder_if_missing=true`, wird er angelegt und abonniert. Schlägt diese Vorbereitung fehl, startet SMTP nicht. Ein abweichender Ordner aus der Anfrage muss bereits existieren. Bei `create_sent_folder_if_missing=false` gilt das auch für den konfigurierten Ordner. Nach bestätigter SMTP-Annahme wird die Mail per IMAP-APPEND abgelegt. Nach SMTP-Annahme lautet die Antwort immer HTTP 200 mit `ok:true`, `sent:true`, der tatsächlichen `message_id` und `saved_to_sent:true|false`. Bei fehlgeschlagener Ablage kommen `sent_folder_error` (z. B. `Ordner nicht gefunden`) und aus Kompatibilitätsgründen `warning="sent_copy_failed"` hinzu. **Dann keinesfalls erneut senden.** Außer dem konfigurierten Gesendet-Ordner werden keine Ordner automatisch angelegt.

   Pro Anfrage überschreibt `sent_folder` die private Config. `null` oder `""` überspringen die Ablage vollständig: `saved_to_sent:false` ohne `sent_folder_error` oder `warning`, und ohne IMAP-Verbindung.

   ```bash
   api '{"action":"send","to":"empfaenger@example.org","subject":"Hallo","text":"Hallo!","sent_folder":"Gesendet"}'
   api '{"action":"send","to":"empfaenger@example.org","subject":"Ohne Ablage","text":"Hallo!","sent_folder":null}'
   ```

   Beispiel, wenn die Ablage nach bestätigter SMTP-Annahme fehlschlägt (etwa weil der zuvor geprüfte Ordner zwischenzeitlich entfernt wurde):

   ```json
   {"ok":true,"data":{"sent":true,"message_id":"<id@example.org>","saved_to_sent":false,"sent_folder_error":"Ordner nicht gefunden","warning":"sent_copy_failed"}}
   ```

   Lehnt SMTP die Nachricht ab oder scheitert die Verbindung vor der Übergabe, kommt `ok:false`, Fehlercode `smtp_failed` (bei Authentifizierungsfehlern `mail_auth_failed`) und der Hinweis, dass nichts versendet wurde. Geht nach DATA die Bestätigung verloren, kann der Server die Mail bereits angenommen haben: dann kommt `smtp_status_unknown` mit dem Hinweis, vor einer Wiederholung die Zustellung zu prüfen. Eine sichere Aussage „nichts versendet“ ist in diesem Fall technisch nicht möglich. Bei bestätigter Annahme für einzelne Empfänger bleibt `sent:true`, auch wenn andere Empfänger abgelehnt wurden; `smtp_warning` weist darauf hin. SMTP und IMAP sind nicht atomar. Es gibt keine automatische Wiederholung und keine Idempotenz-Datenbank.

6. Gelesen-/Stern-Markierung setzen oder entfernen und optional verschieben:

   ```bash
   api '{"action":"flag","folder":"INBOX","uid":123,"seen":true,"flagged":true}'
   api '{"action":"flag","folder":"INBOX","uid":123,"seen":false,"flagged":false}'
   api '{"action":"flag","folder":"INBOX","uid":123,"move_to":"Archiv"}'
   ```

   Nicht angegebene Markierungen bleiben erhalten. Kombination mit `move_to` ist möglich; einzelne IMAP-Operationen sind nicht atomar. Nach Fehlern den Zustand neu lesen. Zielordner muss existieren. Verschieben verwendet ausschließlich RFC-6851-`UID MOVE`, ohne COPY/DELETE/EXPUNGE-Fallback. Unterstützt der Server MOVE nicht, kommt 409 vor jeder Änderung. Die UID im Zielordner kann sich ändern; dort neu auflisten. Es gibt keinen Lösch-Endpunkt und keine frei wählbaren IMAP-Flags.

7. Ordner explizit anlegen und abonnieren:

   ```bash
   api '{"action":"create_folder","folder":"Gesendet"}'
   api '{"action":"create_folder","folder":"Archiv/2026"}'
   ```

   Antwort: `{"ok":true,"data":{"folder":"Gesendet","created":true}}`. Ist der Ordner schon vorhanden, kommt dieselbe Erfolgsantwort mit `created:false`; er wird ebenfalls abonniert. Wiederholte Aufrufe sind damit möglich. Falls nur das Abonnieren scheitert, kommt `folder_subscribe_failed`; ein erneuter Aufruf versucht es nochmals.

   `folder` ist erforderlich. Leere Namen, ungültiges UTF-8, Steuerzeichen, führende/abschließende Leerzeichen, Backslashes, Wildcards (`*`, `%`), Anführungszeichen, Namespace-Präfix `#`, leere Pfadsegmente und `.`/`..`-Segmente werden mit 400 abgelehnt. `/` ist eine portable Hierarchieschreibweise und wird bei Bedarf in das vom Server gemeldete Trennzeichen umgewandelt (z. B. `Archiv.2026`). Die Antwort enthält den tatsächlichen Pfad. Der native Pfad ist ebenfalls zulässig; gemischte Trennzeichen nicht. Die API bietet weder Löschen noch Umbenennen von Ordnern und führt für die Anlage kein EXPUNGE aus.

## Ausgehende Verbindungen und Schutz vor Überlastung

`allowed_mail_hosts` ist eine zusätzliche Server-Whitelist in der privaten Config, unabhängig von `allowed_mailboxes`. Ausschließlich der Administrator bestimmt `mail_host`; der Client kann weder Host noch Ports, TLS-Optionen oder die Whitelist überschreiben. Ein nicht freigegebener Host führt vor jedem Verbindungsversuch zu `mail_server_forbidden` (503). Aus Kompatibilitätsgründen gilt für ältere Configs ohne neue Option ausschließlich der ursprüngliche Host `cloud3-vm338.de-nserver.de` als erlaubt.

```php
'allowed_mail_hosts' => ['cloud3-vm338.de-nserver.de', 'sann.cc', 'sann.gmbh', 'essenzenladen.de', 'ausflowers.de'],
'mail_host' => 'cloud3-vm338.de-nserver.de',
'local_only' => false,
'create_sent_folder_if_missing' => true,
```

Optional beschränkt **`local_only => true` ausschließlich ausgehende IMAP-/SMTP-Verbindungen** auf die feste IPv4-Loopback-Adresse `127.0.0.1`. Es gibt keinen DNS-Fallback auf andere Adressen. Host-Whitelist und feste Mailports gelten weiterhin. Der freigegebene `mail_host` bleibt der TLS-Peername und wird für SNI und die Zertifikatsprüfung verwendet; TLS wird auch lokal nicht abgeschaltet. Der Schalter setzt erreichbare Maildienste auf derselben Maschine voraus. Sind diese nicht verfügbar oder passt ihr Zertifikat nicht, scheitert die Verbindung geschlossen. Die eingehende HTTPS-Erreichbarkeit der API wird davon nicht verändert. Standard ist `false`.

Die Reihenfolge ist HTTPS/Methode → Config-Prüfung ohne Netzwerk → IP-Limiter und Bearer-Verifikation → JSON/Postfach-Whitelist → Mail-Anmeldelimiter → IMAP/SMTP. Ohne gültigen Bearer-Token gibt es keine ausgehenden Mailverbindungen. Bei einem defekten Limiter wird mit 503 abgebrochen, bevor der Mailserver angesprochen wird. Ein gültiger API-Key ersetzt nicht die Mail-Anmeldedaten.

Das IP-Limit und die temporäre Sperre helfen gegen einzelne missbräuchliche Clients, garantieren aber keinen DDoS-Schutz. Bereits TLS-Verbindungen, PHP-Prozesse und die bcrypt-Verifikation beanspruchen Ressourcen; viele verschiedene Quell-IP-Adressen umgehen ein reines Limit pro IP. Für größere Angriffe muss der Hoster bzw. ein vorgeschalteter Reverse Proxy/WAF Verbindungen und Anfragen begrenzen, bevor PHP erreicht wird. Bei Proxys `REMOTE_ADDR` ausschließlich aus vertrauenswürdiger Infrastruktur ableiten. Das Projekt verändert keine globale Firewall- oder Hosting-Konfiguration.

## Limits und Statuscodes

Standard: 60 Anfragen je Minute/IP-Netz (gleitendes Fenster). IPv4 wird pro Adresse gezählt, IPv4-mapped IPv6 entsprechend normalisiert und IPv6 pro /64-Präfix. Fünf falsche API-Keys innerhalb von 15 Minuten sperren das IP-Netz für 15 Minuten. Plausibel formatierte Tokens werden mit `password_verify` geprüft; fehlende oder fehlerhaft formatierte Header werden ohne bcrypt-Aufwand abgelehnt. Auch falsche Keys zählen zum Anfragelimit.

Zusätzlich werden tatsächliche Mail-Anmeldefehler aus IMAP sowie SMTP 534/535 gezählt. Standard: fünf Fehler je IP-Netz innerhalb von 15 Minuten führen zu 15 Minuten Sperre; zehn Fehler für dasselbe Postfach über verschiedene IPs führen zu einer kurzen Sperre von 60 Sekunden. Diese kurze Postfachsperre begrenzt das Risiko, mit einem kompromittierten API-Key legitime Nutzer lange auszusperren. Beide Sperren liefern `mail_auth_rate_limited` (429) mit `Retry-After` und verhindern weitere Mailverbindungen. Bereits laufende Anfragen werden vor dem Netzwerkzugriff reserviert, damit parallele Versuche die Schwelle nicht umgehen. Reservierungen laufen bei abgebrochenen Prozessen nach drei Minuten aus. Erfolgreiche Anfragen entfernen ihre Reservierung, löschen aber nicht die Fehler anderer paralleler Anfragen.

```php
'failed_mail_logins_before_block' => 5,
'mail_auth_block_seconds' => 900,
'failed_mail_logins_per_mailbox' => 10,
'mailbox_auth_block_seconds' => 60,
```

Der Statusspeicher ist begrenzt: getrennt für IP-/API-Limits und Mail-Anmeldungen je maximal 64 feste Dateien, maximal 128 aktive Datensätze und 2 MiB pro Datei. Es gibt keine Datei pro IP oder Postfach mehr. Unauthentifizierte Anfragen können den getrennten Mail-Anmeldespeicher nicht füllen. Abgelaufene Datensätze werden vor der Key-Prüfung und auch bei 401/429 entfernt. Auf eine belegte Dateisperre wird höchstens rund 250 ms gewartet; danach folgt 503 mit `Retry-After: 1`, statt PHP-Prozesse unbegrenzt warten zu lassen. Aktive Sperren werden bei Platzmangel nicht verdrängt; neue Identitäten erhalten dann `rate_limit_capacity` (503). Statusdateien enthalten nur Zeitstempel, Reservierungskennungen und Zähler unter gehashten Identitäten; weder Mail-Benutzernamen noch Passwörter oder API-Keys werden gespeichert. Postfachkennungen verwenden HMAC mit dem privaten API-Key-Hash.

Bei einem Update vom früheren Format nach Aktivierung des neuen Codes einmalig mit der passenden PHP-CLI-Version ausführen:

```bash
php bin/limiter-migrate.php
```

Das Skript übernimmt noch wirksame IPv4-Limits/Sperren und verschiebt alte Einzeldateien in ein privates Backup neben dem Statusverzeichnis. Für eine abweichende Config wie sonst `IMAPI_CONFIG` setzen. Alte IPv6-Einzeladress-Hashes lassen sich ohne gespeicherte Klartextadressen nicht in /64-Kennungen umrechnen; diese Grenzen beginnen mit dem neuen Format neu. Der neue Betrieb benötigt weder eine Datenbank noch einen Cronjob. Backups gehören nicht zum aktiven Statusspeicher und können nach der üblichen Aufbewahrung manuell entfernt werden.

Diese Maßnahmen begrenzen Anwendungsressourcen und Passwortversuche, ersetzen aber keinen vorgeschalteten DDoS-Schutz. Sperrschwellen des Mailservers müssen mit dem Hoster abgestimmt werden: dessen eigene IP-Sperre kann sonst die gemeinsame Gateway-IP treffen. Bei einem kompromittierten API-Key diesen umgehend rotieren.

| HTTP | Bedeutung |
| --- | --- |
| 400 | Ungültiges JSON, Aktion oder Parameter |
| 401 | API-Key fehlt oder ist falsch |
| 403 | Mail-Anmeldung fehlgeschlagen oder Postfach nicht erlaubt |
| 404 | Ordner, UID oder Anhang fehlt; sent_folder_not_found vor SMTP verhindert den Versand |
| 405 | Methode außer POST |
| 409 | Sichere Verschiebung vom Mailserver nicht unterstützt |
| 413 | Anfrage oder vollständige Nachricht zu groß; list bleibt als Header-Liste verfügbar |
| 415 | Content-Type ist nicht application/json |
| 426 | HTTPS erforderlich |
| 429 | API-/Mail-Anmeldelimit, IP-Netz- oder Postfachsperre; Retry-After beachten |
| 502 | Mailserver-/Transportfehler, u. a. smtp_failed, smtp_status_unknown, folder_create_failed, folder_subscribe_failed, sent_folder_prepare_failed |
| 503 | Config/Rate-Limit nicht verfügbar, Statusspeicher voll oder Mailhost nicht freigegeben |

Standardgrößen: 20 MiB JSON-Anfrage, 12 MiB vollständige MIME-Nachricht, 32 MiB gelesene Nachrichten pro Liste. Webhosting-Limits (`memory_limit`, `post_max_size`, Webserver-Bodylimit) entsprechend einstellen, z. B. 256 MiB PHP-Speicher und 24 MiB `post_max_size`. Base64 und MIME-Decodierung benötigen zusätzlichen Speicher. Vorgeschaltete Serverlimits können eigene Fehlerseiten liefern, bevor PHP ausgeführt wird. Netzwerk-Timeout jeweils 20 Sekunden; Laufzeitlimit des Hosters beachten.

## Entwicklung

Lokaler Apache-VHost: `dev/imapi.test.conf`, ausschließlich `public/` als DocumentRoot. `imapi.test` muss auf dem verwendeten Rechner zum Dev-Server auflösen; `.test` ist keine öffentliche Domain. Das Entwicklungszertifikat liegt unversioniert unter `.dev/`, der private Schlüssel wird nicht veröffentlicht. In der laufenden Umgebung: **https://imapi.test/**. Auf einem anderen Rechner Hosts/DNS-Eintrag und Zertifikatsvertrauen ergänzen.

```bash
composer install  # Mit Entwicklungsabhängigkeiten einschließlich PHPStan
composer validate --strict
composer check-platform-reqs --no-dev
php bin/check.php
composer analyse # PHPStan Level 6 für public/, bin/, tests/ und Beispielconfig
composer test     # Funktions-, Authentifizierungs-, IMAP- und SMTP-Tests; CLI pcntl/posix erforderlich
```

`composer check` führt Composer-Validierung, PHPStan und alle PHP-Tests zusammen aus; `composer test` nur die Tests. Die GitHub-Actions-CI führt die Analyse und Tests bei jedem Push und Pull Request unter PHP 8.2, 8.3, 8.4 und 8.5 aus. PHPStan ist ausschließlich eine Entwicklungsabhängigkeit und wird beim Produktionsdeployment mit `composer install --no-dev` nicht installiert. Die Analyse verwendet keine Baseline und keine unterdrückten Fehler. Der lokale Analysecache wird nicht versioniert.

Die Tests prüfen MIME/UTF-8, Anhänge, Bcc, Thread-Header, Eingabevalidierung, Größenlimit, Postfach-Whitelist und Rate-Limit/IP-Sperre. Sicherheitsregressionen decken große Mails und ausgeschöpfte Listenbudgets, IPv6-/64-Gruppierung, feste Speichergrenzen, Bereinigung ohne gültigen Key, Migration bestehender Sperren und Mail-Anmeldesperren einschließlich paralleler Reservierungen ab. Der Authentifizierungstest fängt die Socket-Funktionen beider Bibliotheken ab und weist null Verbindungsversuche bei fehlenden/falschen Tokens nach; außerdem prüft er Loopback-Pinning mit unveränderter TLS-Prüfung. Die IMAP-/SMTP-Protokolltests verwenden ausschließlich lokale Testserver. Sie prüfen PEEK, explizites Markieren, CREATE/SUBSCRIBE mit vorhandenen und neuen Ordnern, Zeichensatz/Trennzeichen sowie Vorbereitung des konfigurierten Gesendet-Ordners vor SMTP, Versandabbruch bei fehlgeschlagener Vorbereitung, SMTP-Annahme trotz später fehlgeschlagener Ablage, übersprungene Ablage, Ablehnung, teilweise Empfängerannahme und verlorene Bestätigung. Optional prüft `IMAPI_TEST_KEY=… python3 tests/gateway.py` die laufende lokale HTTPS-API ohne echte Postfachzugänge; den Key dabei über eine geschützte Shellvariable setzen. Für den echten Postfach-Smoke-Test die obigen Aufrufe mit einem Testpostfach ausführen; dafür werden keine Zugangsdaten im Projekt hinterlegt.

Öffentliches Repository vorbereiten: ausschließlich versionierte Dateien hochladen, niemals `private/`, `.dev/`, Header-Dateien oder Maildaten. GitHub CLI nach Anmeldung etwa: `gh repo create imapi --public --source=. --remote=origin --push`. Die Lizenz ist MIT; siehe `LICENSE`.

Bibliotheken: [PHPMailer](https://github.com/PHPMailer/PHPMailer), [Webklex PHP-IMAP](https://github.com/Webklex/php-imap). Hintergrund: Die [native PHP-IMAP-Erweiterung](https://www.php.net/manual/en/imap.installation.php) ist seit PHP 8.4 in PECL und wird hier nicht benötigt.
