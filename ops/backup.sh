#!/bin/sh
# Destination must be an encrypted backup filesystem under operator control.
set -eu
: "${BACKUP_DIR:?Set the protected encrypted backup destination}"
umask 077
stamp=$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p "$BACKUP_DIR/$stamp"
docker compose exec -T db pg_dump -U browser -d browser -Fc > "$BACKUP_DIR/$stamp/browser.dump"
# Encrypted vault + artifacts. Files may contain private customer data even if
# browser profiles themselves are encrypted; protect this archive at rest.
docker compose exec -T browser tar -C /data -czf - profiles > "$BACKUP_DIR/$stamp/profiles.tar.gz"
cp secrets/profile_key "$BACKUP_DIR/$stamp/profile_key"
printf 'Backup saved: %s\n' "$BACKUP_DIR/$stamp"
