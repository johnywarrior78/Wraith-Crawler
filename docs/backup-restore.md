# Backup and Restore

`backup.sh` creates custom-format PostgreSQL dumps for both Wraith and Metabase plus restricted copies of the runtime environment files and checksums. The directory is mode 0700 and contains secrets; encrypt and protect off-host copies.

```bash
sudo ./backup.sh /secure/backup/wraith-2026-08-13
```

`upgrade.sh` automatically creates a pre-upgrade backup, stops the API, updates the application, runs forward Alembic migrations, reconciles Metabase, restarts services, and runs doctor. It does not wipe assessment history, users, attack paths, or dashboards.

Restore is intentionally guarded and destructive to the selected destination databases:

```bash
sudo ./restore.sh /secure/backup/wraith-2026-08-13
```

The script verifies checksums and requires typing `RESTORE`, then stops services, uses `pg_restore --clean --if-exists`, restarts services, and instructs the operator to rerun doctor. Rehearse restores in an isolated environment and verify findings, attack paths, views, reports, and dashboards before declaring the backup valid.
