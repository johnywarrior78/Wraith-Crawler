# CLI

```bash
sudo wraith-crawler -u https://authorized.example
sudo wraith-crawler --url https://authorized.example:8443/app
sudo wraith-crawler --file /absolute/path/to/targets.txt --profile standard
sudo wraith-crawler --file /absolute/path/to/targets.txt --plugin seed_http --plugin tls
sudo wraith-crawler --url https://authorized.example \
  --plugin seed_http --plugin html_discovery --plugin cookie_security \
  --plugin cms_detection --plugin directory_listing
sudo wraith-crawler --url https://authorized.example --exclude-plugin katana
sudo wraith-crawler doctor
sudo wraith-crawler coverage
sudo wraith-crawler report ASSESSMENT_ID --format both --output output
```

These examples use the installed `/usr/local/bin/wraith-crawler` launcher. In an editable development virtualenv, invoke `wraith-crawler` directly without `sudo`.
Use an absolute path for target files; the service account must be able to read the file.

Target files ignore blank lines and lines beginning with `#`, canonicalize URLs, and deduplicate them. Only absolute `http://` and `https://` URLs are accepted. Batch scans honor target concurrency; one target exception is returned independently and does not stop other targets.

`--plugin` may be repeated to select capabilities. `--exclude-plugin` may be repeated. `--profile`, `--llm`, `--llm-model`, `--environment`, `--output`, and `--verbose` control the assessment. `WRAITH_DATABASE_URL` is preferred over `--database-url` because command arguments may be visible to other local users.

Every successful target prints its persisted assessment ID. A fully failed batch exits nonzero; partial batch success still exposes failed targets in output.

The focused detection workflow includes its declared prerequisites: `seed_http` captures the initial response, `html_discovery` supplies evidence-derived in-scope paths, `cookie_security` inventories likely authentication/session cookies without retaining their values, `cms_detection` applies passive multi-signal fingerprints, and `directory_listing` performs bounded GET checks against at most 10 discovered directory candidates.
