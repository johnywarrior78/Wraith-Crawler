#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys

from wraith_crawler.persistence.database import Database
from wraith_crawler.persistence.reporting_views import verify_reporting_views


def main() -> int:
    database_url = os.getenv("WRAITH_DATABASE_URL")
    if not database_url:
        print("WRAITH_DATABASE_URL is required", file=sys.stderr)
        return 2
    database = Database(database_url)
    with database.engine.connect() as connection:
        results = verify_reporting_views(connection)
    print(json.dumps(results, indent=2, sort_keys=True))
    return 0 if results and all(results.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
