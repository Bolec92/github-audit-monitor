#!/usr/bin/env python3
import argparse
import os
import sys

from security import (
    MASTER_KEY_PATH, SECURITY_DB_PATH, create_setup_code, ensure_master_key,
    has_admin, init_security_db, migrate_legacy_env_connection,
)


def main():
    parser = argparse.ArgumentParser(description="GitHub Audit Monitor security bootstrap")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init", help="initialize security storage and emit a first-run setup code if needed")
    sub.add_parser("rotate-setup-code", help="generate a new setup code; only useful before the first admin is created")
    sub.add_parser("migrate-env", help="encrypt a legacy GITHUB_TOKEN/GITHUB_ORG from the environment")
    args = parser.parse_args()

    if args.command in {"init", "rotate-setup-code"}:
        ensure_master_key(create=True)
        init_security_db()
        if args.command == "init" and has_admin():
            print("ADMIN_EXISTS=1")
            return 0
        code = create_setup_code(force=False)
        print(f"SETUP_CODE={code}")
        print(f"SECURITY_DB={SECURITY_DB_PATH}")
        print(f"MASTER_KEY={MASTER_KEY_PATH}")
        return 0

    if args.command == "migrate-env":
        ensure_master_key(create=True)
        init_security_db()
        changed = migrate_legacy_env_connection()
        print("MIGRATED=1" if changed else "MIGRATED=0")
        return 0

    return 2


if __name__ == "__main__":
    sys.exit(main())
