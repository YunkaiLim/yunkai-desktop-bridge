from __future__ import annotations

import argparse
import getpass
import sys

from secret_vault import SecretVault, SecretVaultError, normalize_alias


def _set(vault: SecretVault, alias: str) -> int:
    normalized = normalize_alias(alias)
    first = getpass.getpass(f"Secret value for {normalized}: ")
    second = getpass.getpass("Confirm secret value: ")
    if first != second:
        raise SecretVaultError("Secret confirmation did not match.")
    info = vault.set_secret(normalized, first)
    print(f"Saved alias '{info.alias}' with Windows DPAPI. Secret value was not printed.")
    return 0


def _list(vault: SecretVault) -> int:
    aliases = vault.list_aliases()
    if not aliases:
        print("No secret aliases are stored.")
        return 0
    print("Stored secret aliases (values are never shown):")
    for item in aliases:
        print(f"- {item.alias}  updated={item.updated_at}")
    return 0


def _delete(vault: SecretVault, alias: str) -> int:
    normalized = normalize_alias(alias)
    confirm = input(f"Delete local alias '{normalized}'? Type DELETE to confirm: ").strip()
    if confirm != "DELETE":
        print("Cancelled.")
        return 1
    deleted = vault.delete_secret(normalized)
    print("Deleted." if deleted else "Alias did not exist.")
    return 0


def _bind(vault: SecretVault, alias: str, window_title: str, name: str | None, automation_id: str | None) -> int:
    target = vault.bind_target(
        alias,
        window_title=window_title,
        name=name,
        automation_id=automation_id,
    )
    print(
        "Bound remote input target: "
        f"alias={normalize_alias(alias)} window={target['window_title']!r} "
        f"name={target['name']!r} automation_id={target['automation_id']!r}"
    )
    return 0


def _interactive(vault: SecretVault) -> int:
    while True:
        print("\nYunkai DesktopBridge Secret Vault")
        print("1. Set or update secret alias")
        print("2. Bind alias to an allowed window/input target")
        print("3. List aliases")
        print("4. Delete alias")
        print("5. Exit")
        choice = input("Choose: ").strip()
        if choice == "1":
            alias = input("Alias, e.g. openai_runtime: ").strip()
            _set(vault, alias)
        elif choice == "2":
            alias = input("Alias to bind: ").strip()
            window_title = input("Exact active window title: ").strip()
            name = input("Exact UIA edit name (leave blank if using automation_id): ").strip() or None
            automation_id = input("Exact UIA automation_id (optional): ").strip() or None
            _bind(vault, alias, window_title, name, automation_id)
        elif choice == "3":
            _list(vault)
        elif choice == "4":
            alias = input("Alias to delete: ").strip()
            _delete(vault, alias)
        elif choice == "5":
            return 0
        else:
            print("Unknown choice.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Manage local DPAPI-protected DesktopBridge secret aliases.")
    sub = parser.add_subparsers(dest="command")
    set_parser = sub.add_parser("set", help="Set or update an alias without echoing the secret.")
    set_parser.add_argument("alias")
    sub.add_parser("list", help="List aliases only; values are never exposed.")
    bind_parser = sub.add_parser("bind", help="Bind an alias to one exact allowed window/input target.")
    bind_parser.add_argument("alias")
    bind_parser.add_argument("--window", required=True)
    bind_parser.add_argument("--name")
    bind_parser.add_argument("--automation-id")
    delete_parser = sub.add_parser("delete", help="Delete one local alias.")
    delete_parser.add_argument("alias")
    args = parser.parse_args()

    vault = SecretVault()
    try:
        if args.command == "set":
            return _set(vault, args.alias)
        if args.command == "list":
            return _list(vault)
        if args.command == "bind":
            return _bind(vault, args.alias, args.window, args.name, args.automation_id)
        if args.command == "delete":
            return _delete(vault, args.alias)
        return _interactive(vault)
    except SecretVaultError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
