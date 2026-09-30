# Security

Yunkai Desktop Bridge is intentionally capability-bounded.

## Invariants

- No arbitrary shell, PowerShell, cmd, registry-edit, uninstall, shutdown/reboot, raw file-delete, or unrestricted process-kill MCP tools.
- Read-only inspection should precede input actions.
- Runtime permission tiers are configured locally, not chosen by the remote caller.
- Sensitive UI actions remain guarded by foreground-window and semantic-target checks.
- Verified actions never automatically retry the input.
- Secret values remain local and are not returned through MCP.

## Public-repository hygiene

Do not commit tunnel IDs, API keys, cookies, OAuth material, DPAPI blobs, browser profiles, owner-specific absolute paths, runtime state, screenshots, or private logs.

## Reporting

Do not post secrets or private user data in a public issue. If GitHub private vulnerability reporting is available for this repository, use it. Otherwise open a minimal issue without exploit secrets and request a private contact path.
