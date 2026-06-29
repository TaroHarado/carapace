# Release Validation

This file records the current manual smoke validation status for local Windows
release binaries.

## Validated artifact path

```text
target/release/cape.exe
```

## Smoke results

### `scripts/smoke-release.ps1`

```text
== cape smoke (windows) ==
help: ok
audit: ok
registry: ok
score: ok
smoke: ok
```

### `scripts/smoke-local.ps1`

```text
== SafeRouter local smoke ==
health: ok
invalid score request: ok
session init: ok
policy evaluate: ok
site: ok
smoke-local: ok
```

## Meaning

The local-first beta works end-to-end on a real release binary, not just from
`target/debug` or source-driven commands.

That does **not** replace cross-platform artifact checks from GitHub Actions,
but it closes the most important local reality gap before public launch.

## Note on tags

If the latest public GitHub release artifact fails smoke, cut a new RC tag.
Do not trust the age of the tag; trust the smoke result.
