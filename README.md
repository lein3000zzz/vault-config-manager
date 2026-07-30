# vault-config-manager

A small HashiCorp Vault config manager, used across several microservices in one of my projects.

It walks a Vault KV v2 mount, flattens every secret it finds into one in-memory config, serves
typed getters off it, and optionally re-reads Vault on a ticker and tells you when something
changed.

```go
import "github.com/lein3000zzz/vault-config-manager/pkg/manager"
```

## Requirements

- Go 1.26.4 (the logging port lines up with [the-watchers](https://github.com/lein3000zzz/the-watchers))
- A Vault KV v2 mount, since the manager reads through `data/` and lists through `metadata/`

## Quick start

```go
ctx := context.Background()

sm, err := manager.NewSecretManager(
	os.Getenv("VAULT_ADDRESS"),
	os.Getenv("VAULT_TOKEN"),
	manager.DefaultBasePathData,     // "kv/data/"
	manager.DefaultBasePathMetaData, // "kv/metadata/"
	logger,
)
if err != nil {
	return err
}

// Nothing is loaded until you ask - the updater only reacts to its ticker
if err := sm.ResetConfig(ctx); err != nil {
	return err
}

dsn, err := sm.GetSecretStringFromConfig(ctx, "postgres_dsn")
```

An empty `vaultAddr` leaves the Vault client on its own defaults, so `VAULT_ADDR` is picked up from
the environment. Both base paths get a trailing `/` appended if you leave it off.

## Logging

`manager.Logger` is a subset of `logging.Logger` from
[the-watchers](https://github.com/lein3000zzz/the-watchers), written in stdlib types only so this
module needs no dependency on it:

```go
type Logger interface {
	Debug(ctx context.Context, msg string, args ...any)
	Info(ctx context.Context, msg string, args ...any)
	Warn(ctx context.Context, msg string, args ...any)
	Error(ctx context.Context, msg string, args ...any)
}
```

`args` is a run of alternating keys and values, as `slog` takes them. A the-watchers logger
satisfies this directly, with no adapter in between:

```go
logger, err := slogging.NewSlogLoggerWithConfig(slogging.Config{
	Level:    logging.LevelInfo,
	Format:   logging.FormatJSON,
	ToStdout: true,
})
```

`cmd/vaultConfigManager` wires exactly that, end to end. Anything else with those four methods works
too - a `*slog.Logger` needs a three-line shim, since its methods are `DebugContext`/`InfoContext`.
`manager.NoopLogger()` discards everything, and is the fallback when `NewSecretManager` is handed a
nil logger.

There is deliberately no `Fatal` on the port: the-watchers treats fatality as a severity rather than
an action, so the manager reports unrecoverable conditions by returning an error and leaves the
decision to end the process to you.

## How the config is assembled

`metadata/` is walked depth-first from the base path, and every folder found is read through
`data/`. Every key lands in **one flat namespace** - folder structure organises secrets in Vault but
does not namespace them here, so `main/db` and `test/db` both contribute a bare `db`.

On a collision the first value wins, and because the walk is stack-based the winner is not
stable across runs. Keep keys unique across folders.

A full read never aborts early: a folder that fails is skipped, its error is joined onto the rest,
and the walk carries on to the end. But `ResetConfig` and `UpdateConfig` then treat any non-nil
error as fatal to the whole operation and throw the partial result away, so **one unreadable folder
means the config is left exactly as it was**. Folders that are only structure and hold no secrets of
their own are not errors - an empty read is excluded from the aggregate.

Numbers arrive from Vault as `json.Number` and are stored as `float64`, which is why
`GetSecretIntFromConfig` accepts both `float64` and `int`.

## API

Everything below is on `*SecretManagerVault`, and the `SecretManager` interface mirrors it
(`var _ SecretManager = (*SecretManagerVault)(nil)` keeps the two from drifting).

**Loading**

| Method | Effect |
| --- | --- |
| `ResetConfig(ctx)` | Full read from Vault, replaces the config wholesale |
| `UpdateConfig(ctx)` | Full read from Vault, merges over the current config |
| `ReloadConfig(ctx)` | `PurgeConfig` then `ResetConfig` |
| `UpdateConfigByPath(ctx, path)` | Reads one path, merges the keys it holds |
| `UpdateSpecificSecret(ctx, folder, key)` | Reads one key, stores it, returns it |
| `PurgeConfig()` | Empties the config, touches no network |

Paths are relative to the base paths given to the constructor, and start without a leading slash -
`UpdateSpecificSecret(ctx, "test/", "password")`.

**Reading**

`GetSecretStringFromConfig`, `GetSecretBoolFromConfig`, `GetSecretIntFromConfig` and
`GetSecretFloat64FromConfig`, all `(ctx, key)`. A missing key gives `ErrKeyNotFound`; a key holding
the wrong type gives the matching `ErrWhileConvertingTo*`.

**Background updates**

```go
go sm.StartConfigUpdater(ctx, manager.DefaultConfigUpdateInterval) // 5m

for range sm.GetNotifierChannel() {
	// config changed, re-read what you care about
}
```

`StartConfigUpdater` blocks, so run it in a goroutine. On each tick it does a full read and, only if
the result actually differs from what it last saw, swaps the config in and pokes the notifier. It
does **not** load anything up front - do that yourself with `ResetConfig`.

The notifier is buffered to one. If a notification cannot be delivered it is dropped with a warning
rather than blocking the updater, so treat it as "something changed", not as a queue of changes. It
is closed when the updater returns, which ends the `range` above.

The updater stops on `StopUpdater()` or on `ctx` cancellation. `StopUpdater` returns
`ErrAlreadyClosed` if called twice, and a second `StartConfigUpdater` logs a warning and returns
rather than starting a rival goroutine.

**Unsealing**

```go
if err := sm.UnsealVault(ctx, keys); err != nil {
	return err
}
```

Returns immediately if the vault is already unsealed, otherwise tries the keys in order. Failures
are joined and returned; if every key is spent and the vault is still sealed you get
`ErrStillSealed`.

## Errors

All comparisons go through `errors.Is`, and aggregates are built with `errors.Join`.

`ErrKeyNotFound`, `ErrNotMapInterface`, `ErrWhileConvertingToString`, `ErrWhileConvertingToBool`,
`ErrWhileConvertingToInt`, `ErrWhileConvertingToFloat`, `ErrEmptyVaultResponse`, `ErrAlreadyClosed`,
`ErrNoKeysList`, `ErrStillSealed`.

## Concurrency

The config is behind an `RWMutex`, so the getters and the updater are safe to use from several
goroutines at once.

## Development

Bare `make` runs `check`: fmt, vet, and the tests that need no Docker. `make test` also runs the
testcontainers-backed integration test against a real Vault container, and `CI=1` is what makes that
one skip itself.

`make cover`, `make lint` (needs golangci-lint), `make tidy` and `make clean` are there too.