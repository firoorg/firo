# SQLite wallet storage

On Linux, Firo supports writable Berkeley DB (BDB) and SQLite wallet
databases during the coexistence period. Other supported targets use BDB-only
wallet builds. BDB wallets remain supported and are never migrated
automatically.

## Build configuration

Wallet builds currently require BDB support. On Linux, SQLite wallet support
is controlled independently:

```bash
cmake -S . -B build \
  -DWITH_BDB=ON \
  -DENABLE_SQLITE_WALLET=ON
```

`ENABLE_SQLITE_WALLET` defaults to `ON` and is currently supported only on
Linux. The Linux depends build supplies SQLite 3.50.4. A supported BDB-only
build uses:

```bash
cmake -S . -B build-bdb \
  -DWITH_BDB=ON \
  -DENABLE_SQLITE_WALLET=OFF
```

For depends, `NO_SQLITE=1` omits SQLite from the packages built and installed
and configures the resulting toolchain with SQLite wallet support disabled.
Depends toolchains generated for non-Linux targets do this automatically. A
BDB-only binary creates BDB wallets and rejects an existing SQLite wallet
before mutation. SQLite-only wallet builds are not supported.

A direct non-Linux configuration must pass
`-DENABLE_SQLITE_WALLET=OFF`; leaving the option enabled fails during
configuration with an actionable error. Windows and macOS remain supported
with writable BDB wallets.

The secure SQLite lifecycle requires Linux kernel and filesystem support for
atomic no-replace publication, atomic exchange during migration and recovery,
and durable file and directory synchronization. Creation, backup, recovery,
or migration fails closed when a required operation is unavailable or cannot
be verified.

## Creating and identifying wallets

When SQLite support is enabled, a new wallet uses SQLite by default:

```bash
firod -wallet=wallet-new.dat
```

Create a BDB wallet explicitly during coexistence with:

```bash
firod -wallet=wallet-bdb.dat -walletdbformat=bdb
```

`-walletdbformat=sqlite` explicitly selects SQLite for a new wallet. The
option only selects the format during creation. An existing wallet is
identified from its file contents and retains its format even if a different
creation selector is supplied later.

The active backend is reported by:

```bash
firo-cli getwalletinfo
```

The `format` field is `sqlite` or `bdb`.

## Explicit BDB-to-SQLite migration

Stop Firo cleanly, then request a one-time migration of the selected existing
BDB wallet:

```bash
firod -wallet=wallet-bdb.dat -migratewalletdb
```

Migration is explicit and cannot be combined with `-walletdbformat`,
`-salvagewallet`, wallet zap options, or `-upgradewallet`. It first creates a
private, collision-safe BDB backup, copies every raw wallet record into a new
SQLite transaction, verifies the candidate, and publishes it at the latest
safe filesystem boundary. The retained backup's exact absolute path is
reported in the successful migration log message.

The backup is never deleted or overwritten by migration. A failure before
publication leaves the BDB source authoritative. Atomic exchange prevents a
missing final wallet path on supported platforms, but power-loss durability
still depends on the filesystem honoring file and directory synchronization.
No migration is attempted during ordinary startup, wallet creation, backup,
or software upgrade.

## Backup

Use the RPC or the GUI while the wallet is running:

```bash
firo-cli backupwallet /secure/backups/wallet-2026-08-01.dat
```

For SQLite, this creates and verifies a consistent live snapshot using the
SQLite backup API. Do not copy a live SQLite wallet file directly and do not
copy its rollback journal, WAL, or shared-memory file. SQLite backups are
owner-private and never overwrite an existing destination; choose a new
absent filename for every snapshot.

BDB backup retains its existing behavior: it checkpoints the database and
overwrites an existing destination. Using a new absent destination is still
recommended so an earlier backup remains available.

`backupwallet` accepts either a filename or a directory. The backup location
is the path selected by the caller; automatic recovery and explicit migration
report their separate retained backup paths.

## Offline restoration

Firo does not provide a runtime `restorewallet` operation. Restore a backup
only while the wallet is stopped:

1. Stop Firo cleanly and retain the original wallet and the backup.
2. Choose a new, absent, flat wallet filename inside the active network data
   directory. Do not replace the original wallet in place.
3. Confirm that the destination and its `-journal`, `-wal`, and `-shm`
   side-file names are all absent.
4. Copy the verified backup to the new filename with the same owner and mode
   `0600`. Use a copy method that exclusively creates the absent destination
   without following symlinks. Set a restrictive umask before copying; a
   default umask followed by a later `chmod` can expose the file temporarily.
5. Start Firo with the new logical filename, for example:

   ```bash
   firod -wallet=wallet-restored.dat
   ```

6. Confirm `getwalletinfo.format`, expected addresses and balances, and wallet
   unlock behavior before making the restored wallet authoritative.

The main SQLite backup is self-contained; no SQLite side file should be
restored with it. Keep the original and backup until the restored wallet has
been verified and backed up again to another absent path.
