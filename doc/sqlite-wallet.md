# SQLite wallet storage

On Linux, macOS, and Windows, Firo supports writable Berkeley DB (BDB) and
SQLite wallet databases during the coexistence period. When SQLite support is
enabled, new wallets default to SQLite. BDB wallets remain supported and are
never migrated automatically.

Older releases without SQLite wallet support cannot open a SQLite wallet.
Changing `-walletdbformat` does not convert it back to BDB. Before migration,
keep the original BDB backup; restoring it later also requires recovering any
keys or wallet metadata added after that backup. Choose `-walletdbformat=bdb`
when creating a wallet that must remain usable with older releases.

## Build configuration

Wallet builds currently require BDB support. On Linux, macOS, and Windows,
SQLite wallet support is controlled independently:

```bash
cmake -S . -B build \
  -DWITH_BDB=ON \
  -DENABLE_SQLITE_WALLET=ON
```

`ENABLE_SQLITE_WALLET` defaults to `ON` on all three platforms. Their depends
builds supply SQLite 3.50.4. A supported BDB-only build uses:

```bash
cmake -S . -B build-bdb \
  -DWITH_BDB=ON \
  -DENABLE_SQLITE_WALLET=OFF
```

For depends, `NO_SQLITE=1` omits SQLite from the packages built and installed
and configures the resulting toolchain with SQLite wallet support disabled.
`ENABLE_SQLITE_WALLET=OFF`, including a toolchain generated with
`NO_SQLITE=1`, is a true BDB-only build: it does not compile SQLite wallet
sources or require SQLite headers or libraries. It creates BDB wallets and
rejects an existing SQLite wallet before mutation. SQLite-only wallet builds
are not supported.

After changing `NO_SQLITE` or other depends package options, use a fresh CMake
build directory or explicitly set the desired CMake options. Reusing a build
directory preserves cached settings; removing `NO_SQLITE=1` alone does not
turn `ENABLE_SQLITE_WALLET` back on in that directory.

Without depends, install SQLite development headers and a matching library
version 3.31.0 or later (`libsqlite3-dev` on Debian/Ubuntu, or `sqlite` with
Homebrew). The library must support thread-safe connections and in-memory
temporary storage; `THREADSAFE=0` and `TEMP_STORE=0` builds are not supported.
Point CMake's `SQLite3_INCLUDE_DIR` and `SQLite3_LIBRARY` at that installation
when it is not found automatically.

The secure SQLite lifecycle publishes or replaces wallet files at the latest
safe filesystem boundary available on each platform. Linux uses `renameat2`
with `RENAME_NOREPLACE` or `RENAME_EXCHANGE` and `fsync`. macOS uses
`renameatx_np` with `RENAME_EXCL` or `RENAME_SWAP` and `F_FULLFSYNC`.

On Linux and macOS, wallets and SQLite backup destinations must be in a
directory owned by the current user with no group or other write permission.
The main file must be private (mode `0600`); parent directories must also be
protected against replacement by other users. Parent symlinks are resolved,
but the final wallet filename cannot be a symlink. Filesystems without the
required private permissions or rename operations, including typical
FAT32/exFAT backup media, are not supported. Back up to a protected supported
filesystem first. Do not disable permission checks or delete journal files
to bypass a refusal.

Wallet and backup filenames cannot end in `-journal`, `-wal`, or `-shm`;
these names belong to SQLite auxiliary files. Windows also rejects filenames
ending in a dot or space because Windows silently normalizes those names.

Windows support requires a local NTFS volume with persistent ACLs and stable
file identities. Firo opens every relevant path component without following
reparse points and rejects reparse entries. New candidates and backups use
`CREATE_NEW` with a protected, non-null DACL granting the current user full
control. Existing SQLite lifecycle files must be current-user-owned and pass
the private-access check. BDB migration sources must be current-user-owned and
source-controlled against untrusted mutation or security-control access;
ordinary BDB loading retains its legacy policy. Private directory validation
also rejects untrusted inheritable grants, so SQLite rollback journals cannot
inherit broader access. Firo retains and verifies native file identities
throughout each operation.

Windows no-replace publication uses
`MoveFileExW(..., MOVEFILE_WRITE_THROUGH)` without
`MOVEFILE_REPLACE_EXISTING`. Migration and recovery use `FileRenameInfoEx`
with replacement and POSIX semantics, allowing the old file to remain readable
through retained handles. The exact source is reopened with DELETE access and
`FILE_FLAG_WRITE_THROUGH`; neither operation permits a cross-volume copy.
Replacement requires native rename-ex support (Windows 10 version 1709 or
later). Missing support fails closed; ordinary writable BDB remains available.
Firo flushes the closed candidate first, reconciles the result using exact
retained file identities, then reopens, verifies, and flushes the final file.

Windows provides no documented generic directory-`fsync` equivalent for an
ordinary user. `MOVEFILE_WRITE_THROUGH` waits for the move to complete on disk,
and NTFS write-through handles synchronize rename metadata, but neither is a
generic directory flush. This contract therefore does not
claim stronger atomicity or durability across power loss, and cleanup of a
failed pre-publication operation cannot be claimed power-loss durable.
Creation, backup, recovery, or migration fails closed when a required
operation is unavailable or cannot be verified.

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

Format detection never falls back from a recognizable SQLite header to BDB.
If corruption destroys SQLite's identifying 16-byte header, however, the
remaining bytes are indistinguishable from a damaged BDB file and enter the
legacy BDB verification and recovery path. Recovery cannot reconstruct a
destroyed format identity; retain known-good backups before attempting it.

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
publication leaves the BDB source authoritative. Linux and macOS use an atomic
exchange at publication. Windows uses a same-volume, write-through replacement
and reconciles the exact candidate, source, and replaced-file identities after
the operation; Windows does not provide the same documented atomic-exchange or
generic directory-synchronization guarantees. Power-loss durability still
depends on the operating system and filesystem honoring the available
synchronization operations. If Windows cannot prove exact candidate cleanup
after a pre-publication failure, Firo reports the retained path, fails closed,
and requests shutdown before another wallet operation. No migration is
attempted during ordinary startup, wallet creation, backup, or software
upgrade.

The retained BDB backup still contains the original private keys and encryption
state. Encrypting the migrated wallet or changing its passphrase does not
protect or invalidate that backup. Keep it private, and include it when
deciding how to protect or retire old wallet backups.

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

SQLite automatic recovery makes a logical copy when integrity checks fail but
all wallet records remain readable. `-salvagewallet` instead copies validated
legacy key records; it is not a complete backup of mnemonic, Spark, or BIP47
wallet data. Both modes stop if a table page cannot be read, rather than publish
an incomplete recovery. Unlike BDB aggressive salvage, they cannot recover
records beyond an unreadable page. Preserve the source and restore a known-good
backup, or have a specialist attempt offline recovery on a separate copy.

An interrupted first-time wallet creation also cannot be salvaged. Its error
message identifies the incomplete wallet; preserve it and use a different
absent filename for a new wallet rather than removing its creation marker.

Firo does not provide a runtime `restorewallet` operation. Restore a backup
only while the wallet is stopped:

1. Stop Firo cleanly and retain the original wallet and the backup.
2. Choose a new, absent, flat wallet filename inside the active network data
   directory. Do not replace the original wallet in place.
3. Confirm that the destination and its `-journal`, `-wal`, and `-shm`
   side-file names are all absent.
4. Copy the verified backup with a method that exclusively creates the absent
   destination without following reparse points or symbolic links. On POSIX
   systems, preserve the owner, use mode `0600`, and set a restrictive umask
   before copying; a later `chmod` can expose the file temporarily. On Windows,
   create the destination as the current user with a protected private DACL
   granting only that user full control; do not rely on tightening inherited
   permissions after the copy.
5. Start Firo with the new logical filename, for example:

   ```bash
   firod -wallet=wallet-restored.dat
   ```

6. Confirm `getwalletinfo.format`, expected addresses and balances, and wallet
   unlock behavior before making the restored wallet authoritative.

The main SQLite backup is self-contained; no SQLite side file should be
restored with it. Keep the original and backup until the restored wallet has
been verified and backed up again to another absent path.
