# Collection Access Control

`CollectionAccessControl` (issue **#148**) is a role registry for Soroban
collections. A single deployment manages many collections — each identified by
its contract address — and lets the collection and the contracts built around it
check who may mint, burn, update metadata or administer transfers.

| Contract | Package | Purpose |
|---|---|---|
| `CollectionAccessControl` | `contracts/collection-access-control` | Per-collection owner plus permission bitmasks for accounts. |

Permissions are bit flags, so an account can hold any combination:

| Flag | Bit | Meaning |
|---|---|---|
| `PERM_ADMIN` | `0b00001` | Manage permissions and collection ownership |
| `PERM_MINTER` | `0b00010` | Mint new assets |
| `PERM_BURNER` | `0b00100` | Burn assets |
| `PERM_METADATA` | `0b01000` | Update asset metadata |
| `PERM_TRANSFER` | `0b10000` | Administer transfers/approvals |

The collection **owner** implicitly holds `PERM_ALL`. A collection may also set
**default permissions** that apply to every account (for example
`PERM_TRANSFER` on a freely transferable collection). Because permissions are
queryable with `has_permission`, any collection contract can gate its own entry
points without duplicating role logic.

## Lifecycle

1. **`initialize`** — one-time setup of the contract-wide `admin`, who can
   register collections and always holds `PERM_ALL`.
2. **`register_collection`** — the admin registers a collection address and
   names its owner. A collection can only be registered once.
3. **`grant_permissions` / `revoke_permissions` / `set_permissions`** — the
   owner or any account holding `PERM_ADMIN` adjusts an account's bits.
4. **`set_default_permissions`** — sets the bits granted to everyone in the
   collection.
5. **`transfer_ownership`** — hands collection ownership to another account.

## API

```rust
use collection_access_control::{CollectionAccessControl, PERM_ADMIN, PERM_MINTER};

let acl_id = env.register_contract(None, CollectionAccessControl);
let acl = CollectionAccessControlClient::new(&env, &acl_id);

// One-time setup, then register the collection contract and its owner.
acl.initialize(&admin);
acl.register_collection(&admin, &collection, &creator);

// Grant the artist minting and metadata rights.
acl.grant_permissions(&creator, &collection, &artist, &(PERM_MINTER | PERM_METADATA));

// Anyone may transfer assets in this collection by default.
acl.set_default_permissions(&creator, &collection, &PERM_TRANSFER);

// A collection contract can gate one of its own entry points:
assert!(acl.has_permission(&collection, &artist, &PERM_MINTER));
assert!(!acl.has_permission(&collection, &stranger, &PERM_MINTER));

// Hand the collection to a new owner and clean up a grant.
acl.transfer_ownership(&creator, &collection, &new_owner);
acl.revoke_permissions(&new_owner, &collection, &artist, &PERM_MINTER);
```

Read helpers: `has_permission(collection, account, permission)`,
`get_permissions(collection, account)` (effective bits, including defaults and
the owner's implicit `PERM_ALL`), `get_owner(collection)`,
`is_registered(collection)`, `get_admin()`.

### Notes

- `has_permission` requires **every** bit in `permission` to be held, so
  combined checks such as `PERM_MINTER | PERM_METADATA` work as expected.
- Permissions and collection owners are stored in **persistent storage** with
  TTL extension; the contract admin lives in instance storage. See
  [SOROBAN_STORAGE_BEST_PRACTICES](SOROBAN_STORAGE_BEST_PRACTICES.md).
- Only the contract admin may `register_collection`; once registered, ownership
  and grants are managed by the collection owner or `PERM_ADMIN` holders.

## Example Integration

`contracts/nft-drop/tests/integration.rs` wires this registry into the NFT drop
(issue **#149**): the drop delegates administration to the registry, so an
account granted `PERM_ADMIN` for the collection can open sale phases and reveal
metadata without being the drop's admin.

```bash
cargo test -p nft-drop --test integration
```

## Testing

```bash
cargo test -p collection-access-control
```

Coverage includes the owner's implicit `PERM_ALL`, grant/revoke bit toggling,
combined permission checks, default permissions, ownership transfer, and
unauthorized-access rejections.
