# Horizon Record Pagination

**Issue:** [#191](https://github.com/Kevin737866/stellar-web3-toolkit/issues/191) — *Bulk infra: Automated check #23 – Horizon pagination handling*

Horizon never returns a whole collection. Every endpoint
(`/accounts/{id}/payments`, `/transactions`, `/operations`, …) answers with one
page of `_embedded.records` plus a `_links.next.href` carrying the cursor for
the following page. A client that reads a single response reports the newest
page and behaves as though the account had no history before it — a monitor
built on that sees a truncated view and calls it complete.

`stellar_toolkit::horizon` models the contract explicitly.

## Pieces

| Item | Purpose |
| --- | --- |
| `Cursor` | The `cursor` query parameter, with an empty value rejected |
| `HorizonPage` | One parsed page: records plus the next cursor |
| `page_path` | Builds a request path with `cursor`, `limit` and `order=asc` pinned |
| `paginate` | Walks pages until Horizon stops handing out a `next` link |

## Why an empty cursor is an error

Horizon reads `cursor=` (empty) as "start from the beginning of time" and an
*absent* cursor as "start from the newest record". Those are opposite ends of
the collection. A helper that quietly dropped an empty cursor would flip the
direction of a walk, so `Cursor::new("")` returns an error instead.
`Cursor::oldest()` is the explicit sentinel (`"0"`) for "from the oldest
record".

## Walking a collection

`paginate` takes a fetch closure, so it is testable without a network and works
with whichever HTTP client a caller already uses:

```rust
use stellar_toolkit::horizon::{paginate, DEFAULT_MAX_PAGES};

let payments = paginate(
    &format!("/accounts/{account}/payments"),
    200,
    DEFAULT_MAX_PAGES,
    |path| {
        let body = ureq::get(&format!("{horizon_base}{path}"))
            .call()
            .map_err(|e| ToolkitError::Horizon(e.to_string()))?
            .into_string()
            .map_err(|e| ToolkitError::Horizon(e.to_string()))?;
        Ok(body)
    },
    |record| Ok(record["id"].as_str().unwrap_or_default().to_string()),
)?;
```

Records come back oldest-first, matching the `order=asc` the path asks for.
That is the order a monitor needs to replay state changes.

## Termination guarantees

Three things stop a walk:

1. **No `next` link.** Horizon says there is nothing more.
2. **`max_pages` reached.** `HorizonPaginationError::PageLimitExceeded`.
3. **The cursor repeats.** `HorizonPaginationError::CursorDidNotAdvance`.

The third matters most in practice. Horizon is not supposed to repeat a cursor,
but a proxy that strips the parameter, or an endpoint that ignores it, turns an
unbounded walk into a hang — and a hang inside a monitoring loop looks exactly
like a healthy idle loop. The walk tracks every cursor it has used and refuses
to revisit one.

A `next` link without a usable `cursor` parameter is also an error rather than a
stop, because continuing would silently re-fetch the current page.

## Parsing tolerance

Only the fields this module needs are typed. Unknown fields are ignored, so a
Horizon release that adds fields does not break parsing. A response with no
`_embedded` block is an empty page, not an error; a `_embedded.records` that is
present but not an array *is* an error, because that means the response shape
changed underneath the caller.

## Limits

`limit` is clamped to `1..=MAX_LIMIT` (`200`) before it reaches the server, so a
caller asking for 5,000 gets a documented 200-record page rather than whatever
the server decides to do with it.
