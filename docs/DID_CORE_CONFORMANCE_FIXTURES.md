# DID Core Serialization Conformance Fixtures (Issue #347)

`crates/stellar-did` now has an explicit DID Core serialization surface beside
its legacy `serde` representation. The legacy shape is unchanged, so callers
that serialize `DidDocument` directly keep getting exactly the JSON they had
before. Callers that need specification-shaped output use the new API.

## Public interface

| Item | Purpose |
|------|---------|
| `stellar_did::validate(&DidDocument)` | Check DID Core invariants without producing JSON. |
| `stellar_did::to_core_value(&DidDocument)` | Build a validated `serde_json::Value`. |
| `stellar_did::to_json(&DidDocument)` | Return compact, deterministic DID document JSON. |
| `stellar_did::resolution_json(&DidDocument)` | Return a complete DID resolution result with empty metadata objects. |
| `stellar_did::ConformanceError` | Actionable errors naming the offending field, index, and value. |
| `stellar_did::DID_CORE_CONTEXT` | The JSON-LD context string emitted in every document and result. |
| `stellar_did::RESERVED_SERVICE_PROPERTIES` | Service keys callers may not override through extensions. |

All functions are pure: they borrow the document, never mutate it, and return
an error instead of repairing an invalid field.

## Emitted shape

```json
{
  "@context": "https://www.w3.org/ns/did/v1",
  "id": "did:stellar:testnet:GABC",
  "service": [
    {
      "id": "did:stellar:testnet:GABC#hub",
      "serviceEndpoint": "https://hub.example.com",
      "type": "LinkedDomains"
    }
  ]
}
```

Differences from the legacy `serde` output:

* `@context` is added to conformant documents and resolution results.
* `service_type` becomes `type` and `service_endpoint` becomes
  `serviceEndpoint`.
* Entries in `Service::properties` are flattened into the service object
  instead of being nested under a `properties` key.
* Object keys are emitted in sorted order, so the same document produces the
  same bytes on every machine. This is the stability guarantee resolver clients
  and golden-file tests rely on.

## Fixtures

Golden files live in `crates/stellar-did/fixtures/` and are compiled into the
tests with `include_str!`:

| Fixture | Covers |
|---------|--------|
| `minimal.json` | A document with no services. |
| `with_service.json` | A document with one validated service endpoint. |
| `with_extension.json` | Flattened extension properties and stable key ordering. |
| `resolution.json` | A full resolution result with stable metadata objects. |

When intentionally changing the conformance output, update the fixture and the
unit test expectation in the same change. Do not regenerate fixtures from an
unvalidated document: the fixture is the specification of the observable
output.

## Invariants and failure behavior

A document is rejected with an error when:

* `id` is not `did:<lowercase-method>:<non-empty-method-specific-id>` without
  whitespace or empty colon-separated segments.
* a service `id` is neither the subject DID nor one of its DID URLs (a full
  `did:...#fragment` or a relative `#fragment`).
* two services share an id.
* `type` is empty or whitespace-only.
* `serviceEndpoint` fails the existing URI scheme allowlist (`https`, `http`,
  `did`) or URI parser. This check also covers documents deserialized from
  untrusted JSON, where the `ServiceEndpoint` constructor was bypassed.
* an extension property would shadow `id`, `type`, or `serviceEndpoint`.

Because validation completes before any JSON is built, a rejected document
never produces a partial result and the caller's document is untouched.

## Configuration and compatibility

There is no runtime configuration. The context string and fixture files are
compile-time constants in the crate. The new API is additive: the existing
`Serialize`/`Deserialize` implementations on `DidDocument`, `Service`, and
`ServiceEndpoint` are unchanged, and no CLI flag or environment variable is
required. A caller that wants the new behavior opts in by calling `to_json` or
`resolution_json` explicitly.

## Validation

```bash
cargo fmt --all -- --check
cargo test -p stellar-did
```

The integration test in `crates/stellar-did/tests/conformance_workflow.rs`
covers the full create -> validate -> serialize -> resolve workflow, including
the case where an untrusted endpoint is rejected before any conformance output
is produced.
