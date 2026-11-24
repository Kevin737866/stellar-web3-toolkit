# Stellar DID Method Implementation

A complete W3C DID method implementation for the Stellar blockchain, enabling self-sovereign identity management using Rust/Soroban.

## Features

- **Complete DID Implementation**: Full compliance with W3C DID Core specification
- **Stellar Integration**: Native integration with Stellar blockchain and Soroban smart contracts
- **Verification Method Management**: Support for Ed25519, X25519, and other cryptographic keys
- **Service Endpoint Management**: Flexible service endpoint configuration
- **Document Updates & Rotation**: Secure document versioning and key rotation
- **Revocation & Deactivation**: Complete lifecycle management
- **REST/GraphQL APIs**: High-performance resolver APIs
- **JSON-LD Support**: Full context and framing support
- **Multi-Network Support**: Public, testnet, and future networks

## Quick Start

### Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
stellar-did = { version = "0.1.0", features = ["resolver-api"] }
```

### Basic Usage

```rust
use stellar_did::{Did, DidDocument, DidResolver};

// Create a DID
let did = Did::new(
    stellar_did::Network::Testnet,
    "GD5XQZOWX3RN6BQHCYVLNQDJN6YBXNHAPK4UQGHKU2VQRA5TJ5N2J53K".to_string(),
)?;

// Create a DID document
let mut document = DidDocument::new(&did)?;

// Add verification method
let keypair = stellar_did::crypto::KeyPair::generate_ed25519()?;
let method = stellar_did::document::VerificationMethod::new(
    format!("{}#key-1", did.to_string()),
    "Ed25519VerificationKey2018".to_string(),
    did.to_string(),
    keypair.public_key().to_string(),
    stellar_did::document::KeyFormat::Base64,
);

document.add_verification_method(method)?;

// Resolve a DID
let resolver = DidResolver::testnet();
let resolved_document = resolver.resolve(&did.to_string()).await?;
```

### Resolver API

Start the resolver server:

```bash
# Start REST API
cargo run --features resolver-api --bin stellar-did-resolver

# With GraphQL enabled
ENABLE_GRAPHQL=true cargo run --features resolver-api,graphql --bin stellar-did-resolver
```

### API Endpoints

#### REST API

```bash
# Resolve a DID
curl "http://localhost:8080/1.0/identifiers/did:stellar:testnet:GD5..."

# Batch resolution
curl -X POST "http://localhost:8080/1.0/identifiers" \
  -H "Content-Type: application/json" \
  -d '["did:stellar:testnet:GD5...", "did:stellar:testnet:GD6..."]'

# List supported methods
curl "http://localhost:8080/methods"
```

#### GraphQL API

```graphql
query {
  resolveDid(did: "did:stellar:testnet:GD5...") {
    didDocument {
      id
      verificationMethod {
        id
        type
        controller
      }
    }
    resolutionMetadata {
      created
      updated
      revoked
    }
  }
}
```

## DID Format

The `did:stellar` method uses the following format:

```
did:stellar:<network>:<account-id>
```

- `network`: `public`, `testnet`, or `future`
- `account-id`: Stellar account ID (G-prefixed, 56 characters)

### Examples

```
did:stellar:testnet:GD5XQZOWX3RN6BQHCYVLNQDJN6YBXNHAPK4UQGHKU2VQRA5TJ5N2J53K
did:stellar:public:GABKJDSKLMNOPQRSTUVWXYZ1234567890ABCDEFGHIJK
```

## DID Identifier Validation (issue #338)

DID document `id` values are checked against the **configured DID method**
before a document is created or returned by a resolver. The default method is
`stellar`; another valid method name can be configured explicitly.

```rust
use stellar_did::{validate_did_id, DidDocument, DidError, DidMethodConfig};

let config = DidMethodConfig::default(); // serves "stellar"
assert!(validate_did_id("did:stellar:testnet:GABC", &config).is_ok());
assert!(matches!(
    validate_did_id("did:example:alice", &config),
    Err(DidError::MethodMismatch { .. })
));

let document = DidDocument::try_new("did:stellar:testnet:GABC", &config)?;
let resolved = DidDocument::from_json_str(&published_json, &config)?;
resolved.validate_id(&config)?;
```

### Interface

| API | Purpose |
|-----|---------|
| `DidMethodConfig::new(method)` | Configure the accepted method; errors on an invalid method name |
| `DidMethodConfig::default()` | The `stellar` method |
| `validate_did_id(id, config)` | Standalone DID Core + method check, returning `ValidatedDidId` |
| `DidDocument::try_new(id, config)` | Create a document only when its id passes validation |
| `DidDocument::validate_id(config)` | Check an existing (e.g. stored) document before returning it |
| `DidDocument::from_json_str(json, config)` | Parse and validate a resolver/storage response |

Failures are reported as `DidError::InvalidDid`, `DidError::MethodMismatch`,
`DidError::InvalidMethodName` and `DidError::InvalidDocument`. Every error
includes the rejected value or an actionable reason; validation never rewrites
the identifier, and no partial document is produced on failure.

### Configuration and rules

A `DidMethodConfig` is the only source of the accepted method — there is no
environment-variable fallback, so a wrong method fails at construction instead
of silently accepting documents from another method. Validation follows the
DID Core 1.0 ABNF: `did:<method-name>:<method-specific-id>`, where the method is
lowercase letters and digits and the method-specific id uses letters, digits,
`.`, `-`, `_`, `:` separators and percent-encoded characters. DID URL
components (`#`, `?`, `/`) and empty id segments are rejected. Service endpoint
schemes are still re-checked when a document is parsed from JSON.

### Compatibility

`DidDocument::new`, direct struct construction and plain `serde` deserialization
are unchanged and remain unvalidated, so existing callers do not break; new
callers should use `try_new` / `from_json_str` for untrusted input. The
`stellar_did::service::DidError` re-export remains available alongside
`stellar_did::DidError`. Resolver responses are stable: the same invalid stored
document is rejected with the same error on every call, rather than being
returned once and rejected later.

## Architecture

### Core Components

- **Core (`core.rs`)**: DID parsing, validation, and basic types
- **Document (`document.rs`)**: DID document structure and management
- **Crypto (`crypto.rs`)**: Cryptographic operations and key management
- **Transaction (`transaction.rs`)**: Stellar transaction handling
- **Verification (`verification.rs`)**: Verification method management
- **Service (`service.rs`)**: Service endpoint management
- **Rotation (`rotation.rs`)**: Document updates and key rotation
- **Revocation (`revocation.rs`)**: Revocation and deactivation
- **Resolver (`resolver.rs`)**: DID resolution logic
- **API (`api.rs`)**: REST and GraphQL APIs
- **JSON-LD (`jsonld.rs`)**: JSON-LD context and framing support

### Security Features

- **Multi-signature Support**: Native Stellar multi-signature integration
- **Key Rotation**: Secure key rotation with version tracking
- **Revocation Registry**: Global revocation status tracking
- **Proof Verification**: Ed25519 signature verification
- **Access Control**: Granular permission management

## Configuration

### Environment Variables

```bash
# Network configuration
STELLAR_NETWORK=testnet
PORT=8080
GRAPHQL_PORT=8081

# Feature flags
ENABLE_GRAPHQL=true
RUST_LOG=debug
```

### Resolver Configuration

```rust
use stellar_did::resolver::{DidResolver, ResolverConfig};

let config = ResolverConfig {
    network: stellar_did::Network::Public,
    horizon_url: "https://horizon.stellar.org".to_string(),
    soroban_rpc_url: "https://soroban.stellar.org".to_string(),
    cache_ttl: 300,
    enable_cache: true,
};

let resolver = DidResolver::new(config);
```

## Testing

Run the test suite:

```bash
# Run all tests
cargo test -p stellar-did

# Run with resolver API features
cargo test -p stellar-did --features resolver-api

# Run integration tests
cargo test -p stellar-did integration_tests
```

## Examples

### Complete DID Lifecycle

```rust
use stellar_did::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Create DID
    let did = Did::new(
        Network::Testnet,
        "GD5XQZOWX3RN6BQHCYVLNQDJN6YBXNHAPK4UQGHKU2VQRA5TJ5N2J53K".to_string(),
    )?;

    // 2. Create document with verification methods
    let mut document = DidDocument::new(&did)?;
    let keypair = crypto::KeyPair::generate_ed25519()?;

    let method = document::VerificationMethod::new(
        format!("{}#key-1", did.to_string()),
        "Ed25519VerificationKey2018".to_string(),
        did.to_string(),
        keypair.public_key().to_string(),
        document::KeyFormat::Base64,
    );

    document.add_verification_method(method)?;

    // 3. Add services
    let service = service::Service {
        id: format!("{}#hub", did.to_string()),
        service_type: "IdentityHub".to_string(),
        service_endpoint: service::ServiceEndpoint::uri(
            "https://hub.example.com".to_string(),
        )?,
        properties: std::collections::HashMap::new(),
    };

    document.add_service(service)?;

    // 4. Create update transaction
    let tx_manager = transaction::DidTransactionManager::new(Network::Testnet);
    let sequence = tx_manager.get_sequence_number(&did.account_id()).await?;

    let update_manager = rotation::DocumentUpdateManager::new(&did, document, Network::Testnet)?;
    let transaction = update_manager.create_update_transaction(&keypair, sequence)?;

    // 5. Submit transaction
    let tx_hash = tx_manager.submit_transaction(&transaction).await?;
    println!("Transaction submitted: {}", tx_hash);

    // 6. Resolve updated document
    let resolver = resolver::DidResolver::testnet();
    let resolved = resolver.resolve_with_metadata(&did.to_string()).await?;
    
    println!("Resolved document: {}", serde_json::to_string_pretty(&resolved.document)?);

    Ok(())
}
```

## Compliance

This implementation is fully compliant with:

- **W3C DID Core Specification**: https://www.w3.org/TR/did-core/
- **W3C DID Resolution**: https://www.w3.org/TR/did-resolution/
- **W3C JSON-LD 1.1**: https://www.w3.org/TR/json-ld11/

## Method Specification

The complete method specification is available in:
`docs/stellar-did-specification.md`

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

MIT License - see [LICENSE](../../LICENSE) file for details.

## Resources

- [Stellar Developers](https://developers.stellar.org/)
- [Soroban Documentation](https://soroban.stellar.org/)
- [W3C DID Working Group](https://www.w3.org/2019/did-wg/)
- [DID Method Registry](https://www.w3.org/TR/did-spec-registries/)
