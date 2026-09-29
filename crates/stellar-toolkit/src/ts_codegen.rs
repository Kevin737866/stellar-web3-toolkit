//! Typed TypeScript client codegen for Soroban contract interfaces.
//!
//! Automated check #57 (issue #246) — generated modules must never contain
//! duplicate import statements. [`ImportSet`] merges every repeated request, so
//! a helper used by ten methods is still imported exactly once and each module
//! is emitted as a single `import { .. } from "..";` line.
//!
//! Automated check #58 (issue #247) — Soroban integers of 64 bits and wider
//! (`i64`, `u64`, `i128`, `u128`) exceed `Number.MAX_SAFE_INTEGER`, so they are
//! emitted as `bigint` and passed to `nativeToScVal` with the matching hint
//! instead of `number`, which would silently lose precision.
//!
//! Arrays and maps are emitted with the coarse `vec`/`map` XDR hints; generated
//! clients are meant to be refined where richer element hints are required.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// Soroban integer types that must be represented as `bigint` in TypeScript.
pub const WIDE_INT_TYPES: [&str; 4] = ["i64", "u64", "i128", "u128"];

/// npm module the generated client imports Soroban primitives from.
const SDK_MODULE: &str = "stellar-sdk";

/// A single contract function parameter with its Soroban type.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParamSpec {
    /// Parameter name as declared by the contract (snake_case).
    pub name: String,
    /// Soroban/Rust type, e.g. `i128`, `Address`, `Vec<Address>`.
    pub soroban_type: String,
    /// Whether the caller may omit the parameter.
    #[serde(default)]
    pub optional: bool,
}

impl ParamSpec {
    pub fn new(name: &str, soroban_type: &str) -> Self {
        Self {
            name: name.to_string(),
            soroban_type: soroban_type.to_string(),
            optional: false,
        }
    }

    pub fn optional(name: &str, soroban_type: &str) -> Self {
        Self {
            name: name.to_string(),
            soroban_type: soroban_type.to_string(),
            optional: true,
        }
    }

    /// TypeScript annotation for this parameter.
    pub fn ts_type(&self) -> String {
        ts_type_for(&self.soroban_type)
    }

    /// `nativeToScVal` type hint for this parameter.
    pub fn scval_type(&self) -> String {
        scval_type_for(&self.soroban_type)
    }

    /// Identifier used for this parameter in the generated client.
    pub fn identifier(&self) -> String {
        ts_identifier(&self.name)
    }
}

/// A contract function exposed to clients.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FunctionSpec {
    /// Function name as declared by the contract (snake_case).
    pub name: String,
    /// Short doc comment copied into the generated client.
    #[serde(default)]
    pub doc: String,
    pub params: Vec<ParamSpec>,
    /// Soroban return type; `()` means no return value.
    pub returns: String,
}

impl FunctionSpec {
    pub fn new(name: &str, doc: &str, params: Vec<ParamSpec>, returns: &str) -> Self {
        Self {
            name: name.to_string(),
            doc: doc.to_string(),
            params,
            returns: returns.to_string(),
        }
    }

    /// TypeScript return annotation.
    pub fn ts_return(&self) -> String {
        if is_void(&self.returns) {
            "void".to_string()
        } else {
            ts_type_for(&self.returns)
        }
    }

    /// Whether the function returns a value that must be decoded.
    pub fn returns_value(&self) -> bool {
        !is_void(&self.returns)
    }
}

/// Contract interface used as codegen input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractSpec {
    /// Contract name in PascalCase, e.g. `AmmPool`.
    pub name: String,
    /// Deployed contract id, or a placeholder in generated clients.
    pub contract_id: String,
    /// Network passphrase of the target network.
    pub network_passphrase: String,
    pub functions: Vec<FunctionSpec>,
}

impl ContractSpec {
    /// Bundled `contracts/amm-pool` interface used by the `codegen` commands
    /// when no spec file is supplied.
    pub fn amm_pool() -> Self {
        Self {
            name: "AmmPool".to_string(),
            contract_id: format!("C{}", "A".repeat(55)),
            network_passphrase: "Test SDF Network ; September 2015".to_string(),
            functions: vec![
                FunctionSpec::new(
                    "initialize",
                    "One-time init (typically called by the factory after deploy).",
                    vec![
                        ParamSpec::new("factory", "Address"),
                        ParamSpec::new("token_a", "Address"),
                        ParamSpec::new("token_b", "Address"),
                    ],
                    "()",
                ),
                FunctionSpec::new(
                    "get_reserves",
                    "Current pool reserves.",
                    vec![],
                    "(i128, i128)",
                ),
                FunctionSpec::new(
                    "factory",
                    "Factory that deployed this pool.",
                    vec![],
                    "Address",
                ),
                FunctionSpec::new("token_a", "First asset of the pair.", vec![], "Address"),
                FunctionSpec::new("token_b", "Second asset of the pair.", vec![], "Address"),
                FunctionSpec::new(
                    "observe",
                    "Cumulative reserves multiplied by timestamp (TWAP input).",
                    vec![],
                    "(i128, i128, u64)",
                ),
                FunctionSpec::new(
                    "add_liquidity",
                    "Deposit both assets and receive LP tokens.",
                    vec![
                        ParamSpec::new("user", "Address"),
                        ParamSpec::new("amount_a_desired", "i128"),
                        ParamSpec::new("amount_b_desired", "i128"),
                        ParamSpec::new("min_a", "i128"),
                        ParamSpec::new("min_b", "i128"),
                    ],
                    "i128",
                ),
                FunctionSpec::new(
                    "remove_liquidity",
                    "Burn LP tokens and withdraw both assets.",
                    vec![
                        ParamSpec::new("user", "Address"),
                        ParamSpec::new("lp_amount", "i128"),
                        ParamSpec::new("min_a", "i128"),
                        ParamSpec::new("min_b", "i128"),
                    ],
                    "(i128, i128)",
                ),
                FunctionSpec::new(
                    "swap",
                    "Swap `token_in` (already transferred to the pool) for the other asset.",
                    vec![
                        ParamSpec::new("token_in", "Address"),
                        ParamSpec::new("to", "Address"),
                        ParamSpec::new("min_out", "i128"),
                    ],
                    "i128",
                ),
                FunctionSpec::new(
                    "flash_swap",
                    "Flash swap: the callback must restore the constant-product invariant.",
                    vec![
                        ParamSpec::new("recipient", "Address"),
                        ParamSpec::new("amount_a_out", "i128"),
                        ParamSpec::new("amount_b_out", "i128"),
                        ParamSpec::new("callback", "Address"),
                    ],
                    "()",
                ),
                FunctionSpec::new(
                    "balance",
                    "LP token balance of `id`.",
                    vec![ParamSpec::new("id", "Address")],
                    "i128",
                ),
                FunctionSpec::new(
                    "allowance",
                    "Effective LP allowance granted to `spender`.",
                    vec![
                        ParamSpec::new("from", "Address"),
                        ParamSpec::new("spender", "Address"),
                    ],
                    "i128",
                ),
                FunctionSpec::new(
                    "approve",
                    "Approve `spender` until `expiration_ledger`.",
                    vec![
                        ParamSpec::new("from", "Address"),
                        ParamSpec::new("spender", "Address"),
                        ParamSpec::new("amount", "i128"),
                        ParamSpec::new("expiration_ledger", "u32"),
                    ],
                    "()",
                ),
                FunctionSpec::new("decimals", "LP token decimals.", vec![], "u32"),
            ],
        }
    }

    /// Load a contract interface spec from a JSON file.
    pub fn from_json_file(path: &Path) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&raw)?)
    }

    /// Soroban RPC endpoint matching the configured network.
    pub fn rpc_url(&self) -> String {
        if self.network_passphrase.starts_with("Test SDF Network") {
            "https://soroban-testnet.stellar.org".to_string()
        } else {
            "https://soroban.stellar.org".to_string()
        }
    }
}

/// Deduplicated import statements for generated TypeScript modules.
#[derive(Debug, Clone, Default)]
pub struct ImportSet {
    modules: BTreeMap<String, BTreeSet<String>>,
}

impl ImportSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a value import. Repeated requests for the same symbol are
    /// ignored, so a module never gets more than one import statement.
    pub fn add_value(&mut self, module: &str, symbol: &str) {
        self.modules
            .entry(module.to_string())
            .or_default()
            .insert(symbol.to_string());
    }

    /// Render one `import { .. } from "..";` statement per module, with the
    /// modules and their symbols in deterministic (sorted) order.
    pub fn render(&self) -> String {
        let mut out = String::new();
        for (module, symbols) in &self.modules {
            let list = symbols
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            out.push_str(&format!("import {{ {list} }} from \"{module}\";\n"));
        }
        out
    }
}

/// Generator for typed TypeScript clients.
pub struct TsClientGenerator {
    spec: ContractSpec,
}

impl TsClientGenerator {
    pub fn new(spec: ContractSpec) -> Self {
        Self { spec }
    }

    pub fn spec(&self) -> &ContractSpec {
        &self.spec
    }

    /// Imports required by the generated client, deduplicated per module.
    pub fn imports(&self) -> ImportSet {
        let mut imports = ImportSet::new();
        let has_args = self.spec.functions.iter().any(|f| !f.params.is_empty());
        let has_results = self.spec.functions.iter().any(|f| f.returns_value());
        if has_args {
            imports.add_value("./scval", "toScVal");
        }
        if has_results {
            imports.add_value("./scval", "fromScVal");
        }
        imports.add_value(SDK_MODULE, "Contract");
        imports.add_value(SDK_MODULE, "rpc");
        imports
    }

    /// Render the client module source.
    pub fn generate(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "// Auto-generated by stellar-toolkit `codegen ts` for {}.\n",
            self.spec.name
        ));
        out.push_str("// 64-bit and wider Soroban integers are emitted as `bigint`.\n\n");
        out.push_str(&self.imports().render());
        out.push('\n');
        out.push_str(&format!(
            "export const CONTRACT_ID = \"{}\";\n",
            self.spec.contract_id
        ));
        out.push_str(&format!(
            "export const NETWORK_PASSPHRASE = \"{}\";\n",
            self.spec.network_passphrase
        ));
        out.push_str(&format!(
            "export const RPC_URL = \"{}\";\n",
            self.spec.rpc_url()
        ));
        out.push_str(&format!("\nexport class {}Client {{\n", self.spec.name));
        out.push_str("  readonly contract: Contract;\n\n");
        out.push_str("  constructor(\n");
        out.push_str("    readonly rpcClient: rpc.Server = new rpc.Server(RPC_URL),\n");
        out.push_str("    contractId: string = CONTRACT_ID,\n");
        out.push_str("  ) {\n");
        out.push_str("    this.contract = new Contract(contractId);\n");
        out.push_str("  }\n");
        for f in &self.spec.functions {
            self.push_method(&mut out, f);
        }
        out.push_str("}\n");
        out
    }

    /// Generated artifacts as `(file name, source)` pairs.
    pub fn files(&self) -> Vec<(String, String)> {
        vec![
            ("scval.ts".to_string(), scval_runtime_source()),
            (
                format!("{}.ts", kebab_case(&self.spec.name)),
                self.generate(),
            ),
        ]
    }

    /// Write every generated artifact into `out_dir` and return the paths.
    pub fn write_to_dir(&self, out_dir: &Path) -> anyhow::Result<Vec<PathBuf>> {
        std::fs::create_dir_all(out_dir)?;
        let mut paths = Vec::new();
        for (name, source) in self.files() {
            let path = out_dir.join(&name);
            std::fs::write(&path, source)?;
            paths.push(path);
        }
        Ok(paths)
    }

    fn push_method(&self, out: &mut String, f: &FunctionSpec) {
        if !f.doc.is_empty() {
            out.push_str(&format!("  /** {} */\n", f.doc));
        }
        let args: Vec<String> = f
            .params
            .iter()
            .map(|p| {
                let mark = if p.optional { "?" } else { "" };
                format!("{}{}: {}", p.identifier(), mark, p.ts_type())
            })
            .collect();
        let ret = f.ts_return();
        out.push_str(&format!(
            "  async {}({}): Promise<{}> {{\n",
            ts_identifier(&f.name),
            args.join(", "),
            ret
        ));
        let call_args: Vec<String> = f
            .params
            .iter()
            .map(|p| format!("toScVal({}, \"{}\")", p.identifier(), p.scval_type()))
            .collect();
        let invoke = if call_args.is_empty() {
            format!("this.contract.invoke(\"{}\")", f.name)
        } else {
            format!(
                "this.contract.invoke(\"{}\", {})",
                f.name,
                call_args.join(", ")
            )
        };
        if ret == "void" {
            out.push_str(&format!("    await {invoke};\n"));
        } else {
            out.push_str(&format!("    const result = await {invoke};\n"));
            out.push_str(&format!("    return fromScVal(result) as {ret};\n"));
        }
        out.push_str("  }\n\n");
    }
}

/// Source of the shared XDR helper module emitted next to every client.
fn scval_runtime_source() -> String {
    let mut imports = ImportSet::new();
    imports.add_value(SDK_MODULE, "nativeToScVal");
    imports.add_value(SDK_MODULE, "scValToNative");

    let mut out = String::new();
    out.push_str("// Auto-generated by stellar-toolkit `codegen ts` — DO NOT EDIT.\n");
    out.push_str("// Shared XDR helpers for generated Soroban clients.\n\n");
    out.push_str(&imports.render());
    out.push('\n');
    out.push_str("/** Convert a native value to an ScVal with a Soroban type hint. */\n");
    out.push_str("export function toScVal(value: unknown, hint: string) {\n");
    out.push_str("  return nativeToScVal(value as never, { type: hint });\n");
    out.push_str("}\n\n");
    out.push_str("/** Convert an ScVal returned by a contract to a native value. */\n");
    out.push_str("export function fromScVal(value: unknown) {\n");
    out.push_str("  return scValToNative(value as never);\n");
    out.push_str("}\n");
    out
}

/// Map a Soroban type to its TypeScript equivalent. Integers of 64 bits and
/// wider become `bigint` because they do not fit a JavaScript `number`.
pub fn ts_type_for(soroban_type: &str) -> String {
    let t = soroban_type.trim();
    if t.is_empty() {
        return "void".to_string();
    }
    if WIDE_INT_TYPES.contains(&t) {
        return "bigint".to_string();
    }
    if t.starts_with('(') && t.ends_with(')') {
        let parts = split_top_level(&t[1..t.len() - 1]);
        let mapped: Vec<String> = parts.iter().map(|p| ts_type_for(p)).collect();
        return format!("[{}]", mapped.join(", "));
    }
    match t {
        "bool" => "boolean".to_string(),
        "Address" | "String" | "Symbol" | "Bytes" | "BytesN<32>" => "string".to_string(),
        "i32" | "u32" => "number".to_string(),
        "void" | "Void" => "void".to_string(),
        _ => ts_container_type(t),
    }
}

/// `nativeToScVal` type hint for a Soroban type.
pub fn scval_type_for(soroban_type: &str) -> String {
    let t = soroban_type.trim();
    if t.starts_with('(') && t.ends_with(')') {
        return "unknown".to_string();
    }
    if strip_generic(t, "Vec").is_some() {
        return "vec".to_string();
    }
    if strip_generic(t, "Option").is_some() {
        return scval_type_for(t.trim_start_matches("Option<").trim_end_matches('>'));
    }
    if strip_generic(t, "Map").is_some() {
        return "map".to_string();
    }
    match t {
        "Address" => "address".to_string(),
        "String" => "string".to_string(),
        "Symbol" => "symbol".to_string(),
        "bool" => "bool".to_string(),
        "Bytes" | "BytesN<32>" => "bytes".to_string(),
        _ if WIDE_INT_TYPES.contains(&t) => t.to_string(),
        _ if t == "i32" || t == "u32" => t.to_string(),
        _ => "unknown".to_string(),
    }
}

fn ts_container_type(t: &str) -> String {
    if let Some(inner) = strip_generic(t, "Vec") {
        return format!("Array<{}>", ts_type_for(inner));
    }
    if let Some(inner) = strip_generic(t, "Option") {
        return format!("{} | undefined", ts_type_for(inner));
    }
    let map_args = strip_generic(t, "Map").and_then(split_generic_args);
    if let Some((key, value)) = map_args {
        return format!("Map<{}, {}>", ts_type_for(&key), ts_type_for(&value));
    }
    "unknown".to_string()
}

fn strip_generic<'a>(t: &'a str, name: &str) -> Option<&'a str> {
    let rest = t.strip_prefix(name)?.trim_start();
    let rest = rest.strip_prefix('<')?;
    let inner = rest.strip_suffix('>')?;
    Some(inner.trim())
}

fn split_generic_args(inner: &str) -> Option<(String, String)> {
    let mut parts = split_top_level(inner);
    if parts.len() != 2 {
        return None;
    }
    let second = parts.pop()?;
    let first = parts.pop()?;
    Some((first, second))
}

fn split_top_level(inner: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut depth = 0usize;
    for ch in inner.chars() {
        match ch {
            '<' | '(' | '[' => {
                depth += 1;
                current.push(ch);
            }
            '>' | ')' | ']' => {
                depth = depth.saturating_sub(1);
                current.push(ch);
            }
            // The accumulator has to be emptied after each element, otherwise
            // the next element is appended to the previous one and
            // `Map<String, i128>` splits into `["String", "String i128"]`.
            ',' if depth == 0 => {
                parts.push(current.trim().to_string());
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    let tail = current.trim();
    if !tail.is_empty() {
        parts.push(tail.to_string());
    }
    parts
}

fn is_void(returns: &str) -> bool {
    let t = returns.trim();
    t.is_empty() || t == "()" || t == "void" || t == "Void"
}

const RESERVED_IDENTIFIERS: [&str; 5] = ["contract", "rpc", "rpcclient", "constructor", "new"];

/// `amount_a_desired` -> `amountADesired`, suffixed when it would shadow a
/// client member or a reserved word.
fn ts_identifier(name: &str) -> String {
    let mut out = String::new();
    for part in name.split(['_', '-', ' ']) {
        if part.is_empty() {
            continue;
        }
        if out.is_empty() {
            out.push_str(&part.to_lowercase());
        } else {
            let mut chars = part.chars();
            if let Some(first) = chars.next() {
                out.extend(first.to_uppercase());
                out.push_str(&chars.as_str().to_lowercase());
            }
        }
    }
    if out.is_empty() {
        return "value".to_string();
    }
    if RESERVED_IDENTIFIERS.contains(&out.as_str()) {
        return format!("{out}Arg");
    }
    out
}

/// `AmmPool` -> `amm-pool`.
fn kebab_case(name: &str) -> String {
    let mut out = String::new();
    for (i, ch) in name.chars().enumerate() {
        if ch.is_uppercase() {
            if i > 0 {
                out.push('-');
            }
            out.extend(ch.to_lowercase());
        } else if ch == '_' || ch == ' ' {
            out.push('-');
        } else {
            out.push(ch);
        }
    }
    out
}

/// Automated check #57: report duplicate imports in a generated module.
pub fn audit_imports(source: &str) -> Vec<String> {
    let mut problems = Vec::new();
    let mut modules: BTreeMap<String, usize> = BTreeMap::new();
    for line in source.lines() {
        let line = line.trim();
        if !line.starts_with("import ") {
            continue;
        }
        let Some(module) = import_module(line) else {
            continue;
        };
        *modules.entry(module.clone()).or_insert(0) += 1;
        let mut seen: BTreeSet<String> = BTreeSet::new();
        for symbol in import_symbols(line) {
            if !seen.insert(symbol.clone()) {
                problems.push(format!(
                    "duplicate import symbol `{symbol}` in one statement"
                ));
            }
        }
    }
    for (module, count) in modules {
        if count > 1 {
            problems.push(format!(
                "module `{module}` is imported by {count} statements"
            ));
        }
    }
    problems
}

/// Automated check #58: report wide Soroban integers generated as `number`.
pub fn audit_bigint(source: &str) -> Vec<String> {
    let declared = declared_types(source);
    let mut problems = Vec::new();
    for (arg, hint) in bigint_call_args(source) {
        if !WIDE_INT_TYPES.contains(&hint.as_str()) {
            continue;
        }
        match declared.get(&arg) {
            Some(ty) if ty == "bigint" => {}
            Some(ty) => problems.push(format!(
                "`{arg}` is declared as `{ty}` but passed as Soroban `{hint}`; \
                 64-bit and wider integers must be `bigint`"
            )),
            None => problems.push(format!(
                "`{arg}` is passed as Soroban `{hint}` without a type annotation"
            )),
        }
    }
    problems
}

/// Automated check #58 (type map half): the Soroban to TypeScript map must
/// never widen a 64-bit or wider integer to `number`.
pub fn audit_type_map() -> Vec<String> {
    let mut problems = Vec::new();
    for t in WIDE_INT_TYPES {
        let ts = ts_type_for(t);
        if ts != "bigint" {
            problems.push(format!("Soroban `{t}` maps to `{ts}`, expected `bigint`"));
        }
        let hint = scval_type_for(t);
        if hint != t {
            problems.push(format!("Soroban `{t}` hint is `{hint}`, expected `{t}`"));
        }
    }
    for t in ["i32", "u32"] {
        let ts = ts_type_for(t);
        if ts != "number" {
            problems.push(format!("Soroban `{t}` maps to `{ts}`, expected `number`"));
        }
    }
    problems
}

/// Run every codegen check for `spec`; an empty result means the client passes
/// both the import dedup check and the bigint mapping check.
pub fn run_checks(spec: &ContractSpec) -> Vec<String> {
    let generator = TsClientGenerator::new(spec.clone());
    let mut problems = audit_type_map();
    for (name, source) in generator.files() {
        for problem in audit_imports(&source) {
            problems.push(format!("{name}: {problem}"));
        }
        for problem in audit_bigint(&source) {
            problems.push(format!("{name}: {problem}"));
        }
    }
    problems
}

fn import_module(line: &str) -> Option<String> {
    let (_, after_from) = line.split_once(" from ")?;
    let start = after_from.find(['"', '\''])?;
    let quote = after_from[start..].chars().next()?;
    let rest = &after_from[start + quote.len_utf8()..];
    let end = rest.find(quote)?;
    Some(rest[..end].to_string())
}

fn import_symbols(line: &str) -> Vec<String> {
    let Some(open) = line.find('{') else {
        return Vec::new();
    };
    let Some(close) = line.rfind('}') else {
        return Vec::new();
    };
    if close <= open {
        return Vec::new();
    }
    line[open + 1..close]
        .split(',')
        .map(|s| s.trim().trim_start_matches("type ").trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// `name: type` annotations declared anywhere in the module.
fn declared_types(source: &str) -> BTreeMap<String, String> {
    let mut declared = BTreeMap::new();
    for line in source.lines() {
        let line = line.trim();
        if line.starts_with("//") {
            continue;
        }
        let mut rest = line;
        while let Some(idx) = rest.find(": ") {
            let (before, after) = rest.split_at(idx);
            let name = before
                .rsplit(|c: char| !(c.is_alphanumeric() || c == '_' || c == '$'))
                .next()
                .unwrap_or("");
            let ty: String = after[2..]
                .chars()
                .take_while(|c| !matches!(*c, ',' | '=' | ';' | ')'))
                .collect();
            let ty = ty.trim();
            if name.starts_with(|c: char| c.is_alphabetic() || c == '_' || c == '$')
                && !ty.is_empty()
                && !ty.contains(' ')
            {
                declared
                    .entry(name.to_string())
                    .or_insert_with(|| ty.to_string());
            }
            rest = &after[2..];
        }
    }
    declared
}

/// `(identifier, hint)` pairs for every `toScVal(identifier, "hint")` call.
fn bigint_call_args(source: &str) -> Vec<(String, String)> {
    let mut calls = Vec::new();
    for line in source.lines() {
        let mut rest = line;
        while let Some(idx) = rest.find("toScVal(") {
            let after = &rest[idx + "toScVal(".len()..];
            let Some(end) = after.find(')') else { break };
            let call = &after[..end];
            let Some(comma) = call.find(", ") else { break };
            calls.push((
                call[..comma].trim().to_string(),
                call[comma + 2..].trim().trim_matches('"').to_string(),
            ));
            rest = &after[end..];
        }
    }
    calls
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn import_set_merges_repeated_symbols_per_module() {
        let mut imports = ImportSet::new();
        imports.add_value(SDK_MODULE, "Contract");
        imports.add_value(SDK_MODULE, "rpc");
        imports.add_value(SDK_MODULE, "Contract");
        imports.add_value("./scval", "toScVal");
        imports.add_value("./scval", "toScVal");

        let rendered = imports.render();
        assert_eq!(
            rendered,
            "import { toScVal } from \"./scval\";\nimport { Contract, rpc } from \"stellar-sdk\";\n"
        );
        assert_eq!(rendered.matches("import ").count(), 2);
    }

    #[test]
    fn generated_modules_have_no_duplicate_imports() {
        let generator = TsClientGenerator::new(ContractSpec::amm_pool());
        for (name, source) in generator.files() {
            let problems = audit_imports(&source);
            assert!(problems.is_empty(), "{name}: {problems:?}");
            let sdk = source
                .lines()
                .filter(|l| l.contains("\"stellar-sdk\""))
                .count();
            assert_eq!(sdk, 1, "{name} imports stellar-sdk more than once");
        }
    }

    #[test]
    fn wide_integers_map_to_bigint() {
        for t in WIDE_INT_TYPES {
            assert_eq!(ts_type_for(t), "bigint");
            assert_eq!(scval_type_for(t), t);
        }
        assert_eq!(ts_type_for("i32"), "number");
        assert_eq!(ts_type_for("u32"), "number");
        assert_eq!(ts_type_for("Address"), "string");
        assert_eq!(ts_type_for("bool"), "boolean");
        assert_eq!(ts_type_for("Vec<Address>"), "Array<string>");
        assert_eq!(ts_type_for("Option<i128>"), "bigint | undefined");
        assert_eq!(ts_type_for("Map<String, i128>"), "Map<string, bigint>");
        assert_eq!(ts_type_for("(i128, u64)"), "[bigint, bigint]");
        assert!(audit_type_map().is_empty());
    }

    #[test]
    fn generated_client_uses_bigint_for_pool_amounts() {
        let client = TsClientGenerator::new(ContractSpec::amm_pool()).generate();
        assert!(client.contains("amountADesired: bigint"));
        assert!(client.contains("minOut: bigint"));
        assert!(client.contains("expirationLedger: number"));
        assert!(client.contains("toScVal(minOut, \"i128\")"));
        assert!(client.contains("Promise<bigint>"));
        assert!(audit_bigint(&client).is_empty());
    }

    #[test]
    fn optional_params_and_spec_round_trip() {
        let spec = ContractSpec {
            name: "Tiny".to_string(),
            contract_id: "C0".to_string(),
            network_passphrase: "Public Global Stellar Network ; September 2015".to_string(),
            functions: vec![FunctionSpec::new(
                "mint",
                "Mint to an optional recipient.",
                vec![
                    ParamSpec::new("amount", "i128"),
                    ParamSpec::optional("to", "Address"),
                ],
                "i128",
            )],
        };
        let generator = TsClientGenerator::new(spec.clone());
        let client = generator.generate();
        assert!(client.contains("amount: bigint"));
        assert!(client.contains("to?: string"));
        assert_eq!(generator.spec().rpc_url(), "https://soroban.stellar.org");
        assert!(run_checks(&spec).is_empty());

        let dir = tempfile::tempdir().unwrap();
        let json = dir.path().join("tiny.json");
        std::fs::write(&json, serde_json::to_string_pretty(&spec).unwrap()).unwrap();
        let loaded = ContractSpec::from_json_file(&json).unwrap();
        assert_eq!(loaded.functions.len(), 1);
        assert!(loaded.functions[0].params[1].optional);
    }

    #[test]
    fn writes_client_and_runtime_files() {
        let dir = tempfile::tempdir().unwrap();
        let generator = TsClientGenerator::new(ContractSpec::amm_pool());
        let paths = generator.write_to_dir(dir.path()).unwrap();
        assert_eq!(paths.len(), 2);
        assert!(dir.path().join("amm-pool.ts").exists());
        assert!(dir.path().join("scval.ts").exists());
    }

    #[test]
    fn audit_flags_duplicate_imports() {
        let source = concat!(
            "import { Contract } from \"stellar-sdk\";\n",
            "import { Contract, rpc } from \"stellar-sdk\";\n",
        );
        let problems = audit_imports(source);
        assert_eq!(problems.len(), 1);
        assert!(problems[0].contains("stellar-sdk"));

        let repeated = "import { Contract, Contract } from \"stellar-sdk\";\n";
        assert_eq!(audit_imports(repeated).len(), 1);
    }

    #[test]
    fn audit_flags_number_typed_wide_integers() {
        let source = concat!(
            "  async swap(to: string, min_out: number): Promise<void> {\n",
            "    await this.contract.invoke(\"swap\", to, toScVal(min_out, \"i128\"));\n",
            "  }\n",
        );
        let problems = audit_bigint(source);
        assert_eq!(problems.len(), 1);
        assert!(problems[0].contains("bigint"));
    }
}
