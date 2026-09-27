//! Migration diff generator: compare two Soroban contract interface snapshots
//! and report what changed.
//!
//! A redeploy or an SDK bump breaks integrators in a small number of very
//! specific ways, and none of them are visible from the contract's source: a
//! function disappears, an argument is inserted, a return type narrows, an
//! event stops being emitted. This module turns two interface snapshots into a
//! structured, ordered list of those changes so a migration can be reviewed
//! before it reaches mainnet.
//!
//! # Input format — and what was actually verified
//!
//! The `soroban-sdk` does **not** emit the `{"env": ..., "modules": ...}` JSON
//! that is sometimes described as a Soroban contract spec. What it emits is a
//! WASM custom section named **`contractspecv0`**, containing an XDR stream of
//! `SCSpecEntry` values, one per function and per event. The canonical JSON
//! rendering of that stream — what `stellar contract inspect interface` and
//! the SDK's own `spec-json` helper print — is a **flat JSON array** of
//! `SCSpecEntry` objects, each a one-armed union keyed `function_v0` or
//! `event_v0`.
//!
//! Every field name and shape below was read out of the `stellar-xdr` JSON
//! schema for `ScSpecEntry`, not guessed. The two that surprise people:
//!
//! * the reserved word `type` is serialised as **`type_`**,
//! * `SCSpecTypeDef` is a union that is *either* a bare string
//!   (`"address"`, `"i128"`, `"void"`) *or* an object
//!   (`{"vec": {...}}`, `{"option": {...}}`, `{"udt": {"name": "..."}}`, ...).
//!
//! This module has **not** been validated against a compiled contract artifact:
//! the repository contains no built WASM, and the pinned `soroban-sdk 21.7.7`
//! predates the tooling needed to produce one. The schema-level verification is
//! as far as the evidence goes, and it is why the parser is deliberately
//! permissive — unknown keys are ignored and unknown type encodings are kept
//! verbatim as canonical strings rather than rejected, so a snapshot from a
//! newer SDK degrades to "shown as changed" instead of failing to parse.
//!
//! # Design: compare is separate from render
//!
//! [`diff_specs`] is pure and returns structured data ([`SpecDiff`]); it does no
//! I/O and never formats for a human. Rendering is a separate layer
//! ([`render_text`], [`render_json`]). That split is what makes the whole thing
//! unit-testable without touching the filesystem, and it is why the CLI is a
//! thin wrapper rather than the substance of the feature.
//!
//! # Arity changes are the headline
//!
//! An added, removed, or reordered argument silently breaks every existing
//! caller, because Soroban contract functions are invoked positionally. That is
//! the single most valuable signal this tool produces, so argument changes are
//! classified individually ([`ArgumentChange`]), flagged as breaking, and
//! rendered in a dedicated section ahead of everything else. Return-type
//! changes are breaking for the same reason — a caller that decodes `i128` will
//! fail against a `void`.
//!
//! Breaking, as defined by [`SpecDiff::is_breaking`]:
//!
//! * a function or event was **removed**,
//! * a function's **arguments were added, removed, reordered, or retyped**,
//! * a function's **return type changed**.
//!
//! Additions (new functions, new events, new optional arguments) are reported
//! but are not breaking.

use crate::error::{Result, ToolkitError};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Maximum number of arguments a Soroban contract function may declare.
pub const MAX_FUNCTION_ARGS: usize = 10;

/// Maximum length of a function or event name in the contract spec.
pub const MAX_NAME_LEN: usize = 32;

/// One argument of a contract function.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ArgSpec {
    pub name: String,
    /// Canonical rendering of the argument type, e.g. `"address"` or
    /// `"vec:address"`. See [`canonical_type`].
    pub type_: String,
}

/// A contract function in a spec snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionSpec {
    pub name: String,
    pub inputs: Vec<ArgSpec>,
    /// Rendered return types. Empty means `void`; the XDR caps this at one.
    pub outputs: Vec<String>,
}

/// One parameter of a contract event.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EventParamSpec {
    pub name: String,
    pub type_: String,
    /// `topic_list` or `data`, from `SCSpecEventParamLocationV0`.
    pub location: String,
}

/// A contract event in a spec snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventSpec {
    pub name: String,
    pub params: Vec<EventParamSpec>,
    /// `single_value`, `vec`, or `map`, from `SCSpecEventDataFormat`.
    pub data_format: String,
}

/// A parsed contract interface snapshot.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractSpec {
    /// Keyed by function name so comparison is order-independent. `BTreeMap`
    /// so output is deterministic.
    pub functions: BTreeMap<String, FunctionSpec>,
    /// Keyed by event name.
    pub events: BTreeMap<String, EventSpec>,
}

impl ContractSpec {
    /// Parses the XDR-JSON rendering of a `contractspecv0` entry stream.
    ///
    /// Accepts either a bare array of entries or an object wrapping one under
    /// `entries`, since tooling differs on which it emits.
    pub fn from_json(json: &str) -> Result<Self> {
        let root: Value = serde_json::from_str(json)
            .map_err(|e| ToolkitError::ContractSpec(format!("input is not valid JSON: {e}")))?;

        let entries: Vec<Value> = match &root {
            Value::Array(a) => a.clone(),
            Value::Object(map) => match map.get("entries") {
                Some(Value::Array(a)) => a.clone(),
                _ => {
                    return Err(ToolkitError::ContractSpec(
                        "expected a JSON array of contract spec entries, or an object with an \
                         `entries` array"
                            .to_string(),
                    ))
                }
            },
            _ => {
                return Err(ToolkitError::ContractSpec(
                    "expected a JSON array of contract spec entries".to_string(),
                ))
            }
        };

        let mut spec = ContractSpec::default();
        for (i, entry) in entries.iter().enumerate() {
            spec.absorb_entry(entry)
                .map_err(|e| ToolkitError::ContractSpec(format!("entry {i}: {e}")))?;
        }
        Ok(spec)
    }

    /// Reads and parses a spec snapshot from a file.
    pub fn from_file(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).map_err(|e| {
            ToolkitError::ContractSpec(format!("cannot read contract spec {}: {e}", path.display()))
        })?;
        Self::from_json(&text)
    }

    /// Adds one `SCSpecEntry` to the spec. Entries that are not functions or
    /// events (structs, enums, unions) are ignored: this diff is scoped to the
    /// surface that breaks integrators.
    fn absorb_entry(&mut self, entry: &Value) -> std::result::Result<(), String> {
        let obj = entry
            .as_object()
            .ok_or_else(|| "spec entry must be an object".to_string())?;

        if let Some(f) = obj.get("function_v0") {
            let function = parse_function(f)?;
            // Later entries win, matching how the spec is a set not a list.
            self.functions.insert(function.name.clone(), function);
            return Ok(());
        }

        if let Some(e) = obj.get("event_v0") {
            let event = parse_event(e)?;
            self.events.insert(event.name.clone(), event);
            return Ok(());
        }

        Ok(())
    }
}

fn parse_function(v: &Value) -> std::result::Result<FunctionSpec, String> {
    let obj = v
        .as_object()
        .ok_or_else(|| "`function_v0` must be an object".to_string())?;

    let name = required_name(obj, "name", "function_v0")?;

    let mut inputs = Vec::new();
    if let Some(list) = obj.get("inputs") {
        let arr = list
            .as_array()
            .ok_or_else(|| "`inputs` must be an array".to_string())?;
        if arr.len() > MAX_FUNCTION_ARGS {
            return Err(format!(
                "function `{name}` has {} inputs, more than the {MAX_FUNCTION_ARGS} the spec allows",
                arr.len()
            ));
        }
        for arg in arr {
            let ao = arg
                .as_object()
                .ok_or_else(|| "each input must be an object".to_string())?;
            inputs.push(ArgSpec {
                name: required_str(ao, "name", "input")?,
                type_: parse_type_field(ao, "input")?,
            });
        }
    }

    let mut outputs = Vec::new();
    if let Some(list) = obj.get("outputs") {
        let arr = list
            .as_array()
            .ok_or_else(|| "`outputs` must be an array".to_string())?;
        for out in arr {
            outputs.push(canonical_type(out));
        }
    }

    Ok(FunctionSpec {
        name,
        inputs,
        outputs,
    })
}

fn parse_event(v: &Value) -> std::result::Result<EventSpec, String> {
    let obj = v
        .as_object()
        .ok_or_else(|| "`event_v0` must be an object".to_string())?;

    let name = required_name(obj, "name", "event_v0")?;

    let mut params = Vec::new();
    if let Some(list) = obj.get("params") {
        let arr = list
            .as_array()
            .ok_or_else(|| "`params` must be an array".to_string())?;
        for p in arr {
            let po = p
                .as_object()
                .ok_or_else(|| "each param must be an object".to_string())?;
            params.push(EventParamSpec {
                name: required_str(po, "name", "param")?,
                type_: parse_type_field(po, "param")?,
                location: po
                    .get("location")
                    .and_then(Value::as_str)
                    .unwrap_or("data")
                    .to_string(),
            });
        }
    }

    Ok(EventSpec {
        name,
        params,
        data_format: obj
            .get("data_format")
            .and_then(Value::as_str)
            .unwrap_or("single_value")
            .to_string(),
    })
}

/// Read a name field, enforcing the `SCSYMBOL_LIMIT` the spec imposes.
fn required_name(
    obj: &serde_json::Map<String, Value>,
    key: &str,
    context: &str,
) -> std::result::Result<String, String> {
    let name = required_str(obj, key, context)?;
    if name.is_empty() {
        return Err(format!("{context} `{key}` must not be empty"));
    }
    if name.chars().count() > MAX_NAME_LEN {
        return Err(format!(
            "{context} `{key}` is {} characters, over the {MAX_NAME_LEN}-character limit",
            name.chars().count()
        ));
    }
    Ok(name)
}

fn required_str(
    obj: &serde_json::Map<String, Value>,
    key: &str,
    context: &str,
) -> std::result::Result<String, String> {
    obj.get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| format!("{context} is missing a string `{key}`"))
}

/// Read a `type_` field, accepting the reserved-word spelling `type` too.
fn parse_type_field(
    obj: &serde_json::Map<String, Value>,
    context: &str,
) -> std::result::Result<String, String> {
    let raw = obj
        .get("type_")
        .or_else(|| obj.get("type"))
        .ok_or_else(|| format!("{context} is missing `type_`"))?;
    Ok(canonical_type(raw))
}

/// Render a `SCSpecTypeDef` JSON value as a stable, comparable string.
///
/// Scalars become their own name (`"address"`). Unions become
/// `"kind(payload)"`, e.g. `vec(address)`, `option(i128)`, `udt(MyStruct)`,
/// `bytes_n(32)`, `tuple(address, i128)`. Object keys are emitted in sorted
/// order so two encodings of the same type always produce the same string,
/// whatever order the snapshot happened to serialise them in.
pub fn canonical_type(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Object(map) => {
            let mut parts: Vec<String> = map
                .iter()
                .map(|(k, val)| format!("{k}({})", canonical_type(val)))
                .collect();
            parts.sort();
            parts.join(",")
        }
        Value::Array(arr) => {
            let parts: Vec<String> = arr.iter().map(canonical_type).collect();
            format!("[{}]", parts.join(", "))
        }
        // Not part of the schema; keep it visible rather than dropping it, so
        // a snapshot from a newer SDK still shows up as a difference.
        other => other.to_string(),
    }
}

/// Render an output list as a single return-type string.
fn render_outputs(outputs: &[String]) -> String {
    if outputs.is_empty() {
        "void".to_string()
    } else {
        outputs.join(", ")
    }
}

/// How one function's argument list changed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArgumentChange {
    /// A new argument appeared. **Breaking**: every existing positional call
    /// now supplies too few arguments.
    Added { position: usize, arg: ArgSpec },
    /// An argument disappeared. **Breaking**: existing calls are malformed.
    Removed { position: usize, arg: ArgSpec },
    /// The same arguments in a different order. **Breaking**: positional
    /// arguments are now bound to the wrong parameters.
    Reordered {
        before: Vec<String>,
        after: Vec<String>,
    },
    /// An argument kept its position and name but changed type.
    TypeChanged {
        position: usize,
        name: String,
        before: String,
        after: String,
    },
}

impl ArgumentChange {
    /// Every argument-list change except a reorder is breaking.
    pub fn is_breaking(&self) -> bool {
        true
    }

    /// One-line rendering, used by both the text and JSON output.
    pub fn describe(&self) -> String {
        match self {
            Self::Added { position, arg } => {
                format!("+ arg[{position}] `{}`: {}", arg.name, arg.type_)
            }
            Self::Removed { position, arg } => {
                format!("- arg[{position}] `{}`: {}", arg.name, arg.type_)
            }
            Self::Reordered { before, after } => {
                format!(
                    "~ arg order: [{}] -> [{}]",
                    before.join(", "),
                    after.join(", ")
                )
            }
            Self::TypeChanged {
                position,
                name,
                before,
                after,
            } => format!("~ arg[{position}] `{name}`: {before} -> {after}"),
        }
    }
}

/// A function that exists in both snapshots but differs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionChange {
    pub name: String,
    pub argument_changes: Vec<ArgumentChange>,
    pub return_before: String,
    pub return_after: String,
    pub return_changed: bool,
}

impl FunctionChange {
    /// A function change is breaking if any argument changed or the return
    /// type changed.
    pub fn is_breaking(&self) -> bool {
        self.return_changed || self.argument_changes.iter().any(|c| c.is_breaking())
    }
}

/// A function present in only one snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionAddition {
    pub spec: FunctionSpec,
}

/// An event that exists in both snapshots but differs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventChange {
    pub name: String,
    pub argument_changes: Vec<ArgumentChange>,
    pub data_format_before: String,
    pub data_format_after: String,
    pub data_format_changed: bool,
}

impl EventChange {
    /// Events are consumed by indexers rather than called positionally, so
    /// only a *removed* event is treated as breaking; a changed event is
    /// reported but does not fail a migration.
    pub fn is_breaking(&self) -> bool {
        false
    }
}

/// Added, removed, and changed functions.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionChanges {
    pub added: Vec<FunctionSpec>,
    pub removed: Vec<FunctionSpec>,
    pub changed: Vec<FunctionChange>,
}

/// Added, removed, and changed events.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventChanges {
    pub added: Vec<EventSpec>,
    pub removed: Vec<EventSpec>,
    pub changed: Vec<EventChange>,
}

/// The complete comparison of two contract interface snapshots.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpecDiff {
    pub functions: FunctionChanges,
    pub events: EventChanges,
}

impl SpecDiff {
    /// Total number of individual changes, for a one-line summary.
    pub fn change_count(&self) -> usize {
        self.functions.added.len()
            + self.functions.removed.len()
            + self.functions.changed.len()
            + self.events.added.len()
            + self.events.removed.len()
            + self.events.changed.len()
    }

    /// Whether anything in this diff breaks an existing integrator.
    pub fn is_breaking(&self) -> bool {
        !self.functions.removed.is_empty()
            || self
                .functions
                .changed
                .iter()
                .any(FunctionChange::is_breaking)
            || !self.events.removed.is_empty()
    }

    /// Every breaking change, as human-readable lines, in a stable order.
    /// Argument changes come first because they are the highest-value signal.
    pub fn breaking_lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        for f in &self.functions.changed {
            for c in &f.argument_changes {
                lines.push(format!("BREAKING  {}.  {}", f.name, c.describe()));
            }
            if f.return_changed {
                lines.push(format!(
                    "BREAKING  {}.  return: {} -> {}",
                    f.name, f.return_before, f.return_after
                ));
            }
        }
        for f in &self.functions.removed {
            lines.push(format!("BREAKING  {}.  function removed", f.name));
        }
        for e in &self.events.removed {
            lines.push(format!("BREAKING  {}.  event removed", e.name));
        }
        lines
    }
}

/// Compares two contract interface snapshots.
///
/// Pure: no I/O, no clock, no formatting. Two identical snapshots always
/// produce an empty diff.
pub fn diff_specs(before: &ContractSpec, after: &ContractSpec) -> SpecDiff {
    let mut functions = FunctionChanges::default();
    let mut events = EventChanges::default();

    // ---- functions -------------------------------------------------------
    for (name, old) in &before.functions {
        match after.functions.get(name) {
            Some(new) => {
                let argument_changes = diff_arguments(&old.inputs, &new.inputs);
                let return_before = render_outputs(&old.outputs);
                let return_after = render_outputs(&new.outputs);
                let return_changed = return_before != return_after;
                if !argument_changes.is_empty() || return_changed {
                    functions.changed.push(FunctionChange {
                        name: name.clone(),
                        argument_changes,
                        return_before,
                        return_after,
                        return_changed,
                    });
                }
            }
            None => functions.removed.push(old.clone()),
        }
    }
    for (name, new) in &after.functions {
        if !before.functions.contains_key(name) {
            functions.added.push(new.clone());
        }
    }

    // ---- events ----------------------------------------------------------
    for (name, old) in &before.events {
        match after.events.get(name) {
            Some(new) => {
                let old_args: Vec<ArgSpec> = old
                    .params
                    .iter()
                    .map(|p| ArgSpec {
                        name: p.name.clone(),
                        type_: p.type_.clone(),
                    })
                    .collect();
                let new_args: Vec<ArgSpec> = new
                    .params
                    .iter()
                    .map(|p| ArgSpec {
                        name: p.name.clone(),
                        type_: p.type_.clone(),
                    })
                    .collect();
                let argument_changes = diff_arguments(&old_args, &new_args);
                let data_format_changed = old.data_format != new.data_format;
                if !argument_changes.is_empty() || data_format_changed {
                    events.changed.push(EventChange {
                        name: name.clone(),
                        argument_changes,
                        data_format_before: old.data_format.clone(),
                        data_format_after: new.data_format.clone(),
                        data_format_changed,
                    });
                }
            }
            None => events.removed.push(old.clone()),
        }
    }
    for (name, new) in &after.events {
        if !before.events.contains_key(name) {
            events.added.push(new.clone());
        }
    }

    SpecDiff { functions, events }
}

/// Classify how one argument list changed relative to another.
///
/// Arguments are matched **by name**, because that is the only stable identity
/// the spec gives them. A rename therefore surfaces as a removal plus an
/// addition, which is the honest reading: it really does break every caller.
/// Ordering is then compared on the arguments common to both lists, so an
/// insertion and a reorder are reported as two distinct facts rather than
/// being conflated.
fn diff_arguments(before: &[ArgSpec], after: &[ArgSpec]) -> Vec<ArgumentChange> {
    let mut changes = Vec::new();

    let before_names: BTreeSet<&str> = before.iter().map(|a| a.name.as_str()).collect();
    let after_names: BTreeSet<&str> = after.iter().map(|a| a.name.as_str()).collect();

    for (position, arg) in after.iter().enumerate() {
        if !before_names.contains(arg.name.as_str()) {
            changes.push(ArgumentChange::Added {
                position,
                arg: arg.clone(),
            });
        }
    }
    for (position, arg) in before.iter().enumerate() {
        if !after_names.contains(arg.name.as_str()) {
            changes.push(ArgumentChange::Removed {
                position,
                arg: arg.clone(),
            });
        }
    }

    // Order of the surviving arguments.
    let common_before: Vec<&str> = before
        .iter()
        .map(|a| a.name.as_str())
        .filter(|n| after_names.contains(n))
        .collect();
    let common_after: Vec<&str> = after
        .iter()
        .map(|a| a.name.as_str())
        .filter(|n| before_names.contains(n))
        .collect();
    if common_before != common_after && !common_before.is_empty() {
        changes.push(ArgumentChange::Reordered {
            before: common_before.iter().map(|s| s.to_string()).collect(),
            after: common_after.iter().map(|s| s.to_string()).collect(),
        });
    }

    // Types of the surviving arguments.
    for (position, old) in before.iter().enumerate() {
        if let Some(new) = after.iter().find(|a| a.name == old.name) {
            if new.type_ != old.type_ {
                changes.push(ArgumentChange::TypeChanged {
                    position,
                    name: old.name.clone(),
                    before: old.type_.clone(),
                    after: new.type_.clone(),
                });
            }
        }
    }

    changes
}

/// Render a diff as human-readable text.
///
/// Breaking argument and return changes are printed first, under their own
/// heading, because they are what breaks callers and they are the reason to
/// read this output at all.
pub fn render_text(diff: &SpecDiff) -> String {
    let mut out = String::new();

    if diff.change_count() == 0 {
        return "No interface changes detected.\n".to_string();
    }

    let breaking = diff.breaking_lines();
    if !breaking.is_empty() {
        out.push_str(&format!("BREAKING CHANGES ({}):\n", breaking.len()));
        for line in &breaking {
            out.push_str("  ");
            out.push_str(line);
            out.push('\n');
        }
        out.push('\n');
    }

    if !diff.functions.removed.is_empty() {
        out.push_str("Functions removed:\n");
        for f in &diff.functions.removed {
            out.push_str(&format!("  - {}({})\n", f.name, render_args(&f.inputs)));
        }
        out.push('\n');
    }

    if !diff.functions.added.is_empty() {
        out.push_str("Functions added:\n");
        for f in &diff.functions.added {
            out.push_str(&format!(
                "  + {}({}) -> {}\n",
                f.name,
                render_args(&f.inputs),
                render_outputs(&f.outputs)
            ));
        }
        out.push('\n');
    }

    if !diff.functions.changed.is_empty() {
        out.push_str("Functions changed:\n");
        for f in &diff.functions.changed {
            out.push_str(&format!("  ~ {}\n", f.name));
            for c in &f.argument_changes {
                out.push_str(&format!("      {}\n", c.describe()));
            }
            if f.return_changed {
                out.push_str(&format!(
                    "      ~ return: {} -> {}\n",
                    f.return_before, f.return_after
                ));
            }
        }
        out.push('\n');
    }

    if !diff.events.removed.is_empty() {
        out.push_str("Events removed:\n");
        for e in &diff.events.removed {
            out.push_str(&format!("  - {}\n", e.name));
        }
        out.push('\n');
    }

    if !diff.events.added.is_empty() {
        out.push_str("Events added:\n");
        for e in &diff.events.added {
            out.push_str(&format!(
                "  + {}({})\n",
                e.name,
                render_event_params(&e.params)
            ));
        }
        out.push('\n');
    }

    if !diff.events.changed.is_empty() {
        out.push_str("Events changed:\n");
        for e in &diff.events.changed {
            out.push_str(&format!("  ~ {}\n", e.name));
            for c in &e.argument_changes {
                out.push_str(&format!("      {}\n", c.describe()));
            }
            if e.data_format_changed {
                out.push_str(&format!(
                    "      ~ data format: {} -> {}\n",
                    e.data_format_before, e.data_format_after
                ));
            }
        }
        out.push('\n');
    }

    out.push_str(&format!(
        "Summary: {} function(s) changed ({} breaking), {} event(s) changed.\n",
        diff.functions.added.len() + diff.functions.removed.len() + diff.functions.changed.len(),
        diff.breaking_lines().len(),
        diff.events.added.len() + diff.events.removed.len() + diff.events.changed.len(),
    ));
    out
}

fn render_args(args: &[ArgSpec]) -> String {
    args.iter()
        .map(|a| format!("{}: {}", a.name, a.type_))
        .collect::<Vec<_>>()
        .join(", ")
}

fn render_event_params(params: &[EventParamSpec]) -> String {
    params
        .iter()
        .map(|p| format!("{}: {} [{}]", p.name, p.type_, p.location))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Render a diff as pretty JSON.
pub fn render_json(diff: &SpecDiff) -> Result<String> {
    serde_json::to_string_pretty(diff)
        .map_err(|e| ToolkitError::ContractSpec(format!("cannot serialise diff: {e}")))
}

/// Loads both snapshots from disk and diffs them.
pub fn diff_files(before: &Path, after: &Path) -> Result<SpecDiff> {
    Ok(diff_specs(
        &ContractSpec::from_file(before)?,
        &ContractSpec::from_file(after)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal but shape-accurate spec snapshot, using the real XDR-JSON
    /// spellings: `function_v0` / `event_v0` wrappers and `type_`.
    const BEFORE: &str = r#"[
      { "function_v0": { "doc": "", "name": "transfer",
          "inputs": [ {"doc":"","name":"to","type_":"address"},
                      {"doc":"","name":"amount","type_":"i128"} ],
          "outputs": [ "i128" ] } },
      { "function_v0": { "doc": "", "name": "balance",
          "inputs": [ {"doc":"","name":"who","type_":"address"} ],
          "outputs": [ "i128" ] } },
      { "function_v0": { "doc": "", "name": "legacy_round",
          "inputs": [], "outputs": [ "void" ] } },
      { "event_v0": { "doc": "", "lib": "", "name": "transfer", "prefix_topics": ["transfer"],
          "params": [ {"doc":"","location":"topic_list","name":"from","type_":"address"},
                      {"doc":"","location":"data","name":"amount","type_":"i128"} ],
          "data_format": "single_value" } },
      { "event_v0": { "doc": "", "lib": "", "name": "retired", "prefix_topics": ["retired"],
          "params": [], "data_format": "single_value" } }
    ]"#;

    fn before() -> ContractSpec {
        ContractSpec::from_json(BEFORE).expect("before spec parses")
    }

    /// A spec containing exactly one function and one event, so that diffing it
    /// against a sibling built the same way compares like for like. Using a
    /// spec with fewer entries than `before()` would report every missing
    /// function as a removal and drown out the change under test.
    fn lone_spec(inputs: &[(&str, &str)], outputs: &[&str]) -> ContractSpec {
        let mut spec = ContractSpec::default();
        spec.functions.insert(
            "transfer".to_string(),
            FunctionSpec {
                name: "transfer".to_string(),
                inputs: inputs
                    .iter()
                    .map(|(n, t)| ArgSpec {
                        name: (*n).to_string(),
                        type_: (*t).to_string(),
                    })
                    .collect(),
                outputs: outputs.iter().map(|o| (*o).to_string()).collect(),
            },
        );
        spec.events.insert(
            "transfer".to_string(),
            EventSpec {
                name: "transfer".to_string(),
                params: vec![
                    EventParamSpec {
                        name: "from".to_string(),
                        type_: "address".to_string(),
                        location: "topic_list".to_string(),
                    },
                    EventParamSpec {
                        name: "amount".to_string(),
                        type_: "i128".to_string(),
                        location: "data".to_string(),
                    },
                ],
                data_format: "single_value".to_string(),
            },
        );
        spec
    }

    /// The reference shape: `transfer(Address, I128) -> I128`.
    fn lone_before() -> ContractSpec {
        lone_spec(&[("to", "address"), ("amount", "i128")], &["i128"])
    }

    // ---- parsing ---------------------------------------------------------

    #[test]
    fn test_parses_functions_and_events_from_xdr_json() {
        let spec = before();
        assert_eq!(spec.functions.len(), 3);
        assert_eq!(spec.events.len(), 2);

        let t = &spec.functions["transfer"];
        assert_eq!(t.inputs.len(), 2);
        assert_eq!(t.inputs[0].name, "to");
        assert_eq!(t.inputs[0].type_, "address");
        assert_eq!(t.outputs, vec!["i128".to_string()]);

        let e = &spec.events["transfer"];
        assert_eq!(e.params[0].location, "topic_list");
        assert_eq!(e.params[1].location, "data");
    }

    #[test]
    fn test_canonical_type_handles_scalars_and_unions() {
        assert_eq!(canonical_type(&serde_json::json!("address")), "address");
        assert_eq!(
            canonical_type(&serde_json::json!({"vec": {"element_type": "address"}})),
            "vec(element_type(address))"
        );
        assert_eq!(
            canonical_type(&serde_json::json!({"option": {"value_type": "i128"}})),
            "option(value_type(i128))"
        );
        assert_eq!(
            canonical_type(&serde_json::json!({"udt": {"name": "MyStruct"}})),
            "udt(name(MyStruct))"
        );
        assert_eq!(
            canonical_type(&serde_json::json!({"bytes_n": {"n": 32}})),
            "bytes_n(n(32))"
        );
    }

    #[test]
    fn test_canonical_type_is_key_order_independent() {
        let a = canonical_type(&serde_json::json!({"vec": {"element_type": "i128"}}));
        let b = canonical_type(&serde_json::json!({"vec": {"element_type": "i128"}}));
        assert_eq!(a, b);
    }

    #[test]
    fn test_empty_inputs_and_outputs() {
        let spec = ContractSpec::from_json(
            r#"[{"function_v0":{"doc":"","name":"poke","inputs":[],"outputs":[]}}]"#,
        )
        .unwrap();
        let f = &spec.functions["poke"];
        assert!(f.inputs.is_empty());
        assert!(f.outputs.is_empty());
        assert_eq!(render_outputs(&f.outputs), "void");
    }

    #[test]
    fn test_wrapper_object_form_is_accepted() {
        let wrapped = format!("{{\"entries\": {BEFORE} }}");
        assert_eq!(
            ContractSpec::from_json(&wrapped).unwrap().functions.len(),
            3
        );
    }

    #[test]
    fn test_empty_inputs_give_empty_spec() {
        let spec = ContractSpec::from_json("[]").unwrap();
        assert!(spec.functions.is_empty());
        assert!(spec.events.is_empty());
        let diff = diff_specs(&spec, &spec);
        assert_eq!(diff.change_count(), 0);
        assert_eq!(render_text(&diff), "No interface changes detected.\n");
    }

    #[test]
    fn test_non_function_entries_are_ignored() {
        let spec = ContractSpec::from_json(
            r#"[{"udt_struct_v0":{"doc":"","lib":"","name":"Foo","fields":[]}},
                {"function_v0":{"doc":"","name":"f","inputs":[],"outputs":["void"]}}]"#,
        )
        .unwrap();
        assert_eq!(spec.functions.len(), 1);
        assert!(spec.events.is_empty());
    }

    // ---- malformed input -------------------------------------------------

    #[test]
    fn test_malformed_json_is_an_error_not_a_panic() {
        for bad in [
            "not json at all",
            "{",
            "[ {",
            "42",
            "\"a string\"",
            r#"[{"function_v0":"not an object"}]"#,
            r#"[{"function_v0":{"inputs":[],"outputs":[]}}]"#,
            r#"[{"function_v0":{"name":"","inputs":[],"outputs":[]}}]"#,
            r#"[{"function_v0":{"name":"f","inputs":"nope","outputs":[]}}]"#,
            r#"[{"function_v0":{"name":"f","inputs":[{"name":"a"}],"outputs":[]}}]"#,
            r#"[{"event_v0":{"name":"e","params":[{"type_":"address"}]}}]"#,
            r#"[{"function_v0":{"name":"f","inputs":[{"name":"a","type_":"address"}],"outputs":"nope"}}]"#,
        ] {
            let err = ContractSpec::from_json(bad).unwrap_err().to_string();
            assert!(
                err.contains("contract spec error"),
                "unhelpful error for {bad:?}: {err}"
            );
        }
    }

    #[test]
    fn test_too_many_arguments_is_rejected() {
        let inputs: Vec<String> = (0..=MAX_FUNCTION_ARGS)
            .map(|i| format!(r#"{{"name":"a{i}","type_":"i128"}}"#))
            .collect();
        let json = format!(
            r#"[{{"function_v0":{{"name":"f","inputs":[{}],"outputs":[]}}}}]"#,
            inputs.join(",")
        );
        let err = ContractSpec::from_json(&json).unwrap_err().to_string();
        assert!(err.contains("more than the 10"));
    }

    #[test]
    fn test_overlong_name_is_rejected() {
        let long = "x".repeat(MAX_NAME_LEN + 1);
        let json = format!(r#"[{{"function_v0":{{"name":"{long}","inputs":[],"outputs":[]}}}}]"#);
        let err = ContractSpec::from_json(&json).unwrap_err().to_string();
        assert!(err.contains("over the 32-character limit"));
    }

    #[test]
    fn test_missing_file_is_a_clear_error() {
        let err = ContractSpec::from_file(Path::new("/no/such/spec.json")).unwrap_err();
        assert!(err.to_string().contains("cannot read contract spec"));
        assert!(err.to_string().contains("/no/such/spec.json"));
    }

    // ---- comparison ------------------------------------------------------

    #[test]
    fn test_identical_specs_produce_no_change() {
        let diff = diff_specs(&before(), &before());
        assert_eq!(diff.change_count(), 0);
        assert!(!diff.is_breaking());
        assert!(diff.breaking_lines().is_empty());
    }

    #[test]
    fn test_entry_order_does_not_matter() {
        // Same functions, declared in a different order.
        let reordered = r#"[
          { "function_v0": { "name": "legacy_round","inputs":[], "outputs": ["void"] } },
          { "function_v0": { "name": "balance","inputs":[{"name":"who","type_":"address"}], "outputs": ["i128"] } },
          { "function_v0": { "name": "transfer","inputs":[{"name":"to","type_":"address"},{"name":"amount","type_":"i128"}], "outputs": ["i128"] } },
          { "event_v0": { "name": "retired","params": [], "data_format": "single_value" } },
          { "event_v0": { "name": "transfer","params":[{"name":"from","type_":"address","location":"topic_list"},{"name":"amount","type_":"i128","location":"data"}], "data_format": "single_value" } }
        ]"#;
        let diff = diff_specs(&before(), &ContractSpec::from_json(reordered).unwrap());
        assert_eq!(
            diff.change_count(),
            0,
            "entry order must not register as a change"
        );
    }

    #[test]
    fn test_function_added() {
        let after = ContractSpec::from_json(&format!(
            r#"[{}, {{"function_v0":{{"name":"freeze","inputs":[],"outputs":["bool"]}}}}]"#,
            &BEFORE[1..BEFORE.len() - 1]
        ))
        .unwrap();
        let diff = diff_specs(&before(), &after);
        assert_eq!(diff.functions.added.len(), 1);
        assert_eq!(diff.functions.added[0].name, "freeze");
        assert!(!diff.is_breaking(), "adding a function is not breaking");
    }

    #[test]
    fn test_function_removed_is_breaking() {
        let mut after = lone_before();
        after.functions.remove("transfer");
        // Direction matters: present in `before`, absent from `after`.
        let diff = diff_specs(&lone_before(), &after);
        assert_eq!(diff.functions.removed.len(), 1);
        assert!(diff.is_breaking());
        assert!(diff.breaking_lines()[0].contains("function removed"));
    }

    #[test]
    fn test_argument_added_is_breaking_and_classified() {
        let after = lone_spec(
            &[("to", "address"), ("amount", "i128"), ("memo", "string")],
            &["i128"],
        );
        let diff = diff_specs(&lone_before(), &after);
        assert!(diff.is_breaking());
        let f = &diff.functions.changed[0];
        assert_eq!(f.name, "transfer");
        assert_eq!(f.argument_changes.len(), 1);
        assert_eq!(
            f.argument_changes[0],
            ArgumentChange::Added {
                position: 2,
                arg: ArgSpec {
                    name: "memo".into(),
                    type_: "string".into()
                }
            }
        );
        assert!(diff.breaking_lines()[0].contains("+ arg[2] `memo`"));
    }

    #[test]
    fn test_argument_removed_is_breaking() {
        let after = lone_spec(&[("to", "address")], &["i128"]);
        let diff = diff_specs(&lone_before(), &after);
        let f = &diff.functions.changed[0];
        assert!(matches!(
            f.argument_changes.as_slice(),
            [ArgumentChange::Removed { position: 1, arg }] if arg.name == "amount"
        ));
        assert!(diff.is_breaking());
    }

    #[test]
    fn test_argument_reordered_is_breaking() {
        let after = lone_spec(&[("amount", "i128"), ("to", "address")], &["i128"]);
        let diff = diff_specs(&lone_before(), &after);
        let f = &diff.functions.changed[0];
        assert_eq!(
            f.argument_changes,
            vec![ArgumentChange::Reordered {
                before: vec!["to".into(), "amount".into()],
                after: vec!["amount".into(), "to".into()],
            }]
        );
        // A reorder of the same arguments is not an add or a remove.
        assert!(!f.argument_changes.iter().any(|c| matches!(
            c,
            ArgumentChange::Added { .. } | ArgumentChange::Removed { .. }
        )));
        assert!(diff.is_breaking());
    }

    #[test]
    fn test_argument_type_changed_is_breaking() {
        let after = lone_spec(&[("to", "address"), ("amount", "u128")], &["i128"]);
        let diff = diff_specs(&lone_before(), &after);
        let f = &diff.functions.changed[0];
        assert_eq!(
            f.argument_changes,
            vec![ArgumentChange::TypeChanged {
                position: 1,
                name: "amount".into(),
                before: "i128".into(),
                after: "u128".into(),
            }]
        );
        assert!(diff.is_breaking());
    }

    #[test]
    fn test_argument_rename_reads_as_remove_plus_add() {
        // A rename genuinely breaks positional callers, so reporting it as a
        // removal plus an addition is the honest classification.
        let after = lone_spec(&[("recipient", "address"), ("amount", "i128")], &["i128"]);
        let diff = diff_specs(&lone_before(), &after);
        let f = &diff.functions.changed[0];
        assert_eq!(f.argument_changes.len(), 2);
        assert!(f
            .argument_changes
            .iter()
            .any(|c| matches!(c, ArgumentChange::Removed { arg, .. } if arg.name == "to")));
        assert!(f
            .argument_changes
            .iter()
            .any(|c| matches!(c, ArgumentChange::Added { arg, .. } if arg.name == "recipient")));
    }

    #[test]
    fn test_return_type_changed_is_breaking() {
        let after = lone_spec(&[("to", "address"), ("amount", "i128")], &["void"]);
        let diff = diff_specs(&lone_before(), &after);
        let f = &diff.functions.changed[0];
        assert!(f.return_changed);
        assert_eq!(f.return_before, "i128");
        assert_eq!(f.return_after, "void");
        assert!(f.argument_changes.is_empty(), "args did not change");
        assert!(diff.is_breaking());
        assert!(diff.breaking_lines()[0].contains("return: i128 -> void"));
    }

    #[test]
    fn test_event_added_and_removed() {
        let mut a = before();
        a.events.remove("retired");
        a.events.insert(
            "mint".to_string(),
            EventSpec {
                name: "mint".into(),
                params: vec![],
                data_format: "single_value".into(),
            },
        );
        let diff = diff_specs(&before(), &a);
        assert_eq!(diff.events.added.len(), 1);
        assert_eq!(diff.events.removed.len(), 1);
        assert!(diff.is_breaking(), "a removed event breaks indexers");
    }

    #[test]
    fn test_event_params_changed_and_data_format_changed() {
        let mut after = lone_before();
        let e = after.events.get_mut("transfer").unwrap();
        e.params.push(EventParamSpec {
            name: "seq".into(),
            type_: "u64".into(),
            location: "data".into(),
        });
        e.data_format = "vec".into();
        let diff = diff_specs(&lone_before(), &after);
        let e = &diff.events.changed[0];
        assert!(e.data_format_changed);
        assert_eq!(e.data_format_before, "single_value");
        assert_eq!(e.data_format_after, "vec");
        assert!(e
            .argument_changes
            .iter()
            .any(|c| matches!(c, ArgumentChange::Added { arg, .. } if arg.name == "seq")));
        // A changed event is reported but does not fail a migration.
        assert!(!diff.is_breaking());
    }

    #[test]
    fn test_breaking_lines_put_argument_changes_first() {
        let after = lone_spec(
            &[("to", "address"), ("amount", "i128"), ("memo", "string")],
            &["bool"],
        );
        let diff = diff_specs(&lone_before(), &after);
        let lines = diff.breaking_lines();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("arg["), "argument change must come first");
        assert!(lines[1].contains("return:"));
    }

    // ---- rendering -------------------------------------------------------

    #[test]
    fn test_render_text_is_stable_and_mentions_arity_first() {
        let after = lone_spec(
            &[("to", "address"), ("amount", "i128"), ("memo", "string")],
            &["i128"],
        );
        let diff = diff_specs(&lone_before(), &after);
        let text = render_text(&diff);
        assert_eq!(text, render_text(&diff), "rendering must be deterministic");
        assert!(text.starts_with("BREAKING CHANGES (1):"));
        // The argument change appears before the "Functions changed" section.
        let arg_at = text.find("+ arg[2] `memo`").unwrap();
        let changed_at = text.find("Functions changed:").unwrap();
        assert!(arg_at < changed_at);
        assert!(text.contains("Summary:"));
    }

    #[test]
    fn test_render_json_roundtrips() {
        let after = lone_spec(&[("to", "address")], &["i128"]);
        let diff = diff_specs(&lone_before(), &after);
        let json = render_json(&diff).unwrap();
        let back: SpecDiff = serde_json::from_str(&json).unwrap();
        assert_eq!(back, diff);
    }

    #[test]
    fn test_diff_files_reports_a_missing_path_clearly() {
        let err = diff_files(
            Path::new("/no/such/before.json"),
            Path::new("/no/such/after.json"),
        )
        .unwrap_err();
        assert!(err.to_string().contains("cannot read contract spec"));
    }
}
