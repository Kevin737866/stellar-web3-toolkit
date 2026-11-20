//! Onboarding checklist progress (issue #194).
//!
//! `docs/CONTRIBUTING_ONBOARDING.md` tells a new contributor what to do, but
//! nothing tells them how far they have got. This module reads the checklist out
//! of that document and reports progress, so the answer comes from the same file
//! a maintainer edits rather than from a second copy that drifts.
//!
//! # What counts as a step
//!
//! A Markdown task item — `- [ ]` or `- [x]` — anywhere in the document, with
//! fenced code blocks ignored so a shell snippet containing `- [ ]` is not
//! mistaken for a step. Each step belongs to the nearest preceding `##`/`###`
//! heading, which is what makes the report readable: progress per section, not
//! just one global fraction.
//!
//! # How progress is recorded
//!
//! The document is the state. A contributor ticks `- [x]` as they go, which
//! means progress is committed and reviewable rather than living in a local
//! file. The CLI writes nothing back by default; `--write` is explicit because
//! silently rewriting a document someone is reading is surprising.
//!
//! # Why the parser is strict about its input
//!
//! It targets exactly the shape this one document uses: `#`/`##`/`###` headings,
//! `- [ ]` items, and ```` ``` ```` fences. A document with no checklist at all
//! is reported as such instead of as "100% complete", which would be the worst
//! possible lie for a progress check to tell.

use serde::Serialize;
use std::fmt::Write as _;

/// Default checklist document, relative to the workspace root.
pub const CHECKLIST_PATH: &str = "docs/CONTRIBUTING_ONBOARDING.md";

/// One checklist item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Step {
    /// Text after the checkbox, trimmed.
    pub text: String,
    /// Whether the box was `[x]`.
    pub done: bool,
    /// Nearest preceding heading, or empty when the item precedes every heading.
    pub section: String,
    /// 1-based line number, so the report can point at the item.
    pub line: usize,
}

/// Progress for one section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SectionProgress {
    pub section: String,
    pub done: usize,
    pub total: usize,
}

impl SectionProgress {
    pub fn complete(&self) -> bool {
        self.total > 0 && self.done == self.total
    }
}

/// The whole checklist.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Checklist {
    pub steps: Vec<Step>,
}

impl Checklist {
    /// Parse the checklist out of a Markdown document.
    ///
    /// Fenced code blocks are skipped: a `- [ ]` inside a shell example is
    /// documentation *about* a checklist, not a step.
    pub fn parse(markdown: &str) -> Self {
        let mut steps = Vec::new();
        let mut section = String::new();
        let mut in_fence = false;

        for (index, raw) in markdown.lines().enumerate() {
            let line = raw.trim_end();
            let trimmed = line.trim_start();

            if trimmed.starts_with("```") {
                in_fence = !in_fence;
                continue;
            }
            if in_fence {
                continue;
            }

            if let Some(heading) = heading_text(trimmed) {
                section = heading.to_string();
                continue;
            }

            if let Some((done, text)) = task_item(trimmed) {
                steps.push(Step {
                    text,
                    done,
                    section: section.clone(),
                    line: index + 1,
                });
            }
        }

        Self { steps }
    }

    pub fn done(&self) -> usize {
        self.steps.iter().filter(|s| s.done).count()
    }

    pub fn total(&self) -> usize {
        self.steps.len()
    }

    /// Whether every step is ticked. An empty checklist is *not* complete: there
    /// is nothing to have finished.
    pub fn complete(&self) -> bool {
        !self.steps.is_empty() && self.done() == self.total()
    }

    /// Completion as a percentage, rounded down so 99% never reads as 100%.
    pub fn percent(&self) -> u8 {
        if self.steps.is_empty() {
            return 0;
        }
        // `total` cannot exceed `usize::MAX / 100` for any document that fits in
        // memory, so the multiplication cannot overflow in practice; the cast is
        // still bounded to the 0..=100 range by the division that follows.
        ((self.done() * 100) / self.total()).min(100) as u8
    }

    /// Progress per section, in document order.
    pub fn sections(&self) -> Vec<SectionProgress> {
        let mut out: Vec<SectionProgress> = Vec::new();
        for step in &self.steps {
            match out.iter_mut().find(|s| s.section == step.section) {
                Some(progress) => {
                    progress.total += 1;
                    if step.done {
                        progress.done += 1;
                    }
                }
                None => out.push(SectionProgress {
                    section: step.section.clone(),
                    done: usize::from(step.done),
                    total: 1,
                }),
            }
        }
        out
    }

    /// The next step a contributor has not ticked, if any.
    pub fn next_step(&self) -> Option<&Step> {
        self.steps.iter().find(|s| !s.done)
    }

    pub fn render(&self) -> String {
        let mut out = String::new();
        if self.steps.is_empty() {
            let _ = writeln!(
                out,
                "no checklist items found — expected `- [ ]` items in {CHECKLIST_PATH}"
            );
            return out;
        }

        let _ = writeln!(
            out,
            "onboarding: {}/{} steps complete ({}%)",
            self.done(),
            self.total(),
            self.percent()
        );

        for section in self.sections() {
            let mark = if section.complete() { "x" } else { " " };
            let _ = writeln!(
                out,
                "  [{mark}] {} ({}/{})",
                if section.section.is_empty() {
                    "(untitled)"
                } else {
                    &section.section
                },
                section.done,
                section.total
            );
        }

        if let Some(step) = self.next_step() {
            let _ = writeln!(out, "next: {} (line {})", step.text, step.line);
        } else {
            let _ = writeln!(out, "next: nothing — the checklist is complete");
        }

        out
    }

    pub fn to_json(&self) -> String {
        serde_json::json!({
            "done": self.done(),
            "total": self.total(),
            "percent": self.percent(),
            "complete": self.complete(),
            "sections": self.sections(),
            "next": self.next_step(),
            "steps": self.steps,
        })
        .to_string()
    }
}

/// Return the text of an ATX heading (`#`, `##`, `###`, ...).
fn heading_text(trimmed: &str) -> Option<&str> {
    let hashes = trimmed.chars().take_while(|c| *c == '#').count();
    if hashes == 0 || hashes > 6 {
        return None;
    }
    let rest = trimmed[hashes..].strip_prefix(' ')?;
    let text = rest.trim_end_matches('#').trim();
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

/// Return `(done, text)` for a Markdown task item.
fn task_item(trimmed: &str) -> Option<(bool, String)> {
    let rest = trimmed
        .strip_prefix("- [")
        .or_else(|| trimmed.strip_prefix("* ["))
        .or_else(|| trimmed.strip_prefix("+ ["))?;
    let mut chars = rest.chars();
    let mark = chars.next()?;
    let done = match mark {
        ' ' => false,
        'x' | 'X' => true,
        _ => return None,
    };
    let after = chars.as_str().strip_prefix(']')?;
    // `- [x]foo` is not a task item; Markdown requires the space.
    let text = after.strip_prefix(' ')?.trim();
    if text.is_empty() {
        None
    } else {
        Some((done, text.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOC: &str = r"
# Onboarding

Intro prose with a [link](https://example.com).

## Setup

- [x] Install the toolchain
- [x] Add the wasm target
- [ ] Install cargo tools

## Workflow

- [ ] Create a branch
- [ ] Run the tests

```bash
# a fenced example must not count
- [ ] this is not a step
```
";

    #[test]
    fn every_task_item_is_found() {
        let checklist = Checklist::parse(DOC);
        assert_eq!(checklist.total(), 5);
        assert_eq!(checklist.done(), 2);
    }

    #[test]
    fn a_fenced_example_is_not_a_step() {
        let checklist = Checklist::parse(DOC);
        assert!(
            !checklist
                .steps
                .iter()
                .any(|s| s.text.contains("not a step")),
            "a checklist inside a code fence is documentation, not a step"
        );
    }

    #[test]
    fn steps_are_grouped_by_their_heading() {
        let checklist = Checklist::parse(DOC);
        let sections = checklist.sections();
        assert_eq!(sections.len(), 2);
        assert_eq!(sections[0].section, "Setup");
        assert_eq!(sections[0].done, 2);
        assert_eq!(sections[0].total, 3);
        assert_eq!(sections[1].section, "Workflow");
        assert_eq!(sections[1].done, 0);
        assert_eq!(sections[1].total, 2);
    }

    #[test]
    fn the_percentage_rounds_down() {
        // 2/3 is 66.6%, and 67 would overstate it.
        let checklist = Checklist::parse(DOC);
        assert_eq!(checklist.percent(), 40);
        let two_of_three = Checklist::parse("- [x] a\n- [x] b\n- [ ] c\n");
        assert_eq!(two_of_three.percent(), 66);
    }

    #[test]
    fn a_complete_checklist_is_complete() {
        let checklist = Checklist::parse("- [x] a\n- [x] b\n");
        assert!(checklist.complete());
        assert_eq!(checklist.percent(), 100);
        assert!(checklist.next_step().is_none());
    }

    #[test]
    fn an_empty_document_is_not_complete() {
        let checklist = Checklist::parse("# Nothing here\n\nJust prose.\n");
        assert!(!checklist.complete(), "no steps cannot mean finished");
        assert_eq!(checklist.percent(), 0);
        assert_eq!(checklist.total(), 0);
    }

    #[test]
    fn the_next_step_is_the_first_unticked_one() {
        let checklist = Checklist::parse(DOC);
        let next = checklist.next_step().unwrap();
        assert_eq!(next.text, "Install cargo tools");
        assert_eq!(next.line, 10);
    }

    #[test]
    fn a_section_is_complete_only_when_all_its_steps_are() {
        let checklist = Checklist::parse(DOC);
        let sections = checklist.sections();
        assert!(!sections[0].complete());
        assert!(!sections[1].complete());

        let partial = Checklist::parse("## A\n- [x] one\n\n## B\n- [x] two\n");
        let sections = partial.sections();
        assert!(sections[0].complete());
        assert!(sections[1].complete());
    }

    #[test]
    fn an_item_without_a_space_is_not_a_task() {
        assert!(task_item("- [x]nospace").is_none());
        assert!(task_item("- [ ]").is_none());
        assert_eq!(task_item("- [X] upper").unwrap(), (true, "upper".into()));
        assert_eq!(task_item("* [ ] star").unwrap(), (false, "star".into()));
    }

    #[test]
    fn headings_are_recognised_at_every_level() {
        assert_eq!(heading_text("# One"), Some("One"));
        assert_eq!(heading_text("### Three"), Some("Three"));
        assert_eq!(heading_text("#nospace"), None);
        assert_eq!(heading_text("####### seven"), None);
        assert_eq!(heading_text("#"), None);
    }

    #[test]
    fn the_render_names_the_next_step_and_every_section() {
        let checklist = Checklist::parse(DOC);
        let rendered = checklist.render();
        assert!(rendered.contains("2/5 steps complete (40%)"));
        assert!(rendered.contains("Setup (2/3)"));
        assert!(rendered.contains("next: Install cargo tools (line 10)"));
    }

    #[test]
    fn the_json_report_carries_the_counts_and_sections() {
        let checklist = Checklist::parse(DOC);
        let json: serde_json::Value = serde_json::from_str(&checklist.to_json()).unwrap();
        assert_eq!(json["done"], 2);
        assert_eq!(json["total"], 5);
        assert_eq!(json["complete"], false);
        assert_eq!(json["sections"].as_array().unwrap().len(), 2);
        assert_eq!(json["next"]["text"], "Install cargo tools");
    }

    #[test]
    fn the_real_onboarding_document_parses() {
        // The conformance test: the document this module exists for must yield
        // steps, or the CLI would report "no checklist" on a healthy repo.
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/CONTRIBUTING_ONBOARDING.md");
        let markdown = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
        let checklist = Checklist::parse(&markdown);
        assert!(
            checklist.total() > 0,
            "{} has no `- [ ]` items; the parser or the document changed shape",
            path.display()
        );
    }
}
