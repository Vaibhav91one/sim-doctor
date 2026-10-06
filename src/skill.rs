//! The agent skill: how a coding agent runs `sim-doctor scan --json` and reads the envelope.
//!
//! `sim-doctor install` writes it where an agent looks for guidance. This module only builds
//! text and writes files under a root directory; it never touches a reader, a card or stdout,
//! so it stays a leaf of the crate.

use std::io;
use std::path::{Path, PathBuf};

/// The module's name, as `sim-doctor modules` reports it.
pub const NAME: &str = "skill";

/// The skill body shared by every target.
const BODY: &str = include_str!("skill_body.md");

/// Opens the block this tool owns inside a shared file such as `AGENTS.md`.
const BLOCK_START: &str = "<!-- sim-doctor:start -->";
/// Closes it. Everything outside the pair is the user's and is never touched.
const BLOCK_END: &str = "<!-- sim-doctor:end -->";

/// An agent we can write guidance for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Agent {
    /// Claude Code: `.claude/skills/sim-doctor/SKILL.md`.
    Claude,
    /// Cursor: `.cursor/rules/sim-doctor.mdc`.
    Cursor,
    /// Codex: reads `AGENTS.md`.
    Codex,
    /// opencode: reads `AGENTS.md`.
    Opencode,
}

impl Agent {
    /// Every agent, in the order `install` writes them.
    pub const ALL: [Agent; 4] = [Agent::Claude, Agent::Cursor, Agent::Codex, Agent::Opencode];

    /// The spellings `--agent` accepts.
    pub const NAMES: [&'static str; 4] = ["claude", "cursor", "codex", "opencode"];

    /// Parses a `--agent` value.
    pub fn parse(name: &str) -> Option<Agent> {
        match name {
            "claude" => Some(Agent::Claude),
            "cursor" => Some(Agent::Cursor),
            "codex" => Some(Agent::Codex),
            "opencode" => Some(Agent::Opencode),
            _ => None,
        }
    }

    /// The file this agent reads, relative to the project root.
    pub fn target(self) -> Target {
        match self {
            Agent::Claude => Target::ClaudeSkill,
            Agent::Cursor => Target::CursorRule,
            Agent::Codex | Agent::Opencode => Target::AgentsBlock,
        }
    }
}

/// One file `install` writes. Codex and opencode share one, so a target is written once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// `.claude/skills/sim-doctor/SKILL.md`, replaced whole.
    ClaudeSkill,
    /// `.cursor/rules/sim-doctor.mdc`, replaced whole.
    CursorRule,
    /// A marked block inside `AGENTS.md`, replaced in place, the rest preserved.
    AgentsBlock,
}

impl Target {
    /// The path under the project root.
    pub fn path(self) -> &'static str {
        match self {
            Target::ClaudeSkill => ".claude/skills/sim-doctor/SKILL.md",
            Target::CursorRule => ".cursor/rules/sim-doctor.mdc",
            Target::AgentsBlock => "AGENTS.md",
        }
    }

    /// What this tool owns in that file: the whole file, or just the marked block.
    pub fn content(self) -> String {
        match self {
            Target::ClaudeSkill => format!(
                "---\nname: sim-doctor\ndescription: Scan a SIM/UICC card over PC/SC with `sim-doctor scan --json` and read the result envelope. Use when asked to examine, audit or score a SIM card.\n---\n\n{BODY}"
            ),
            Target::CursorRule => format!(
                "---\ndescription: How to run sim-doctor and read its JSON envelope\nalwaysApply: false\n---\n\n{BODY}"
            ),
            Target::AgentsBlock => format!("{BLOCK_START}\n{}\n{BLOCK_END}\n", BODY.trim_end()),
        }
    }
}

/// The distinct targets for these agents, in order. `None` means every agent.
pub fn targets(agents: Option<Agent>) -> Vec<Target> {
    let mut out = Vec::new();
    for agent in agents.map_or(Agent::ALL.to_vec(), |a| vec![a]) {
        if !out.contains(&agent.target()) {
            out.push(agent.target());
        }
    }
    out
}

/// Puts `block` into `existing`: replaces a previous block in place, else appends.
///
/// Text outside the markers is returned byte for byte, so a hand-written AGENTS.md survives.
pub fn upsert_block(existing: &str, block: &str) -> String {
    if let (Some(start), Some(end)) = (existing.find(BLOCK_START), existing.find(BLOCK_END)) {
        if start < end {
            let after = end + BLOCK_END.len();
            let tail = existing[after..]
                .strip_prefix('\n')
                .unwrap_or(&existing[after..]);
            return format!("{}{}{}", &existing[..start], block, tail);
        }
    }
    if existing.is_empty() {
        return block.to_owned();
    }
    let sep = if existing.ends_with("\n\n") {
        ""
    } else if existing.ends_with('\n') {
        "\n"
    } else {
        "\n\n"
    };
    format!("{existing}{sep}{block}")
}

/// Writes one target under `root` and returns the path written.
pub fn install(root: &Path, target: Target) -> io::Result<PathBuf> {
    let path = root.join(target.path());
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let text = match target {
        Target::AgentsBlock => {
            let existing = match std::fs::read_to_string(&path) {
                Ok(text) => text,
                Err(e) if e.kind() == io::ErrorKind::NotFound => String::new(),
                Err(e) => return Err(e),
            };
            upsert_block(&existing, &target.content())
        }
        _ => target.content(),
    };
    std::fs::write(&path, text)?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("sim-doctor-skill-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn codex_and_opencode_share_one_agents_target() {
        assert_eq!(targets(None).len(), 3);
        assert_eq!(targets(Some(Agent::Codex)), vec![Target::AgentsBlock]);
    }

    #[test]
    fn an_existing_agents_md_keeps_its_text_and_gains_one_block_even_after_two_installs() {
        let root = scratch("agents");
        std::fs::write(root.join("AGENTS.md"), "# Mine\n\nhand written\n").unwrap();
        install(&root, Target::AgentsBlock).unwrap();
        install(&root, Target::AgentsBlock).unwrap();
        let text = std::fs::read_to_string(root.join("AGENTS.md")).unwrap();
        assert!(text.starts_with("# Mine\n\nhand written\n"));
        assert_eq!(text.matches(BLOCK_START).count(), 1);
        assert_eq!(text.matches(BLOCK_END).count(), 1);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_stale_block_is_replaced_in_place_and_the_text_after_it_survives() {
        let old = format!("top\n{BLOCK_START}\nold\n{BLOCK_END}\nbottom\n");
        let new = upsert_block(&old, &Target::AgentsBlock.content());
        assert!(new.starts_with("top\n") && new.ends_with("bottom\n"));
        assert!(!new.contains("\nold\n") && new.contains("scan --json"));
    }

    #[test]
    fn claude_and_cursor_files_are_written_with_frontmatter() {
        let root = scratch("files");
        for t in [Target::ClaudeSkill, Target::CursorRule] {
            let p = install(&root, t).unwrap();
            assert!(std::fs::read_to_string(p).unwrap().starts_with("---\n"));
        }
        std::fs::remove_dir_all(root).unwrap();
    }
}
