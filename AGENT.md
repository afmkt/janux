# AGENT.md — Pi / coding agents

This file is kept for agents that specifically look for `AGENT.md`.

**For deploy and operations**, follow **[AGENTS.md](AGENTS.md)** and load **`janux-agent/SKILL.md`**.

## Code formatting & whitespace (Rust)

- This project uses standard **`rustfmt`** for all Rust code formatting.
- **Mandatory rule:** Whenever you modify or create any `.rs` file using the `edit` or `write` tool, you **must immediately run `cargo fmt`** using the `bash` tool to clean up spacing and indentation.
- If an `edit` tool call fails due to an exact-match whitespace or line mismatch, do not guess blindly. Read the file again to get the exact lines, then retry.
