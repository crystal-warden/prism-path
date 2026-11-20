# Can a PreToolUse hook rewrite a tool call?

Checked 2026-11-20 against https://code.claude.com/docs/en/hooks (section "PreToolUse decision control") and the Claude Code installed on the build host, version 2.1.326.

## Finding

Yes. A `PreToolUse` hook can return a changed tool input. The field is `updatedInput` inside `hookSpecificOutput`, beside `permissionDecision`.

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "allow",
    "permissionDecisionReason": "My reason here",
    "updatedInput": {
      "field_to_modify": "new value"
    },
    "additionalContext": "Current environment: production. Proceed with caution."
  }
}
```

For a Bash call the input object is `{"command": "...", ...}`, so the rewrite is `"updatedInput": {"command": "<new command>"}`.

What the documentation says about `updatedInput`:

- It replaces the entire input object. Unchanged fields (`description`, `timeout` and so on) must be repeated.
- Permission rules and a Bash command's auto-background eligibility are evaluated against the input the hook returns, not the one the model sent.
- With `"allow"` it auto-approves the rewritten call. With `"ask"` it shows the rewritten input to the person. With `"defer"` it is ignored.
- With no `permissionDecision` in auto mode, Claude Code can deny the changed call ("a hook changed this call's input after auto mode reviewed it"). So the hook should always return `allow` with the rewrite.
- Deny and ask rules in settings still apply whatever the hook returns. Between several hooks the order is deny, defer, ask, allow.
- The page gives no minimum version for `updatedInput` on Bash. It only gives v2.1.314 for hooks matching Monitor, where a Bash matcher's `allow` and `updatedInput` have no effect. The installed 2.1.326 is past that.

I did not run a live Claude Code session to see a rewritten command execute. This is from the documentation. WP3 should include one real session check.

## Consequence for the plan

The WP3 design holds. For an allowed `run_command` the hook returns `permissionDecision: "allow"` plus `updatedInput.command` set to the call run under `sandbox_exec` (the full original input carried over). `hook_answer` in `prismpath/agent/claude_code.py` needs a field for the rewrite. The MCP-proxy fallback in section 4 of the plan (deny Bash in the hook, run the command through a PrismPath MCP tool) is not needed and is not built.
