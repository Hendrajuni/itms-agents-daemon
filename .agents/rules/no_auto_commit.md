---
trigger: always_on
description: Strictly prohibit automatic git commit and git push unless explicitly requested by the user.
---

# No Auto Commit to Git

## Context
The user prefers to review code changes locally before committing them to the repository. Automatic commits by agents have previously caused issues or bypassed the user's manual review process.

## Rules
- **NEVER** run `git commit` or `git push` automatically after making code changes.
- Always pause and wait for the user to explicitly ask you to commit, or let the user handle the git operations themselves.
- You may suggest git commit messages to the user (e.g., "Here is a suggested commit message..."), but **do not execute the command** unless specifically instructed to do so in the current prompt.
