---
trigger: always_on
description: Prohibit using browser automation or opening browsers for code debugging to avoid excessive token consumption. Instruct the user directly instead.
---

# No Browser Debugging / Automation

## Context
Automated browser testing and debugging (such as spawning browser subagents, capturing multiple browser screenshots, or interacting with web pages programmatically) consumes excessive token quotas and adds unnecessary overhead.

## Rules
- **NEVER** launch a browser subagent (`browser_subagent`), automated browser session, or headless browser to test or debug code.
- **NEVER** open browser windows to inspect DOM elements, click buttons, or check console logs.
- Instead, perform static analysis and code inspection directly, and **provide clear step-by-step instructions** to the USER explaining:
  1. What URL to open or refresh in their browser.
  2. What buttons, inputs, or features to click or test.
  3. What to check in the browser Developer Tools (Console / Network tab) if an issue occurs.
- This prevents token waste ("boncos token") and keeps the development workflow fast, clean, and collaborative.
