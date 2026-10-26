# Workspace Cleanup Rule

When creating temporary Python scripts, intermediate data files, or one-off tools for data extraction or codebase modification, you MUST place them inside the `.ai_workspace/` directory, rather than littering the project root.

This ensures the user's project structure remains clean and prevents these temporary files from accidentally being tracked in version control (as `.ai_workspace/` is added to `.gitignore`).
