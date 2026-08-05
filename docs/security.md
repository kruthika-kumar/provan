# Security

Repository URLs containing credentials and unsafe Git protocols are rejected. Full commit object IDs are required; mutable refs are rejected. Git runs with isolated HOME/configuration, prompts disabled, hooks disabled, object replacement disabled, LFS smudging disabled, and no repository code execution. Object-store alternates and symlinks are rejected. Object count, repository bytes, tree entries, tree output, and command duration are bounded and fail closed. Treat receipts as potentially sensitive and review them before sharing.
