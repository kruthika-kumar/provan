from .errors import CUSTOMER_REPOSITORY_MUTATION_FORBIDDEN, ProvanError


MUTATION_OPERATIONS = frozenset({
    "write_target", "create_branch", "create_worktree", "create_commit",
    "push", "open_pr", "merge", "deploy", "remediate", "apply_patch",
})


def require_read_only(operation: str) -> None:
    if operation in MUTATION_OPERATIONS:
        raise ProvanError(
            CUSTOMER_REPOSITORY_MUTATION_FORBIDDEN,
            f"operation {operation!r} is outside Provan Community authority",
        )
