class ProvanError(RuntimeError):
    """Typed, user-safe Provan failure."""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


CUSTOMER_REPOSITORY_MUTATION_FORBIDDEN = "CUSTOMER_REPOSITORY_MUTATION_FORBIDDEN"
QUALIFIED_SANDBOX_REQUIRED = "QUALIFIED_SANDBOX_REQUIRED"
