import sys


MIGRATION_MESSAGE = "Shiproom is historical and unavailable. Use the read-only `provan` CLI."


def legacy_cli_main() -> int:
    print(MIGRATION_MESSAGE, file=sys.stderr)
    return 2
