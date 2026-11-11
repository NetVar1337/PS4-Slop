import re


class WorkbenchError(Exception):
    pass


def require_integer(value, name, minimum, maximum):
    if type(value) is not int or not minimum <= value <= maximum:
        raise WorkbenchError(f"{name} must be an integer in [{minimum}, {maximum}]")
    return value


def require_hash(value, name="sha256"):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise WorkbenchError(f"{name} must be a lowercase SHA-256 digest")
    return value


def parse_address(value):
    """Parse a broker address string ("0x..." or decimal) into a uint64."""
    if not isinstance(value, str):
        raise WorkbenchError("Address must be a string")
    try:
        parsed = int(value, 16 if value.startswith("0x") else 10)
    except ValueError as error:
        raise WorkbenchError("Invalid address: " + value[:32]) from error
    if not 0 <= parsed <= 0xFFFFFFFFFFFFFFFF:
        raise WorkbenchError("Address exceeds uint64")
    return parsed


def numeric(value):
    """Debugger map fields arrive as integers or "0x..." strings."""
    return int(value, 0) if isinstance(value, str) else value
