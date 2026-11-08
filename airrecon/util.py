"""Small text helpers shared by the other modules."""


def safe_text(value, fallback='—'):
    if value is None:
        return fallback
    # Do not interpret control characters received in names or saved files.
    return ''.join(char if char.isprintable() else repr(char)[1:-1] for char in str(value))
