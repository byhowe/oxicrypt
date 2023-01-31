import warnings

try:
    from oxicrypt.oxicrypt import version
except ImportError:

    def version() -> str:
        return ""

    # useful for documentation
    warnings.warn("oxicrypt ffi binary is missing")

from oxicrypt.oxicrypt import core

__all__ = [
    "__version__",
    "core",
]
__version__ = version()
