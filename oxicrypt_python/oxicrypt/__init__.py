import warnings

try:
    from oxicrypt.oxicrypt import version
except ImportError:

    def version() -> str:
        return ""

    # useful for documentation
    warnings.warn("oxicrypt ffi binary is missing")

__all__ = [
    "__version__",
]
__version__ = version()
