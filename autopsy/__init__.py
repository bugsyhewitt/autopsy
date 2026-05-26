"""autopsy — angr-backed Python-native whole-program binary analysis.

CWE-aligned vulnerability detection over ELF binaries. This top-level module is
deliberately free of any ``angr`` import so that importing ``autopsy`` (for the
CLI, report formatting, or scope logic) is cheap and does not pull in the
multi-hundred-megabyte angr dependency. angr is imported lazily, only inside
``autopsy.engine`` when an actual analysis runs.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
