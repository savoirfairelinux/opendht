"""
Python package facade for OpenDHT.

This package re-exports the Cython-built core bindings from ``opendht._core``
to preserve the public API (e.g., ``opendht.DhtRunner``), and also exposes a
pure-Python asyncio-friendly wrapper under ``opendht.aio``.
"""

from ._core import *  # re-export core Cython bindings

__all__ = [name for name in dir() if not name.startswith("_")]
