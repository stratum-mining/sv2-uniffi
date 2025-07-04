"""
Stratum v2 Python Bindings

This package provides Python bindings for the Stratum v2 protocol implementation.
"""

# Re-export the main components for easier importing
from sv2 import (
    Sv2CodecState,
    Sv2Encoder,
    Sv2Decoder,
    Sv2Message,
    SetupConnection,
    Sv2CodecError,
    Sv2MessagesError
)

__all__ = [
    'Sv2CodecState',
    'Sv2Encoder',
    'Sv2Decoder',
    'Sv2Message',
    'SetupConnection',
    'Sv2CodecError',
    'Sv2MessagesError'
]

__version__ = '0.1.0' 