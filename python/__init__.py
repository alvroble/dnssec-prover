"""
Python DNSSEC Prover Library

A Python implementation of DNSSEC validation based on RFC 9102 proofs.
This library provides offline DNSSEC validation capabilities.
"""

from .validation import (
    verify_rr_stream,
    verify_rrsig,
    verify_rr_set,
    root_hints,
    ValidationError,
    VerifiedRRStream,
    resolve_time,
    MAX_PROOF_STEPS
)

from .rr import (
    Name,
    Record,
    A,
    AAAA,
    NS,
    Txt,
    TLSA,
    CName,
    DName,
    DnsKey,
    DS,
    RRSig,
    NSec,
    NSec3,
    NSecTypeMask,
    parse_rr_stream,
    write_rr,
    RECORD_TYPES
)

from .ser import (
    SerializationError,
    read_u8,
    read_u16,
    read_u32,
    read_wire_packet_name,
    write_name,
    name_len
)

from .base32 import encode, decode
from .crypto import Hasher, HashResult, validate_rsa

__version__ = "0.1.0"

__all__ = [
    # Validation
    "verify_rr_stream",
    "verify_rrsig", 
    "verify_rr_set",
    "root_hints",
    "ValidationError",
    "VerifiedRRStream",
    "resolve_time",
    "MAX_PROOF_STEPS",
    
    # Resource Records
    "Name",
    "Record",
    "A",
    "AAAA", 
    "NS",
    "Txt",
    "TLSA",
    "CName",
    "DName",
    "DnsKey",
    "DS",
    "RRSig",
    "NSec",
    "NSec3",
    "NSecTypeMask",
    "parse_rr_stream",
    "write_rr",
    "RECORD_TYPES",
    
    # Serialization
    "SerializationError",
    "read_u8",
    "read_u16", 
    "read_u32",
    "read_wire_packet_name",
    "write_name",
    "name_len",
    
    # Base32
    "encode",
    "decode",
    
    # Crypto
    "Hasher",
    "HashResult",
    "validate_rsa",
] 