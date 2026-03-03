"""
app/core/merkle.py
------------------
Cryptographic Merkle Tree Implementation for chunk-level integrity sealing.
Used by the secure WebSocket ingestion pipeline to produce a tamper-evident
root hash from ordered chunk hashes.
"""

import hashlib
import math
from typing import List, Optional
from app.core.logging import logger


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _sha256_pair(left: str, right: str) -> str:
    """Hash two hex-encoded sibling nodes into a parent node."""
    combined = bytes.fromhex(left) + bytes.fromhex(right)
    return hashlib.sha256(combined).hexdigest()


def _normalize_layer(layer: List[str]) -> List[str]:
    """
    Ensure an even number of nodes per layer by duplicating the last node
    when the layer length is odd (standard Bitcoin-style Merkle padding).
    """
    if len(layer) % 2 != 0:
        layer = layer + [layer[-1]]
    return layer


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_merkle_root(chunk_hashes: List[str]) -> str:
    """
    Build a Merkle root from an ordered list of SHA-256 chunk hashes.

    Args:
        chunk_hashes: Ordered list of hex-encoded SHA-256 digests, one per
                      received chunk. Must not be empty.

    Returns:
        Hex-encoded Merkle root hash.

    Raises:
        ValueError: If chunk_hashes is empty.
    """
    if not chunk_hashes:
        raise ValueError("Cannot build Merkle root from an empty chunk list.")

    # Leaf nodes — each chunk hash is treated as a leaf
    current_layer: List[str] = list(chunk_hashes)

    logger.debug(
        f"[Merkle] Building tree from {len(current_layer)} leaf nodes."
    )

    while len(current_layer) > 1:
        current_layer = _normalize_layer(current_layer)
        next_layer: List[str] = []
        for i in range(0, len(current_layer), 2):
            parent = _sha256_pair(current_layer[i], current_layer[i + 1])
            next_layer.append(parent)
        current_layer = next_layer

    root = current_layer[0]
    logger.debug(f"[Merkle] Root hash computed: {root}")
    return root


def build_merkle_proof(chunk_hashes: List[str], index: int) -> List[dict]:
    """
    Generate a Merkle proof (audit path) for a single leaf at *index*.

    Returns a list of {"sibling": <hash>, "direction": "left"|"right"}
    entries that can be used by an external verifier to reconstruct the root
    without possessing all chunks.

    Args:
        chunk_hashes: Full ordered list of chunk hashes.
        index: Zero-based index of the leaf to prove.

    Returns:
        List of proof steps.
    """
    if not chunk_hashes:
        raise ValueError("Chunk hash list is empty.")
    if index < 0 or index >= len(chunk_hashes):
        raise ValueError(f"Index {index} out of range [0, {len(chunk_hashes)}).")

    current_layer = list(chunk_hashes)
    proof: List[dict] = []
    current_index = index

    while len(current_layer) > 1:
        current_layer = _normalize_layer(current_layer)
        if current_index % 2 == 0:
            sibling_index = current_index + 1
            direction = "right"
        else:
            sibling_index = current_index - 1
            direction = "left"

        proof.append({
            "sibling": current_layer[sibling_index],
            "direction": direction,
        })

        # Build next layer
        next_layer: List[str] = []
        for i in range(0, len(current_layer), 2):
            next_layer.append(_sha256_pair(current_layer[i], current_layer[i + 1]))

        current_layer = next_layer
        current_index //= 2

    return proof


def verify_merkle_proof(
    leaf_hash: str,
    proof: List[dict],
    expected_root: str,
) -> bool:
    """
    Verify a Merkle proof for a single leaf.

    Args:
        leaf_hash: Hex-encoded SHA-256 hash of the leaf.
        proof: List of proof steps returned by build_merkle_proof().
        expected_root: Hex-encoded Merkle root to verify against.

    Returns:
        True if the proof is valid, False otherwise.
    """
    current = leaf_hash
    for step in proof:
        sibling = step["sibling"]
        direction = step["direction"]
        if direction == "right":
            current = _sha256_pair(current, sibling)
        else:
            current = _sha256_pair(sibling, current)

    valid = current == expected_root
    if not valid:
        logger.warning(
            f"[Merkle] Proof verification failed. "
            f"Computed root={current}, expected={expected_root}"
        )
    return valid


def verify_merkle_integrity(chunk_hashes: List[str], expected_root: str) -> bool:
    """
    Full re-computation integrity check: rebuild the Merkle root from all
    chunk hashes and compare against a stored expected root.

    Args:
        chunk_hashes: Ordered chunk hash list.
        expected_root: Previously stored Merkle root.

    Returns:
        True if roots match, False otherwise.
    """
    try:
        computed_root = build_merkle_root(chunk_hashes)
        match = computed_root == expected_root
        if not match:
            logger.error(
                f"[Merkle] Integrity mismatch! "
                f"Computed={computed_root}, Stored={expected_root}"
            )
        else:
            logger.info("[Merkle] Integrity check passed.")
        return match
    except Exception as exc:
        logger.error(f"[Merkle] Integrity check exception: {exc}")
        return False
