"""
backend/blockchain/merkle.py
-----------------------------
Merkle Tree implementation for blockchain message integrity verification.
"""

import hashlib
from typing import List, Optional


def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


class MerkleTree:
    """
    Binary Merkle Tree built from a list of data items.
    Each leaf = SHA-256 of the item. Parent = SHA-256(left+right).
    """

    def __init__(self, data_list: List[str]):
        if not data_list:
            self.leaves = []
            self._tree  = []
            return

        self.leaves = [_sha256(str(d)) for d in data_list]
        self._tree  = self._build(self.leaves)

    # ------------------------------------------------------------------
    def _build(self, leaves: List[str]) -> List[List[str]]:
        tree = [leaves[:]]
        current = leaves[:]

        while len(current) > 1:
            next_level = []
            for i in range(0, len(current), 2):
                left  = current[i]
                right = current[i + 1] if i + 1 < len(current) else left  # duplicate last
                next_level.append(_sha256(left + right))
            tree.append(next_level)
            current = next_level

        return tree

    # ------------------------------------------------------------------
    @property
    def root(self) -> str:
        """Return the Merkle root hash, or 64 zeros if tree is empty."""
        if not self._tree:
            return "0" * 64
        return self._tree[-1][0]

    # ------------------------------------------------------------------
    def get_proof(self, index: int) -> List[dict]:
        """
        Return the Merkle proof path for the leaf at `index`.
        Each step is {'hash': str, 'direction': 'left'|'right'}.
        """
        proof = []
        current_index = index

        for level in self._tree[:-1]:           # all levels except root
            if current_index % 2 == 0:          # left child → sibling is right
                sibling_index = current_index + 1
                direction     = "right"
            else:                               # right child → sibling is left
                sibling_index = current_index - 1
                direction     = "left"

            if sibling_index < len(level):
                proof.append({"hash": level[sibling_index], "direction": direction})
            current_index //= 2

        return proof

    # ------------------------------------------------------------------
    @staticmethod
    def verify_proof(leaf_data: str, proof: List[dict], expected_root: str) -> bool:
        """
        Verify that leaf_data belongs to the tree with the given root,
        using the provided proof path.
        """
        current = _sha256(str(leaf_data))

        for step in proof:
            if step["direction"] == "right":
                current = _sha256(current + step["hash"])
            else:
                current = _sha256(step["hash"] + current)

        return current == expected_root


# ------------------------------------------------------------------
# Convenience helpers for blockchain tables
# ------------------------------------------------------------------

def compute_chain_merkle_root(blocks: list) -> str:
    """
    Given a list of blockchain row dicts, build a Merkle tree
    from each block's stored hash and return the root.
    """
    if not blocks:
        return "0" * 64
    hashes = [b["hash"] for b in blocks]
    return MerkleTree(hashes).root


def get_block_proof(blocks: list, block_index: int) -> dict:
    """
    Return the Merkle proof for the block at `block_index` in the chain.
    """
    if not blocks or block_index >= len(blocks):
        return {"error": "Invalid block index"}

    hashes = [b["hash"] for b in blocks]
    tree   = MerkleTree(hashes)
    proof  = tree.get_proof(block_index)
    leaf   = hashes[block_index]

    return {
        "block_index":    block_index,
        "leaf_hash":      leaf,
        "merkle_root":    tree.root,
        "proof":          proof,
    }
