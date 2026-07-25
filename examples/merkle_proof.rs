// Example: Merkle tree construction and proof verification.
//
// Run: cargo run --example merkle_proof

use enprot::merkle::{self, MerkleTree};

fn main() -> enprot::Result<()> {
    // Build a tree from 7 leaves
    let leaves: Vec<Vec<u8>> = (0..7).map(|i| format!("leaf-{}", i).into_bytes()).collect();
    let tree = MerkleTree::from_leaves(&leaves)?;
    let root = tree.root()?;

    println!("Merkle tree with {} leaves", tree.leaf_count());
    println!("Root: {}", root);

    // Generate a proof for leaf 3
    let proof = tree.proof(3)?;
    println!("\nProof for leaf 3:");
    println!("  leaf hash: {}", proof.leaf.to_hex());
    println!("  steps: {}", proof.steps.len());

    // Verify the proof
    let ok = merkle::verify_proof(&root, &proof)?;
    println!("  verification: {}", if ok { "VALID" } else { "INVALID" });

    // Tamper: swap the leaf hash
    let mut tampered = proof.clone();
    tampered.leaf = merkle::hash_leaf(b"wrong")?;
    let ok_tampered = merkle::verify_proof(&root, &tampered)?;
    println!("\nTampered proof: {}", if ok_tampered { "VALID" } else { "INVALID" });

    Ok(())
}
