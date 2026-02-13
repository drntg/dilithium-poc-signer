# dilithium-poc-signer
This repository contains a small experimental C++ program that demonstrates how to embed a post-quantum signature (using liboqs) into a Bitcoin SegWit witness stack and construct a raw transaction hex. It is an educational prototype.

## Specifics
Generates a post-quantum keypair using liboqs (algorithm: ML-DSA-44 / OQS level 2).

Builds a simplified witness script that bypasses ECDSA and expects PQC data (uses a custom opcode 0xbb for the PQC check).

Signs a dummy 32-byte sighash (0xAA repeated) with the PQC secret key.

Chunks public key and signature to fit into the witness stack items.

Serializes a hardcoded 1-in/1-out SegWit transaction template and prints the raw transaction hex
