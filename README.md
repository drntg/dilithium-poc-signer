<<<<<<< Updated upstream
# dilithium-poc-signer
This repository contains a small experimental C++ program that demonstrates how to embed a post-quantum signature (using liboqs) into a Bitcoin SegWit witness stack and construct a raw transaction hex. It is an educational prototype.

## Specifics
Generates a post-quantum keypair using liboqs (algorithm: ML-DSA-44 / OQS level 2).

Builds a simplified witness script that bypasses ECDSA and expects PQC data (uses a custom opcode 0xbb for the PQC check).

Signs a dummy 32-byte sighash (0xAA repeated) with the PQC secret key.

Chunks public key and signature to fit into the witness stack items.

Serializes a hardcoded 1-in/1-out SegWit transaction template and prints the raw transaction hex
=======
# PQC Bitcoin Signer — PoC

Proof-of-concept tools that construct post-quantum signed Bitcoin transactions in P2WSH format. Both programs use **ML-DSA-44** (formerly Dilithium2, NIST Security Level 2) from liboqs and a custom opcode `OP_DILITHIUM_VERIFY` (0xbb) implemented in a modified bitcoind.

Part of a thesis on integrating post-quantum cryptography into the Bitcoin protocol.

---

## Files

| File | Description |
|---|---|
| `signer.cpp` | Single-key PoC. Generates a key pair, builds a P2WSH address, signs a dummy sighash, and outputs a raw SegWit transaction with an `OP_RETURN` burn output. |
| `AliceBobsigner.cpp` | Transfer simulation. Generates separate key pairs for Alice (sender) and Bob (recipient), produces unique P2WSH addresses for each, and constructs a transaction that spends Alice's UTXO into Bob's P2WSH output. |

---

## Dependencies

| Library | Purpose |
|---|---|
| [liboqs](https://github.com/open-quantum-safe/liboqs) | ML-DSA-44 key generation, signing, verification |
| OpenSSL | SHA-256 for P2WSH scriptPubKey computation |
| Modified bitcoind | Contains `OP_DILITHIUM_VERIFY` (0xbb) in `script/interpreter.cpp` |

## Build

```bash
g++ signer.cpp -o signer \
    -I/usr/local/include \
    -L/usr/local/lib \
    -loqs -lssl -lcrypto

g++ AliceBobsigner.cpp -o AliceBobsigner \
    -I/usr/local/include \
    -L/usr/local/lib \
    -loqs -lssl -lcrypto
```

---

## signer — basic PoC

Generates a key pair, prints the P2WSH scriptPubKey, reads a funding UTXO from stdin, and outputs a raw transaction hex.

```
=== C++ PQC BITCOIN SIGNER ===

SCRIPT PUBKEY:
0020<sha256_of_witness_script>
(Use 'decodescript' in bitcoin-cli to obtain the bcrt1... address)

Enter TXID (hex): <funding_txid>
Enter VOUT: <output_index>

RAW TRANSACTION HEX:
<hex>
```

The output spends into `OP_RETURN <deadbeef>` (burn). The purpose is solely to verify that the modified node accepts a transaction whose witness passes `OP_DILITHIUM_VERIFY`.

---

## AliceBobsigner — PQC-to-PQC transfer

Generates independent key pairs for Alice and Bob, verifies the resulting P2WSH addresses differ, then builds a transaction that moves funds from Alice's UTXO into Bob's spendable P2WSH output.

```
=== PQC-TO-PQC TRANSFER SIMULATION ===

[1] ALICE (SENDER)
    PK hash:      <hex>
    ScriptPubKey: 0020<hex>
--> Fund this address before proceeding.

[2] BOB (RECIPIENT)
    PK hash:      <hex>
    ScriptPubKey: 0020<hex>
--> OK: Addresses differ. PQC identity works.

Enter funding TXID (Alice's UTXO): <txid>
Enter VOUT index: <n>

RAW TRANSACTION HEX (Alice -> Bob):
<hex>
```

### Identity stamp

Each witness script embeds `SHA256(public_key)` followed by `OP_DROP` at the top. This value is pushed and discarded at execution time and has no effect on the stack seen by `OP_DILITHIUM_VERIFY`. Its sole purpose is to make the script hash — and therefore the P2WSH address — unique per public key, so that two users with structurally identical scripts still receive different addresses.

---

## Script and witness layout

### Witness script

```
<SHA256(pk)> OP_DROP  <depth=8> OP_PICK  <num_pk=3> <num_sig=5>  OP_DILITHIUM_VERIFY  OP_VERIFY  OP_TRUE
```

(`signer.cpp` omits the identity stamp; `AliceBobsigner.cpp` includes it.)

**Execution flow:**

| Step | Instruction | Effect |
|---|---|---|
| 1 | `<SHA256(pk)> OP_DROP` | Push and discard identity stamp (AliceBobsigner only) |
| 2 | `<8> OP_PICK` | Copy sighash from bottom of stack to top (skips 5 sig + 3 pk chunks) |
| 3 | `<3> <5>` | Push chunk counts as parameters |
| 4 | `OP_DILITHIUM_VERIFY` (0xbb) | Reconstruct signature and public key from chunks, verify ML-DSA-44 signature against sighash, leave bool on stack |
| 5 | `OP_VERIFY` | Fail script if result is false |
| 6 | `OP_TRUE` | Leave `1` on stack (cleanstack) |

### Witness stack

```
Index   Content                      Size
----------------------------------------------
[0]     sighash                      32 B
[1]     sig chunk 0                 520 B
[2]     sig chunk 1                 520 B
[3]     sig chunk 2                 520 B
[4]     sig chunk 3                 520 B
[5]     sig chunk 4                 340 B
[6]     pk chunk 0                  520 B
[7]     pk chunk 1                  520 B
[8]     pk chunk 2                  272 B
[9]     witness script              (last item = P2WSH redeem script)
```

### ML-DSA-44 parameters

| Parameter | Value |
|---|---|
| Public key size | 1 312 B → 3 chunks of max 520 B |
| Signature size | 2 420 B → 5 chunks of max 520 B |
| Chunk limit | 520 B (Bitcoin script stack item limit) |

---

## PoC limitations

- **Sighash is constant** (`0xAA × 32`). A production implementation would serialise the transaction and compute the real BIP-143 sighash before signing.
- `signer.cpp` always burns the output via `OP_RETURN`; it cannot be spent further.
- Keys are generated fresh on every run and are not persisted.
- Requires a modified bitcoind with opcode 0xbb (`OP_DILITHIUM_VERIFY`).
>>>>>>> Stashed changes
