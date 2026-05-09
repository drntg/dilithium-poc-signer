#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <cstring>
#include <openssl/sha.h>
#include <oqs/oqs.h>
#include <oqs/rand.h>

// --- CONFIGURATION ---
const char* OQS_ALG = OQS_SIG_alg_ml_dsa_44; // NIST Level 2
const size_t CHUNK_SIZE = 520;

// Opcodes
const uint8_t OP_swapped_block = 0xbb; // OP_DILITHIUM_VERIFY
const uint8_t OP_TRUE  = 0x51;
const uint8_t OP_DROP  = 0x75;
const uint8_t OP_VERIFY = 0x69;
const uint8_t OP_PICK  = 0x79;

struct KeyPair {
    std::vector<uint8_t> pk;
    std::vector<uint8_t> sk;
};

// --- HELPERS ---

std::string to_hex(const std::vector<uint8_t>& data) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (uint8_t b : data) ss << std::setw(2) << (int)b;
    return ss.str();
}

std::vector<uint8_t> from_hex(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (unsigned int i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = (uint8_t)strtol(byteString.c_str(), NULL, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

std::vector<uint8_t> reverse_bytes(const std::vector<uint8_t>& in) {
    std::vector<uint8_t> out = in;
    std::reverse(out.begin(), out.end());
    return out;
}

std::vector<std::vector<uint8_t>> chunk_data(const uint8_t* data, size_t len) {
    std::vector<std::vector<uint8_t>> chunks;
    for (size_t i = 0; i < len; i += CHUNK_SIZE) {
        size_t current_size = std::min(CHUNK_SIZE, len - i);
        chunks.push_back(std::vector<uint8_t>(data + i, data + i + current_size));
    }
    return chunks;
}

std::vector<uint8_t> sha256(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
    SHA256(data.data(), data.size(), hash.data());
    return hash;
}

void push_data(std::vector<uint8_t>& script, const std::vector<uint8_t>& data) {
    if (data.size() < 76) {
        script.push_back((uint8_t)data.size());
    } else if (data.size() <= 255) {
        script.push_back(0x4c);
        script.push_back((uint8_t)data.size());
    } else if (data.size() <= 65535) {
        script.push_back(0x4d);
        script.push_back((uint8_t)data.size());
        script.push_back((uint8_t)(data.size() >> 8));
    }
    script.insert(script.end(), data.begin(), data.end());
}

// --- SCRIPT BUILDER ---

std::vector<uint8_t> build_pqc_script(const std::vector<uint8_t>& pk) {
    auto pk_chunks = chunk_data(pk.data(), pk.size());
    std::vector<uint8_t> script;

    // Identity stamp: SHA256(pk) is pushed and immediately dropped.
    // This makes the script hash — and therefore the P2WSH address —
    // unique per public key without affecting witness execution.
    std::vector<uint8_t> pk_hash = sha256(pk);
    push_data(script, pk_hash);
    script.push_back(OP_DROP);

    // A) Copy sighash from the bottom of the stack to the top.
    //    depth = num_sig_chunks + num_pk_chunks (items sitting above sighash)
    int num_pk  = pk_chunks.size(); // 3 for ML-DSA-44
    int num_sig = 5;                // 5 for ML-DSA-44
    int depth   = num_pk + num_sig; // 8

    auto push_small_int = [&](int val) {
        if (val >= 1 && val <= 16) script.push_back(0x50 + val);
        else script.push_back((uint8_t)val);
    };

    push_small_int(depth);
    script.push_back(OP_PICK);
    push_small_int(num_pk);
    push_small_int(num_sig);

    // B) PQC verification
    script.push_back(OP_swapped_block); // 0xbb  OP_DILITHIUM_VERIFY
    script.push_back(OP_VERIFY);
    script.push_back(OP_TRUE);

    return script;
}

// --- KEY GENERATION ---

KeyPair generate_pqc_keys() {
    OQS_SIG* sig = OQS_SIG_new(OQS_ALG);
    if (!sig) {
        std::cerr << "ERROR: OQS algorithm not found!" << std::endl;
        exit(1);
    }

    KeyPair keys;
    keys.pk.resize(sig->length_public_key);
    keys.sk.resize(sig->length_secret_key);

    if (OQS_SIG_keypair(sig, keys.pk.data(), keys.sk.data()) != OQS_SUCCESS) {
        std::cerr << "ERROR: Key generation failed!" << std::endl;
        exit(1);
    }
    OQS_SIG_free(sig);
    return keys;
}

// --- MAIN ---

int main() {
    std::cout << "=== PQC-TO-PQC TRANSFER SIMULATION ===" << std::endl;

    OQS_randombytes_switch_algorithm(OQS_RAND_alg_system);

    // ---------------------------------------------------------
    // STEP 1: Alice (sender)
    // ---------------------------------------------------------
    KeyPair alice = generate_pqc_keys();
    std::vector<uint8_t> alice_script     = build_pqc_script(alice.pk);
    std::vector<uint8_t> alice_scripthash = sha256(alice_script);
    std::string alice_p2wsh_hex = "0020" + to_hex(alice_scripthash);

    std::cout << "\n[1] ALICE (SENDER)" << std::endl;
    std::cout << "    PK hash:      " << to_hex(sha256(alice.pk)) << std::endl;
    std::cout << "    ScriptPubKey: " << alice_p2wsh_hex << std::endl;
    std::cout << "--> Fund this address before proceeding." << std::endl;

    // ---------------------------------------------------------
    // STEP 2: Bob (recipient)
    // ---------------------------------------------------------
    KeyPair bob = generate_pqc_keys();
    std::vector<uint8_t> bob_script     = build_pqc_script(bob.pk);
    std::vector<uint8_t> bob_scripthash = sha256(bob_script);
    std::string bob_p2wsh_hex = "0020" + to_hex(bob_scripthash);

    std::cout << "\n[2] BOB (RECIPIENT)" << std::endl;
    std::cout << "    PK hash:      " << to_hex(sha256(bob.pk)) << std::endl;
    std::cout << "    ScriptPubKey: " << bob_p2wsh_hex << std::endl;

    if (alice_p2wsh_hex == bob_p2wsh_hex) {
        std::cerr << "\nERROR: Alice and Bob have identical addresses." << std::endl;
        return 1;
    }
    std::cout << "--> OK: Addresses differ. PQC identity works." << std::endl;

    // ---------------------------------------------------------
    // STEP 3: User input
    // ---------------------------------------------------------
    std::string txid_str;
    int vout_idx;

    std::cout << "\n---------------------------------------------------" << std::endl;
    std::cout << "Enter funding TXID (Alice's UTXO): ";
    std::cin >> txid_str;
    std::cout << "Enter VOUT index: ";
    std::cin >> vout_idx;

    // ---------------------------------------------------------
    // STEP 4: Build transaction (Alice -> Bob)
    // ---------------------------------------------------------

    // A) Sign dummy sighash with Alice's key.
    //    A constant is used intentionally to avoid implementing BIP-143 in C++.
    OQS_SIG* sig_alg = OQS_SIG_new(OQS_ALG);
    std::vector<uint8_t> sighash(32, 0xaa);
    std::vector<uint8_t> signature(sig_alg->length_signature);
    size_t sig_len;
    OQS_SIG_sign(sig_alg, signature.data(), &sig_len, sighash.data(), 32, alice.sk.data());
    OQS_SIG_free(sig_alg);

    auto sig_chunks = chunk_data(signature.data(), sig_len);
    auto pk_chunks  = chunk_data(alice.pk.data(), alice.pk.size());

    // B) Witness stack (bottom to top, script is last):
    //    sighash | sig[0..4] | pk[0..2] | alice_script
    std::vector<std::vector<uint8_t>> stack;
    stack.push_back(sighash);
    for (const auto& c : sig_chunks) stack.push_back(c);
    for (const auto& c : pk_chunks)  stack.push_back(c);
    stack.push_back(alice_script);

    // C) Serialise (version 2, 1-in 1-out SegWit)
    std::stringstream tx;
    tx << "02000000" << "0001" << "01"; // version, segwit marker/flag, input count

    auto txid_rev = reverse_bytes(from_hex(txid_str));
    tx << to_hex(txid_rev);

    uint32_t vout = vout_idx;
    tx << to_hex({(uint8_t)(vout & 0xff), (uint8_t)((vout >> 8) & 0xff),
                  (uint8_t)((vout >> 16) & 0xff), (uint8_t)((vout >> 24) & 0xff)});
    tx << "00";         // empty scriptSig (SegWit)
    tx << "fdffffff";   // sequence (RBF)
    tx << "01";         // output count

    // Output: 90 000 sat to Bob's P2WSH address (10 000 sat fee)
    uint64_t out_amt = 90000;
    std::vector<uint8_t> amt_bytes;
    for (int i = 0; i < 8; i++) amt_bytes.push_back((out_amt >> (i * 8)) & 0xff);
    tx << to_hex(amt_bytes);

    tx << "22";          // scriptPubKey length: 34 bytes
    tx << bob_p2wsh_hex; // 0020<sha256(bob_script)>

    // Witness field
    tx << std::hex << std::setw(2) << std::setfill('0') << (int)stack.size();
    for (const auto& item : stack) {
        if (item.size() < 253) {
            tx << std::hex << std::setw(2) << std::setfill('0') << item.size();
        } else if (item.size() <= 65535) {
            tx << "fd"
               << std::hex << std::setw(2) << std::setfill('0') << (item.size() & 0xff)
               << std::hex << std::setw(2) << std::setfill('0') << ((item.size() >> 8) & 0xff);
        }
        tx << to_hex(item);
    }
    tx << "00000000"; // locktime

    std::cout << "\nRAW TRANSACTION HEX (Alice -> Bob):" << std::endl;
    std::cout << tx.str() << std::endl;

    return 0;
}
