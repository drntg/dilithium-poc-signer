#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <cstring>
#include <openssl/sha.h>
#include <oqs/oqs.h>

// --- CONFIGURATION ---
// ML-DSA-44 (NIST Level 2) — same algorithm as used in the modified bitcoind
const char* OQS_ALG = OQS_SIG_alg_ml_dsa_44;
const size_t CHUNK_SIZE = 520;

// Opcodes
const uint8_t OP_swapped_block = 0xbb; // OP_DILITHIUM_VERIFY
const uint8_t OP_TRUE  = 0x51;
const uint8_t OP_DROP  = 0x75;
const uint8_t OP_VERIFY = 0x69;
const uint8_t OP_PICK  = 0x79;

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

// P2WSH scriptPubKey: OP_0 <sha256(script)>
std::string create_p2wsh_script_pubkey(const std::vector<uint8_t>& witness_script) {
    return "0020" + to_hex(sha256(witness_script));
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

void push_int(std::vector<uint8_t>& script, int val) {
    if (val >= 1 && val <= 16)
        script.push_back(0x50 + val); // OP_1 .. OP_16
    else
        script.push_back((uint8_t)val);
}

// --- MAIN ---

int main() {
    std::cout << "=== C++ PQC BITCOIN SIGNER ===" << std::endl;

    // 1. KEY GENERATION
    OQS_SIG* sig = OQS_SIG_new(OQS_ALG);
    if (sig == NULL) {
        std::cerr << "Error: algorithm " << OQS_ALG << " not found." << std::endl;
        return 1;
    }

    std::vector<uint8_t> public_key(sig->length_public_key);
    std::vector<uint8_t> secret_key(sig->length_secret_key);

    if (OQS_SIG_keypair(sig, public_key.data(), secret_key.data()) != OQS_SUCCESS) {
        std::cerr << "Error: key generation failed." << std::endl;
        return 1;
    }

    // 2. BUILD WITNESS SCRIPT
    auto pk_chunks = chunk_data(public_key.data(), public_key.size());

    std::vector<uint8_t> witness_script;

    // A) Copy sighash from the bottom of the stack to the top.
    //    ML-DSA-44: 5 sig chunks + 3 pk chunks → depth = 8
    int num_pk  = pk_chunks.size(); // 3
    int num_sig = 5;                // fixed for ML-DSA-44
    int depth   = num_pk + num_sig; // 8

    push_int(witness_script, depth);
    witness_script.push_back(OP_PICK);
    push_int(witness_script, num_pk);
    push_int(witness_script, num_sig);

    // B) PQC verification
    witness_script.push_back(OP_swapped_block); // 0xbb  OP_DILITHIUM_VERIFY
    witness_script.push_back(OP_VERIFY);
    witness_script.push_back(OP_TRUE);

    std::cout << "\nSCRIPT PUBKEY:" << std::endl;
    std::cout << create_p2wsh_script_pubkey(witness_script) << std::endl;
    std::cout << "(Use 'decodescript' in bitcoin-cli to obtain the bcrt1... address)" << std::endl;

    // 3. TRANSACTION INPUTS
    std::string txid_str;
    int vout_idx;

    std::cout << "\nEnter TXID (hex): ";
    std::cin >> txid_str;
    std::cout << "Enter VOUT: ";
    std::cin >> vout_idx;

    // 4. SIGN
    // A constant sighash is used intentionally to avoid implementing BIP-143 in C++.
    std::vector<uint8_t> sighash(32, 0xaa);
    std::vector<uint8_t> signature(sig->length_signature);
    size_t sig_len;

    OQS_SIG_sign(sig, signature.data(), &sig_len, sighash.data(), 32, secret_key.data());

    auto sig_chunks = chunk_data(signature.data(), sig_len);

    // 5. BUILD WITNESS STACK
    // Bottom to top (script is last, consumed as P2WSH redeem script):
    //   sighash | sig[0..4] | pk[0..2] | witness_script
    std::vector<std::vector<uint8_t>> stack;
    stack.push_back(sighash);
    for (const auto& c : sig_chunks) stack.push_back(c);
    for (const auto& c : pk_chunks)  stack.push_back(c);
    stack.push_back(witness_script);

    // 6. SERIALISE (version 2, 1-in 1-out SegWit)
    std::stringstream tx;

    tx << "02000000" << "0001" << "01"; // version, segwit marker/flag, input count

    auto txid_bytes = from_hex(txid_str);
    tx << to_hex(reverse_bytes(txid_bytes));

    uint32_t vout = vout_idx;
    tx << to_hex({(uint8_t)(vout & 0xff), (uint8_t)((vout >> 8) & 0xff),
                  (uint8_t)((vout >> 16) & 0xff), (uint8_t)((vout >> 24) & 0xff)});
    tx << "00";         // empty scriptSig (SegWit)
    tx << "fdffffff";   // sequence (RBF)
    tx << "01";         // output count

    // Output: 90 000 sat, OP_RETURN burn (10 000 sat fee)
    uint64_t out_amt = 90000;
    std::vector<uint8_t> amt_bytes;
    for (int i = 0; i < 8; i++) amt_bytes.push_back((out_amt >> (i * 8)) & 0xff);
    tx << to_hex(amt_bytes);
    tx << "066a04deadbeef"; // OP_RETURN <deadbeef>

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

    std::cout << "\nRAW TRANSACTION HEX:" << std::endl;
    std::cout << tx.str() << std::endl;

    OQS_SIG_free(sig);
    return 0;
}
