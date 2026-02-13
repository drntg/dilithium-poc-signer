#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <cstring>
#include <openssl/sha.h>
#include <oqs/oqs.h>

// --- KONFIGURACE ---
// Používáme Level 2 (ML-DSA-44) - stejný jako v Bitcoind
const char* OQS_ALG = OQS_SIG_alg_ml_dsa_44; 
const size_t CHUNK_SIZE = 520;

// Opkódy
const uint8_t OP_2DROP = 0x6d;
const uint8_t OP_swapped_block = 0xbb; // VÁŠ OPKÓD (0xbb)
const uint8_t OP_TRUE = 0x51;
const uint8_t OP_DROP = 0x75;
const uint8_t OP_VERIFY = 0x69;
const uint8_t OP_PICK = 0x79;

// --- POMOCNÉ FUNKCE ---

// Převod na HEX string
std::string to_hex(const std::vector<uint8_t>& data) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (uint8_t b : data) ss << std::setw(2) << (int)b;
    return ss.str();
}

// Převod z HEX stringu
std::vector<uint8_t> from_hex(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (unsigned int i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = (uint8_t)strtol(byteString.c_str(), NULL, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

// Reverze (pro TXID)
std::vector<uint8_t> reverse_bytes(const std::vector<uint8_t>& in) {
    std::vector<uint8_t> out = in;
    std::reverse(out.begin(), out.end());
    return out;
}

// Chunking dat
std::vector<std::vector<uint8_t>> chunk_data(const uint8_t* data, size_t len) {
    std::vector<std::vector<uint8_t>> chunks;
    for (size_t i = 0; i < len; i += CHUNK_SIZE) {
        size_t current_size = std::min(CHUNK_SIZE, len - i);
        std::vector<uint8_t> chunk(data + i, data + i + current_size);
        chunks.push_back(chunk);
    }
    return chunks;
}

// SHA256
std::vector<uint8_t> sha256(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
    SHA256(data.data(), data.size(), hash.data());
    return hash;
}

// Tvorba P2WSH adresy (zjednodušená - vrací jen scriptPubKey hex)
// P2WSH = 00 20 <sha256(script)>
std::string create_p2wsh_script_pubkey(const std::vector<uint8_t>& witness_script) {
    std::vector<uint8_t> hash = sha256(witness_script);
    std::string hex = "0020" + to_hex(hash);
    return hex;
}

// Push data do skriptu (přidá délku)
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

// Push int (pro malá čísla)
void push_int(std::vector<uint8_t>& script, int val) {
    if (val >= 1 && val <= 16) {
        script.push_back(0x50 + val); // OP_1 .. OP_16
    } else {
        script.push_back((uint8_t)val); // Pro malá data
    }
}

// --- HLAVNÍ LOGIKA ---

int main() {
    std::cout << "=== C++ PQC BITCOIN SIGNER ===" << std::endl;

    // 1. GENEROVÁNÍ KLÍČŮ (Nativní C++ liboqs)
    OQS_SIG *sig = OQS_SIG_new(OQS_ALG);
    if (sig == NULL) {
        std::cerr << "Chyba: Algoritmus " << OQS_ALG << " nenalezen." << std::endl;
        return 1;
    }

    std::vector<uint8_t> public_key(sig->length_public_key);
    std::vector<uint8_t> secret_key(sig->length_secret_key);

    if (OQS_SIG_keypair(sig, public_key.data(), secret_key.data()) != OQS_SUCCESS) {
        std::cerr << "Chyba Keygen" << std::endl;
        return 1;
    }

    // 2. SESTAVENÍ WITNESS SKRIPTU
    auto pk_chunks = chunk_data(public_key.data(), public_key.size());
    
    std::vector<uint8_t> witness_script;
    
    // A) Bypass ECDSA (OP_2DROP)
    witness_script.push_back(OP_2DROP);

    // B) Příprava pro PQC (Pick hash)
    // Level 2 = 5 sig chunks, 3 pk chunks -> Depth = 8
    int num_pk = pk_chunks.size(); // 3
    int num_sig = 5; // Pro ML-DSA-44 fixní odhad
    int depth = num_pk + num_sig;

    push_int(witness_script, depth);
    witness_script.push_back(OP_PICK);
    push_int(witness_script, num_pk);
    push_int(witness_script, num_sig);

    // C) PQC Ověření
    witness_script.push_back(OP_swapped_block); // 0xbb
    witness_script.push_back(OP_VERIFY);
   //    witness_script.push_back(OP_DROP);
    witness_script.push_back(OP_TRUE);

    // VÝPIS ADRESY
    std::cout << "\nSCRIPT PUB KEY (Pro importaddress):" << std::endl;
    std::cout << create_p2wsh_script_pubkey(witness_script) << std::endl;
    std::cout << "(Poznámka: Toto je raw hex scriptPubKey. Použijte 'decodescript' v CLI pro získání adresy bcrt1...)" << std::endl;

    // 3. VSTUPY PRO TRANSAKCI
    std::string txid_str;
    int vout_idx;
    uint64_t amount_sat = 100000;

    std::cout << "\nZadejte TXID (hex): ";
    std::cin >> txid_str;
    std::cout << "Zadejte VOUT: ";
    std::cin >> vout_idx;

    // 4. PODPIS (DUMMY HASH 0xAA)
    // Používáme konstantu, abychom se vyhnuli implementaci BIP-143 v C++ (což je na 500 řádků).
    // Protokolově je to validní test PQC ověření.
    std::vector<uint8_t> sighash(32, 0xaa); 
    std::vector<uint8_t> signature(sig->length_signature);
    size_t sig_len;

    OQS_SIG_sign(sig, signature.data(), &sig_len, sighash.data(), 32, secret_key.data());
    
    // Chunking podpisu
    auto sig_chunks = chunk_data(signature.data(), sig_len);

    // 5. SESTAVENÍ WITNESS STACKU
    // Format: [Items Count] [Item 1 Len] [Item 1] ...
    // Bitcoin serializace witnessu: <počet položek> <item1> <item2> ...
    
    std::vector<std::vector<uint8_t>> stack;
    
    // Dno: Dummy Hash
    stack.push_back(sighash);
    // Sig Chunky
    for (const auto& c : sig_chunks) stack.push_back(c);
    // Pk Chunky
    for (const auto& c : pk_chunks) stack.push_back(c);
    // Dummy ECDSA (2x, protože OP_2DROP zahodí 2 itemy)
    stack.push_back({0x00}); // Dummy Sig
    stack.push_back({0x00}); // Dummy PK
    // Vrchol: Skript
    stack.push_back(witness_script);

    // 6. SERIALIZACE DO HEX (Hardcoded template pro 1-in 1-out SegWit)
    std::stringstream tx;
    
    // Version (2)
    tx << "02000000"; 
    // Marker & Flag (Segwit)
    tx << "0001";
    // Input Count (1)
    tx << "01";
    
    // Input TXID (Reversed!)
    auto txid_bytes = from_hex(txid_str);
    auto txid_rev = reverse_bytes(txid_bytes);
    tx << to_hex(txid_rev);
    
    // Input VOUT (4 bytes little endian)
    uint32_t vout = vout_idx;
    tx << to_hex({(uint8_t)(vout & 0xff), (uint8_t)((vout >> 8) & 0xff), (uint8_t)((vout >> 16) & 0xff), (uint8_t)((vout >> 24) & 0xff)});
    
    // ScriptSig Len (0 for Segwit input)
    tx << "00";
    
    // Sequence (Enable RBF)
    tx << "fdffffff";

    // Output Count (1)
    tx << "01";
    
    // Output Amount (90000 sat = 0.0009 BTC, Little Endian)
    // 10k sat fee
    uint64_t out_amt = 90000; 
    std::vector<uint8_t> amt_bytes;
    for(int i=0; i<8; i++) amt_bytes.push_back((out_amt >> (i*8)) & 0xff);
    tx << to_hex(amt_bytes);

    // Output ScriptPubKey (OP_RETURN deadbeef - Burn)
    tx << "066a04deadbeef"; 

    // WITNESS FIELD
    // Počet položek
    tx << std::hex << std::setw(2) << std::setfill('0') << (int)stack.size();
    
    // Položky
    for (const auto& item : stack) {
        // Varint length (zjednodušeně pro naše velikosti)
        if (item.size() < 253) {
            tx << std::hex << std::setw(2) << std::setfill('0') << item.size();
        } else if (item.size() <= 65535) {
            tx << "fd" << std::hex << std::setw(2) << std::setfill('0') << (item.size() & 0xff);
            tx << std::hex << std::setw(2) << std::setfill('0') << ((item.size() >> 8) & 0xff);
        }
        // Data
        tx << to_hex(item);
    }

    // Locktime
    tx << "00000000";

    std::cout << "\n📦 RAW TRANSACTION HEX:" << std::endl;
    std::cout << tx.str() << std::endl;

    OQS_SIG_free(sig);
    return 0;
}