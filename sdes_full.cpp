/*
 * S-DES Algorithm Implementation (C++)
 * Assignment 1: S-DES Algorithm
 *
 * Features:
 *   1. Basic encrypt/decrypt (8-bit plaintext + 10-bit key)
 *   2. Cross-test support (standard permutation tables)
 *   3. ASCII string encrypt/decrypt
 *   4. Brute force attack
 *   5. Closed test (multi-key analysis)
 *
 * Compile (MSVC):  cl /EHsc /utf-8 sdes_full.cpp
 * Compile (GCC):   g++ -o sdes sdes_full.cpp
 */

#include <iostream>
#include <string>
#include <vector>
#include <cstdlib>
#include <ctime>
#include <map>
#include <iomanip>
using namespace std;

// ============================================================
// Permutation Tables (strictly per assignment spec, 0-based)
// ============================================================

// P10: 10-bit key -> 10 bits
const int P10[10] = {2, 4, 1, 6, 3, 9, 0, 8, 7, 5};

// P8: select 8 bits from 10
const int P8[8] = {5, 2, 6, 3, 7, 4, 9, 8};

// Initial Permutation IP
const int IP[8] = {1, 5, 2, 0, 3, 7, 4, 6};

// Inverse Initial Permutation
const int IP_INV[8] = {3, 0, 2, 4, 6, 1, 7, 5};

// Expansion Permutation EP
const int EP[8] = {3, 0, 1, 2, 1, 2, 3, 0};

// Direct Permutation P4
const int P4[4] = {1, 3, 2, 0};

// S-Box 1 (S0)
const int SBOX1[4][4] = {
    {1, 0, 3, 2},
    {3, 2, 1, 0},
    {0, 2, 1, 3},
    {3, 1, 0, 2}
};

// S-Box 2 (S1)
const int SBOX2[4][4] = {
    {0, 1, 2, 3},
    {2, 3, 1, 0},
    {3, 0, 1, 2},
    {2, 1, 0, 3}
};

// ============================================================
// Utility Functions
// ============================================================

vector<int> strToBits(const string& s) {
    vector<int> bits(s.length());
    for (size_t i = 0; i < s.length(); i++)
        bits[i] = (s[i] == '1') ? 1 : 0;
    return bits;
}

string bitsToStr(const vector<int>& bits) {
    string s;
    for (size_t i = 0; i < bits.size(); i++)
        s += (bits[i] ? '1' : '0');
    return s;
}

vector<int> permute(const vector<int>& bits, const int table[], int len_out) {
    vector<int> out(len_out);
    for (int i = 0; i < len_out; i++)
        out[i] = bits[table[i]];
    return out;
}

vector<int> leftShift(const vector<int>& in, int n) {
    int len = in.size();
    vector<int> out(len);
    for (int i = 0; i < len; i++)
        out[i] = in[(i + n) % len];
    return out;
}

vector<int> xorBits(const vector<int>& a, const vector<int>& b) {
    vector<int> out(a.size());
    for (size_t i = 0; i < a.size(); i++)
        out[i] = a[i] ^ b[i];
    return out;
}

// ============================================================
// Key Expansion: 10-bit key -> K1, K2 (each 8-bit)
// ============================================================
void keyExpansion(const vector<int>& key, vector<int>& k1, vector<int>& k2) {
    vector<int> p10 = permute(key, P10, 10);

    vector<int> left(5), right(5);
    for (int i = 0; i < 5; i++) {
        left[i] = p10[i];
        right[i] = p10[i + 5];
    }

    // K1: left shift by 1
    left = leftShift(left, 1);
    right = leftShift(right, 1);
    vector<int> c1(10);
    for (int i = 0; i < 5; i++) {
        c1[i] = left[i];
        c1[i + 5] = right[i];
    }
    k1 = permute(c1, P8, 8);

    // K2: left shift by 2 more (total 3)
    left = leftShift(left, 2);
    right = leftShift(right, 2);
    vector<int> c2(10);
    for (int i = 0; i < 5; i++) {
        c2[i] = left[i];
        c2[i + 5] = right[i];
    }
    k2 = permute(c2, P8, 8);
}

// ============================================================
// S-Box lookup: 4-bit input -> 2-bit output
// Row = bit0 + bit3, Col = bit1 + bit2
// ============================================================
vector<int> sboxLookup(const int sbox[4][4], const vector<int>& input) {
    int row = (input[0] << 1) | input[3];
    int col = (input[1] << 1) | input[2];
    int val = sbox[row][col];
    vector<int> out(2);
    out[0] = (val >> 1) & 1;
    out[1] = val & 1;
    return out;
}

// ============================================================
// Round Function F(R, K)
// ============================================================
vector<int> fFunction(const vector<int>& R, const vector<int>& K) {
    vector<int> ep = permute(R, EP, 8);
    vector<int> mixed = xorBits(ep, K);

    vector<int> left4(4), right4(4);
    for (int i = 0; i < 4; i++) {
        left4[i] = mixed[i];
        right4[i] = mixed[i + 4];
    }

    vector<int> s1 = sboxLookup(SBOX1, left4);
    vector<int> s2 = sboxLookup(SBOX2, right4);

    vector<int> sboxOut(4);
    sboxOut[0] = s1[0];
    sboxOut[1] = s1[1];
    sboxOut[2] = s2[0];
    sboxOut[3] = s2[1];

    return permute(sboxOut, P4, 4);
}

// ============================================================
// Feistel Two Rounds
// ============================================================
vector<int> feistel(const vector<int>& ipOut, const vector<int>& k1, const vector<int>& k2) {
    vector<int> L(4), R(4);
    for (int i = 0; i < 4; i++) {
        L[i] = ipOut[i];
        R[i] = ipOut[i + 4];
    }

    // Round 1
    vector<int> f1 = fFunction(R, k1);
    vector<int> newL = R;
    vector<int> newR = xorBits(L, f1);

    // Round 2
    vector<int> f2 = fFunction(newR, k2);
    vector<int> finalL = xorBits(newL, f2);
    vector<int> finalR = newR;

    vector<int> out(8);
    for (int i = 0; i < 4; i++) {
        out[i] = finalL[i];
        out[i + 4] = finalR[i];
    }
    return out;
}

// ============================================================
// Encrypt
// ============================================================
vector<int> encrypt(const vector<int>& plaintext, const vector<int>& key) {
    vector<int> k1, k2;
    keyExpansion(key, k1, k2);

    vector<int> ip = permute(plaintext, IP, 8);
    vector<int> feistelOut = feistel(ip, k1, k2);
    return permute(feistelOut, IP_INV, 8);
}

// ============================================================
// Decrypt
// ============================================================
vector<int> decrypt(const vector<int>& ciphertext, const vector<int>& key) {
    vector<int> k1, k2;
    keyExpansion(key, k1, k2);

    vector<int> ip = permute(ciphertext, IP, 8);
    vector<int> feistelOut = feistel(ip, k2, k1);
    return permute(feistelOut, IP_INV, 8);
}

// ============================================================
// Byte <-> Bits conversion
// ============================================================
vector<int> byteToBits(unsigned char c) {
    vector<int> bits(8);
    for (int i = 0; i < 8; i++)
        bits[i] = (c >> (7 - i)) & 1;
    return bits;
}

unsigned char bitsToByte(const vector<int>& bits) {
    unsigned char c = 0;
    for (int i = 0; i < 8; i++)
        c |= (bits[i] << (7 - i));
    return c;
}

// ============================================================
// Print Menu
// ============================================================
void printMenu() {
    cout << endl;
    cout << "======================================" << endl;
    cout << "       S-DES Algorithm System" << endl;
    cout << "======================================" << endl;
    cout << "  1. Basic Encrypt/Decrypt Test" << endl;
    cout << "  2. ASCII String Encrypt/Decrypt" << endl;
    cout << "  3. Batch Random Test (Consistency)" << endl;
    cout << "  4. Brute Force Attack" << endl;
    cout << "  5. Closed Test (Multi-key Analysis)" << endl;
    cout << "  0. Exit" << endl;
    cout << "======================================" << endl;
    cout << "Select: ";
}

// ============================================================
// Main
// ============================================================
int main() {
    srand(time(NULL));
    int choice;

    while (true) {
        printMenu();
        cin >> choice;

        if (choice == 0) {
            cout << "Goodbye!" << endl;
            break;
        }

        cout << endl;

        switch (choice) {

        // ==========================================
        // 1. Basic Encrypt/Decrypt
        // ==========================================
        case 1: {
            cout << "=== Basic Encrypt/Decrypt ===" << endl;
            cout << "Enter 8-bit plaintext (e.g. 00100110): ";
            string pstr, kstr;
            cin >> pstr;
            cout << "Enter 10-bit key (e.g. 1010000010): ";
            cin >> kstr;

            vector<int> pt = strToBits(pstr);
            vector<int> kt = strToBits(kstr);
            vector<int> ct = encrypt(pt, kt);
            vector<int> dt = decrypt(ct, kt);

            cout << endl;
            cout << "Plaintext:  " << bitsToStr(pt) << endl;
            cout << "Key:        " << bitsToStr(kt) << endl;
            cout << "Ciphertext: " << bitsToStr(ct) << endl;
            cout << "Decrypted:  " << bitsToStr(dt) << endl;
            cout << "Result:     " << (dt == pt ? "[PASS] Consistent" : "[FAIL] Inconsistent") << endl;
            break;
        }

        // ==========================================
        // 2. ASCII String Encrypt/Decrypt
        // ==========================================
        case 2: {
            cout << "=== ASCII String Encrypt/Decrypt ===" << endl;
            cout << "Enter string: ";
            cin.ignore();
            string text;
            getline(cin, text);
            cout << "Enter 10-bit key: ";
            string kstr;
            cin >> kstr;
            vector<int> kt = strToBits(kstr);

            cout << endl << "Encryption per byte:" << endl;
            string encrypted = "";
            for (size_t i = 0; i < text.size(); i++) {
                unsigned char c = static_cast<unsigned char>(text[i]);
                vector<int> pt = byteToBits(c);
                vector<int> ct = encrypt(pt, kt);
                unsigned char ctByte = bitsToByte(ct);
                cout << "  '" << text[i] << "' (" << bitsToStr(pt) << ") -> "
                     << bitsToStr(ct) << endl;
                encrypted += ctByte;
            }

            cout << endl << "Decryption per byte:" << endl;
            string decrypted = "";
            for (size_t i = 0; i < encrypted.size(); i++) {
                unsigned char c = static_cast<unsigned char>(encrypted[i]);
                vector<int> ct = byteToBits(c);
                vector<int> pt = decrypt(ct, kt);
                unsigned char ptByte = bitsToByte(pt);
                cout << "  " << bitsToStr(ct) << " -> '"
                     << (isprint(ptByte) ? (char)ptByte : '?') << "' ("
                     << bitsToStr(pt) << ")" << endl;
                decrypted += ptByte;
            }
            cout << endl << "Decrypted result: " << decrypted << endl;
            cout << "Result:           " << (decrypted == text ? "[PASS] Match" : "[FAIL] Mismatch") << endl;
            break;
        }

        // ==========================================
        // 3. Batch Random Test
        // ==========================================
        case 3: {
            cout << "=== Batch Random Test ===" << endl;
            cout << "Number of tests (default 50): ";
            int n;
            cin >> n;
            if (n <= 0) n = 50;

            int pass = 0;
            for (int i = 0; i < n; i++) {
                vector<int> pt(8), kt(10);
                for (int j = 0; j < 8; j++) pt[j] = rand() % 2;
                for (int j = 0; j < 10; j++) kt[j] = rand() % 2;
                vector<int> ct = encrypt(pt, kt);
                vector<int> dt = decrypt(ct, kt);
                if (dt == pt) {
                    pass++;
                } else {
                    cout << "  Test " << (i+1) << " FAILED: pt=" << bitsToStr(pt)
                         << " key=" << bitsToStr(kt) << endl;
                }
            }
            cout << endl << "Passed: " << pass << "/" << n << endl;
            break;
        }

        // ==========================================
        // 4. Brute Force Attack
        // ==========================================
        case 4: {
            cout << "=== Brute Force Attack ===" << endl;
            cout << "Enter known 8-bit plaintext: ";
            string pstr;
            cin >> pstr;
            cout << "Enter known 8-bit ciphertext: ";
            string cstr;
            cin >> cstr;

            vector<int> pt = strToBits(pstr);
            vector<int> ct = strToBits(cstr);

            cout << endl << "Scanning 1024 possible keys..." << endl;
            clock_t start = clock();

            vector<string> found;
            for (int k = 0; k < 1024; k++) {
                vector<int> kt(10);
                for (int i = 0; i < 10; i++)
                    kt[i] = (k >> (9 - i)) & 1;
                if (encrypt(pt, kt) == ct) {
                    found.push_back(bitsToStr(kt));
                }
            }

            clock_t end = clock();
            double elapsed = double(end - start) / CLOCKS_PER_SEC;

            cout << "Time: " << fixed << setprecision(3) << elapsed << " seconds" << endl;
            cout << "Found " << found.size() << " possible keys:" << endl;
            for (size_t i = 0; i < found.size(); i++) {
                cout << "  " << (i+1) << ". " << found[i] << endl;
            }
            break;
        }

        // ==========================================
        // 5. Closed Test
        // ==========================================
        case 5: {
            cout << "=== Closed Test: Multi-key Analysis ===" << endl;
            cout << "Analyzing: how many keys map to same ciphertext for fixed plaintext" << endl;
            cout << "Enter 8-bit plaintext (enter 'all' for all 256 plaintexts): ";
            string pstr;
            cin >> pstr;

            if (pstr == "all") {
                cout << endl << "Analyzing all 256 plaintexts..." << endl;
                int totalDuplicate = 0;
                int maxKeys = 0;
                string maxCipher = "";

                for (int p = 0; p < 256; p++) {
                    vector<int> pt = byteToBits((unsigned char)p);
                    map<string, int> cipherCount;

                    for (int k = 0; k < 1024; k++) {
                        vector<int> kt(10);
                        for (int i = 0; i < 10; i++)
                            kt[i] = (k >> (9 - i)) & 1;
                        vector<int> ct = encrypt(pt, kt);
                        cipherCount[bitsToStr(ct)]++;
                    }

                    int dup = 0;
                    for (map<string, int>::iterator it = cipherCount.begin(); it != cipherCount.end(); ++it) {
                        if (it->second > 1) dup++;
                        if (it->second > maxKeys) {
                            maxKeys = it->second;
                            maxCipher = it->first;
                        }
                    }
                    totalDuplicate += dup;
                }

                cout << endl << "===== Results =====" << endl;
                cout << "Total plaintexts: 256" << endl;
                cout << "Avg duplicate ciphertexts per plaintext: "
                     << fixed << setprecision(1) << (totalDuplicate / 256.0) << endl;
                cout << "Max keys for single ciphertext: " << maxKeys << endl;
                cout << "  Ciphertext: " << maxCipher << endl;
                cout << endl << "Conclusion: S-DES indeed has many-to-one mapping." << endl;
                cout << "Different keys can produce the same ciphertext for same plaintext." << endl;
            } else {
                vector<int> pt = strToBits(pstr);
                map<string, vector<string> > cipherToKeys;

                for (int k = 0; k < 1024; k++) {
                    vector<int> kt(10);
                    for (int i = 0; i < 10; i++)
                        kt[i] = (k >> (9 - i)) & 1;
                    vector<int> ct = encrypt(pt, kt);
                    cipherToKeys[bitsToStr(ct)].push_back(bitsToStr(kt));
                }

                cout << endl << "Plaintext: " << bitsToStr(pt) << endl;
                cout << "Total unique ciphertexts: " << cipherToKeys.size() << endl;
                cout << endl << "Ciphertexts with multiple keys:" << endl;

                int multi = 0;
                for (map<string, vector<string> >::iterator it = cipherToKeys.begin(); it != cipherToKeys.end(); ++it) {
                    if (it->second.size() > 1) {
                        multi++;
                        cout << "  Ciphertext " << it->first << " <- "
                             << it->second.size() << " keys" << endl;
                    }
                }
                cout << endl << "Total ciphertexts with multiple keys: " << multi << endl;
                cout << "Conclusion: Yes, different keys can encrypt same plaintext to same ciphertext." << endl;
            }
            break;
        }

        default:
            cout << "Invalid choice, please try again." << endl;
        }

        cout << endl << "Press Enter to continue...";
        cin.ignore();
        cin.get();
    }

    return 0;
}
