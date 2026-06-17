/*
 * db_creator.cpp  —  Bitcoin Adres → Hash160 Sirali Veritabani Olusturucu
 *
 * Desteklenen tipler:
 *   - P2PKH   "1..."      (Base58Check, version 0x00)
 *   - P2WPKH  "bc1q..."   (Bech32, witness version 0, 20-byte program)
 *   - P2SH    "3..."      (Base58Check, version 0x05)  → ayri dosyaya
 *
 * Kullanim:
 *   db_creator.exe                              (varsayilan: asagidaki CSV'leri tarar)
 *   db_creator.exe -o database.bin -p2sh p2sh.bin <csv1> [csv2] ...
 *
 * Varsayilan girdi dosyalari (bulunanlar otomatik islenir):
 *   adresler.csv, bcq1.csv, P2SH.csv
 *
 * Cikti:
 *   database.bin       — P2PKH + P2WPKH birlestirilmis hash160 (ayni pubkey-hash havuzu)
 *   database_p2sh.bin  — P2SH hash160 (Phase 2 wrapped-segwit icin ayri)
 *
 * Format (her iki .bin de ayni):
 *   [8 bytes]  uint64_t count (little-endian)
 *   [20 × count bytes]  sirali Hash160 kayitlari
 *
 * Derleme:
 *   MSVC  : cl /O2 /EHsc /Fe:db_creator.exe db_creator.cpp
 *   g++   : g++ -O3 -std=c++17 -o db_creator.exe db_creator.cpp
 */

#include <cstdint>
#include <cstring>
#include <cstdio>
#include <vector>
#include <string>
#include <algorithm>
#include <chrono>
#include <ctype.h>

// ============================================================================
// SHA-256  (bagimsiz)
// ============================================================================
static const uint32_t SHA256_K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
    0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
    0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
    0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
    0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
    0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define ROR32(x,n) (((x)>>(n))|((x)<<(32-(n))))

struct Sha256Ctx {
    uint32_t state[8];
    uint64_t count;
    uint8_t  buf[64];
};

static void sha256_compress(Sha256Ctx* ctx, const uint8_t blk[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)blk[i*4]<<24)|((uint32_t)blk[i*4+1]<<16)|
               ((uint32_t)blk[i*4+2]<<8)|(uint32_t)blk[i*4+3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ROR32(w[i-15],7)^ROR32(w[i-15],18)^(w[i-15]>>3);
        uint32_t s1 = ROR32(w[i-2],17)^ROR32(w[i-2],19)^(w[i-2]>>10);
        w[i] = w[i-16]+s0+w[i-7]+s1;
    }
    uint32_t a=ctx->state[0],b=ctx->state[1],c=ctx->state[2],d=ctx->state[3];
    uint32_t e=ctx->state[4],f=ctx->state[5],g=ctx->state[6],h=ctx->state[7];
    for (int i = 0; i < 64; i++) {
        uint32_t t1 = h + (ROR32(e,6)^ROR32(e,11)^ROR32(e,25))
                      + ((e&f)^(~e&g)) + SHA256_K[i] + w[i];
        uint32_t t2 = (ROR32(a,2)^ROR32(a,13)^ROR32(a,22))
                      + ((a&b)^(a&c)^(b&c));
        h=g; g=f; f=e; e=d+t1;
        d=c; c=b; b=a; a=t1+t2;
    }
    ctx->state[0]+=a; ctx->state[1]+=b; ctx->state[2]+=c; ctx->state[3]+=d;
    ctx->state[4]+=e; ctx->state[5]+=f; ctx->state[6]+=g; ctx->state[7]+=h;
}

static void sha256_init(Sha256Ctx* ctx) {
    ctx->state[0]=0x6a09e667; ctx->state[1]=0xbb67ae85;
    ctx->state[2]=0x3c6ef372; ctx->state[3]=0xa54ff53a;
    ctx->state[4]=0x510e527f; ctx->state[5]=0x9b05688c;
    ctx->state[6]=0x1f83d9ab; ctx->state[7]=0x5be0cd19;
    ctx->count = 0;
    memset(ctx->buf, 0, 64);
}

static void sha256_update(Sha256Ctx* ctx, const uint8_t* data, size_t len) {
    size_t i = (size_t)(ctx->count & 63);
    ctx->count += len;
    if (i + len < 64) { memcpy(ctx->buf+i, data, len); return; }
    size_t j = 64-i;
    memcpy(ctx->buf+i, data, j);
    sha256_compress(ctx, ctx->buf);
    for (; j+64 <= len; j+=64) sha256_compress(ctx, data+j);
    memcpy(ctx->buf, data+j, len-j);
}

static void sha256_final(Sha256Ctx* ctx, uint8_t out[32]) {
    uint64_t bc = ctx->count * 8;
    uint8_t p = 0x80;
    sha256_update(ctx, &p, 1);
    while ((ctx->count & 63) != 56) { p=0; sha256_update(ctx,&p,1); }
    uint8_t bits[8];
    for (int i=7; i>=0; i--) { bits[i]=(uint8_t)(bc&0xFF); bc>>=8; }
    sha256_update(ctx, bits, 8);
    for (int i=0; i<8; i++) {
        out[i*4]  =(uint8_t)(ctx->state[i]>>24);
        out[i*4+1]=(uint8_t)(ctx->state[i]>>16);
        out[i*4+2]=(uint8_t)(ctx->state[i]>> 8);
        out[i*4+3]=(uint8_t)(ctx->state[i]);
    }
}

static void sha256d(const uint8_t* data, size_t len, uint8_t out[32]) {
    uint8_t tmp[32];
    Sha256Ctx ctx;
    sha256_init(&ctx); sha256_update(&ctx,data,len); sha256_final(&ctx,tmp);
    sha256_init(&ctx); sha256_update(&ctx,tmp,32);  sha256_final(&ctx,out);
}

#undef ROR32

// ============================================================================
// Base58Check decoder — P2PKH (1...) ve P2SH (3...)
// ============================================================================

static const int8_t B58MAP[128] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8,-1,-1,-1,-1,-1,-1,
    -1, 9,10,11,12,13,14,15,16,-1,17,18,19,20,21,-1,
    22,23,24,25,26,27,28,29,30,31,32,-1,-1,-1,-1,-1,
    -1,33,34,35,36,37,38,39,40,41,42,43,-1,44,45,46,
    47,48,49,50,51,52,53,54,55,56,57,-1,-1,-1,-1,-1
};

// expected_ver: 0x00 = P2PKH, 0x05 = P2SH
static bool decode_base58_address(const char* addr, int alen, uint8_t hash160[20], uint8_t expected_ver) {
    if (alen < 25 || alen > 34) return false;

    for (int i = 0; i < alen; i++) {
        unsigned char c = (unsigned char)addr[i];
        if (c >= 128 || B58MAP[c] < 0) return false;
    }

    uint8_t dec[32] = {};
    int dec_len = 0;

    for (int ci = 0; ci < alen; ci++) {
        int carry = B58MAP[(unsigned char)addr[ci]];
        for (int i = dec_len-1; i >= 0; i--) {
            carry += (int)dec[i] * 58;
            dec[i] = (uint8_t)(carry & 0xFF);
            carry >>= 8;
        }
        while (carry > 0) {
            if (dec_len >= 28) return false;
            memmove(dec+1, dec, (size_t)dec_len);
            dec[0] = (uint8_t)(carry & 0xFF);
            carry >>= 8;
            dec_len++;
        }
    }

    int leading = 0;
    for (int i = 0; i < alen && addr[i] == '1'; i++) leading++;

    if (dec_len + leading != 25) return false;

    uint8_t payload[25] = {};
    memcpy(payload + 25 - dec_len, dec, (size_t)dec_len);

    if (payload[0] != expected_ver) return false;

    uint8_t chk[32];
    sha256d(payload, 21, chk);
    if (memcmp(chk, payload+21, 4) != 0) return false;

    memcpy(hash160, payload+1, 20);
    return true;
}

// ============================================================================
// Bech32 decoder (Pieter Wuille, BIP-173)  — P2WPKH  "bc1q..."
// ============================================================================

static uint32_t bech32_polymod_step(uint32_t pre) {
    uint8_t b = pre >> 25;
    return ((pre & 0x1FFFFFF) << 5) ^
        (-((b >> 0) & 1) & 0x3b6a57b2UL) ^
        (-((b >> 1) & 1) & 0x26508e6dUL) ^
        (-((b >> 2) & 1) & 0x1ea119faUL) ^
        (-((b >> 3) & 1) & 0x3d4233ddUL) ^
        (-((b >> 4) & 1) & 0x2a1462b3UL);
}

static const int8_t BECH32_REV[128] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    15,-1,10,17,21,20,26,30, 7, 5,-1,-1,-1,-1,-1,-1,
    -1,29,-1,24,13,25, 9, 8,23,-1,18,22,31,27,19,-1,
     1, 0, 3,16,11,28,12,14, 6, 4, 2,-1,-1,-1,-1,-1,
    -1,29,-1,24,13,25, 9, 8,23,-1,18,22,31,27,19,-1,
     1, 0, 3,16,11,28,12,14, 6, 4, 2,-1,-1,-1,-1,-1
};

// Decode bech32 to hrp + 5-bit data. Returns true on success.
static bool bech32_decode(const char* input, int input_len, char hrp[84], uint8_t data[128], int* data_len) {
    if (input_len < 8 || input_len > 90) return false;

    // Find separator '1' (last occurrence)
    int sep = -1;
    for (int i = input_len - 1; i >= 0; i--) {
        if (input[i] == '1') { sep = i; break; }
    }
    if (sep < 1 || sep + 7 > input_len) return false;

    // HRP
    int hrp_len = sep;
    for (int i = 0; i < hrp_len; i++) {
        char c = input[i];
        if (c < 33 || c > 126) return false;
        if (c >= 'A' && c <= 'Z') c = c - 'A' + 'a';
        hrp[i] = c;
    }
    hrp[hrp_len] = 0;

    // Data part length (excluding 6-char checksum)
    int dl = input_len - sep - 1 - 6;
    if (dl < 0 || dl > 120) return false;

    // Compute checksum
    uint32_t chk = 1;
    for (int i = 0; i < hrp_len; i++) {
        chk = bech32_polymod_step(chk) ^ ((unsigned char)hrp[i] >> 5);
    }
    chk = bech32_polymod_step(chk);
    for (int i = 0; i < hrp_len; i++) {
        chk = bech32_polymod_step(chk) ^ ((unsigned char)hrp[i] & 0x1f);
    }

    for (int i = sep + 1; i < input_len; i++) {
        unsigned char c = (unsigned char)input[i];
        if (c >= 128) return false;
        int v = BECH32_REV[c];
        if (v < 0) return false;
        chk = bech32_polymod_step(chk) ^ v;
        if (i < input_len - 6) {
            data[i - sep - 1] = (uint8_t)v;
        }
    }
    if (chk != 1) return false;

    *data_len = dl;
    return true;
}

// Convert 5-bit data to 8-bit witness program.
static bool convert_bits_5_to_8(const uint8_t* in, int inlen, uint8_t* out, int* outlen) {
    uint32_t val = 0;
    int bits = 0;
    int ol = 0;
    for (int i = 0; i < inlen; i++) {
        val = (val << 5) | in[i];
        bits += 5;
        while (bits >= 8) {
            bits -= 8;
            out[ol++] = (uint8_t)((val >> bits) & 0xFF);
        }
    }
    if (bits >= 5 || ((val << (8 - bits)) & 0xFF)) return false;
    *outlen = ol;
    return true;
}

// Decode bc1q... → 20-byte hash160. Sadece v0 P2WPKH (20 byte). v1+ Taproot atlanir.
static bool decode_bech32_p2wpkh(const char* addr, int alen, uint8_t hash160[20]) {
    if (alen < 14 || alen > 90) return false;
    // HRP prefix "bc" bekleniyor
    if (!(alen >= 3 && (addr[0]=='b'||addr[0]=='B') && (addr[1]=='c'||addr[1]=='C') && addr[2]=='1'))
        return false;

    char hrp[84];
    uint8_t data[128];
    int dl;
    if (!bech32_decode(addr, alen, hrp, data, &dl)) return false;
    if (strcmp(hrp, "bc") != 0) return false;
    if (dl < 1) return false;

    int witver = data[0];
    if (witver != 0) return false; // sadece v0 (Taproot/P2TR atla)

    uint8_t prog[40];
    int plen;
    if (!convert_bits_5_to_8(data + 1, dl - 1, prog, &plen)) return false;

    if (plen != 20) return false; // P2WPKH = 20 byte (P2WSH = 32 byte atla)

    memcpy(hash160, prog, 20);
    return true;
}

// ============================================================================
// Hash160 yapisi
// ============================================================================
struct Hash160 {
    uint8_t h[20];
    bool operator<(const Hash160& o) const {
        return memcmp(h, o.h, 20) < 0;
    }
    bool operator==(const Hash160& o) const {
        return memcmp(h, o.h, 20) == 0;
    }
};

// ============================================================================
// Adres tipini prefix'ten tespit et
// ============================================================================
enum AddrType { ADDR_UNKNOWN=0, ADDR_P2PKH=1, ADDR_P2WPKH=2, ADDR_P2SH=3 };

static AddrType detect_type(const char* tok, int len) {
    if (len < 14 || len > 90) return ADDR_UNKNOWN;
    char c0 = tok[0];
    char c1 = (len > 1) ? tok[1] : 0;
    if (c0 == '1') return ADDR_P2PKH;
    if (c0 == '3') return ADDR_P2SH;
    if ((c0 == 'b' || c0 == 'B') && (c1 == 'c' || c1 == 'C') && len > 2 && tok[2] == '1')
        return ADDR_P2WPKH;
    return ADDR_UNKNOWN;
}

// ============================================================================
// Dosya varlik kontrolu
// ============================================================================
static bool file_exists(const char* path) {
    FILE* fp = fopen(path, "rb");
    if (fp) { fclose(fp); return true; }
    return false;
}

// ============================================================================
// CSV'yi isle (bir veya birden fazla tokenli satirlar desteklenir)
// ============================================================================
static void process_csv(const char* path,
                        std::vector<Hash160>& pubkey_hashes,  // P2PKH + P2WPKH
                        std::vector<Hash160>& p2sh_hashes,
                        uint64_t& ok_pkh, uint64_t& ok_wpkh, uint64_t& ok_p2sh,
                        uint64_t& failed)
{
    FILE* fp = fopen(path, "rb");
    if (!fp) { fprintf(stderr, "[HATA] %s acilamadi\n", path); return; }

    printf("[*] Islennyor: %s\n", path);
    auto t0 = std::chrono::high_resolution_clock::now();

    char line[4096];
    uint64_t lines_read = 0;
    uint64_t local_ok = 0;

    while (fgets(line, sizeof(line), fp)) {
        lines_read++;

        char* p = line;
        while (*p) {
            while (*p && (*p==','||*p==' '||*p=='\t'||*p=='\n'||*p=='\r'||*p==';')) p++;
            if (!*p) break;

            char* tok = p;
            while (*p && *p!=','&&*p!=' '&&*p!='\t'&&*p!='\n'&&*p!='\r'&&*p!=';') p++;
            int tlen = (int)(p - tok);

            AddrType type = detect_type(tok, tlen);
            Hash160 h;
            bool decoded = false;

            switch (type) {
                case ADDR_P2PKH:
                    if (decode_base58_address(tok, tlen, h.h, 0x00)) {
                        pubkey_hashes.push_back(h);
                        ok_pkh++; local_ok++; decoded = true;
                    }
                    break;
                case ADDR_P2WPKH:
                    if (decode_bech32_p2wpkh(tok, tlen, h.h)) {
                        pubkey_hashes.push_back(h);
                        ok_wpkh++; local_ok++; decoded = true;
                    }
                    break;
                case ADDR_P2SH:
                    if (decode_base58_address(tok, tlen, h.h, 0x05)) {
                        p2sh_hashes.push_back(h);
                        ok_p2sh++; local_ok++; decoded = true;
                    }
                    break;
                default: break;
            }
            if (!decoded && type != ADDR_UNKNOWN) failed++;
        }

        if (lines_read % 500000 == 0) {
            auto tn = std::chrono::high_resolution_clock::now();
            double el = std::chrono::duration<double>(tn-t0).count();
            printf("\r    %.1fM satir | %llu adres | %.1fs     ",
                lines_read/1e6, (unsigned long long)local_ok, el);
            fflush(stdout);
        }
    }
    fclose(fp);
    auto t1 = std::chrono::high_resolution_clock::now();
    double el = std::chrono::duration<double>(t1-t0).count();
    printf("\r    %s tamam: %llu adres (%.2fs)           \n",
        path, (unsigned long long)local_ok, el);
}

// ============================================================================
// Hash vektorunu sirala, dedupe et, .bin olarak yaz
// ============================================================================
static void write_bin(const char* path, std::vector<Hash160>& v) {
    if (v.empty()) {
        printf("[*] %s: bos, atlaniyor\n", path);
        return;
    }
    printf("[*] Siralaniyor: %s (%llu kayit)\n", path, (unsigned long long)v.size());
    std::sort(v.begin(), v.end());
    // Dedupe
    auto last = std::unique(v.begin(), v.end());
    size_t before = v.size();
    v.erase(last, v.end());
    size_t after = v.size();
    if (before != after) {
        printf("    Duplicate silindi: %llu -> %llu\n",
            (unsigned long long)before, (unsigned long long)after);
    }

    FILE* fp = fopen(path, "wb");
    if (!fp) { fprintf(stderr, "[HATA] %s yazilamadi\n", path); return; }
    uint64_t n = (uint64_t)v.size();
    fwrite(&n, sizeof(n), 1, fp);
    const size_t WBUF = 65536;
    for (size_t i = 0; i < v.size(); ) {
        size_t chunk = std::min(v.size()-i, WBUF);
        fwrite(v[i].h, 20, chunk, fp);
        i += chunk;
    }
    fclose(fp);
    printf("    %s yazildi: %.2f MB\n", path, (8.0 + n*20)/1e6);
}

// ============================================================================
// main
// ============================================================================
int main(int argc, char* argv[]) {
    const char* out_main = "database.bin";
    const char* out_p2sh = "database_p2sh.bin";
    std::vector<const char*> inputs;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-o") == 0 && i+1 < argc) out_main = argv[++i];
        else if (strcmp(argv[i], "-p2sh") == 0 && i+1 < argc) out_p2sh = argv[++i];
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printf("Kullanim: %s [-o database.bin] [-p2sh database_p2sh.bin] [csv1 csv2 ...]\n", argv[0]);
            return 0;
        }
        else inputs.push_back(argv[i]);
    }

    // Varsayilan CSV'ler (argsiz calistirilirsa otomatik bulunanlar alinir)
    if (inputs.empty()) {
        const char* defaults[] = {"adresler.csv", "bcq1.csv", "P2SH.csv"};
        for (auto* d : defaults) if (file_exists(d)) inputs.push_back(d);
        if (inputs.empty()) {
            fprintf(stderr, "[HATA] CSV girdisi yok. Varsayilan dosyalar bulunamadi: adresler.csv, bcq1.csv, P2SH.csv\n");
            return 1;
        }
    }

    printf("=============================================================\n");
    printf("  Bitcoin Hash160 Veritabani Olusturucu (v2: bech32 destekli)\n");
    printf("=============================================================\n");
    printf("  Cikti (P2PKH+P2WPKH) : %s\n", out_main);
    printf("  Cikti (P2SH)         : %s\n", out_p2sh);
    printf("  Girdi dosyalari      :\n");
    for (auto* p : inputs) printf("     - %s\n", p);
    printf("=============================================================\n");

    auto t0 = std::chrono::high_resolution_clock::now();

    std::vector<Hash160> pubkey_hashes;
    std::vector<Hash160> p2sh_hashes;
    pubkey_hashes.reserve(40000000);
    p2sh_hashes.reserve(5000000);

    uint64_t ok_pkh=0, ok_wpkh=0, ok_p2sh=0, failed=0;
    for (auto* path : inputs) {
        process_csv(path, pubkey_hashes, p2sh_hashes, ok_pkh, ok_wpkh, ok_p2sh, failed);
    }

    auto t_read = std::chrono::high_resolution_clock::now();
    double rs = std::chrono::duration<double>(t_read-t0).count();
    printf("\n[*] Tum CSV'ler okundu (%.2fs)\n", rs);
    printf("    P2PKH  (1...)   : %llu\n", (unsigned long long)ok_pkh);
    printf("    P2WPKH (bc1q..) : %llu\n", (unsigned long long)ok_wpkh);
    printf("    P2SH   (3...)   : %llu\n", (unsigned long long)ok_p2sh);
    if (failed) printf("    Basarisiz/atlandi: %llu\n", (unsigned long long)failed);

    if (pubkey_hashes.empty() && p2sh_hashes.empty()) {
        fprintf(stderr, "[HATA] Hic gecerli adres yok.\n");
        return 1;
    }

    // P2PKH ve P2WPKH ayni pubkey-hash havuzu — birlestirip yaz
    write_bin(out_main, pubkey_hashes);
    // P2SH ayri dosya (Phase 2 wrapped-segwit icin)
    write_bin(out_p2sh, p2sh_hashes);

    auto t_end = std::chrono::high_resolution_clock::now();
    double total = std::chrono::duration<double>(t_end-t0).count();
    printf("\n=============================================================\n");
    printf("  TAMAMLANDI (%.2f saniye)\n", total);
    printf("=============================================================\n");
    return 0;
}
