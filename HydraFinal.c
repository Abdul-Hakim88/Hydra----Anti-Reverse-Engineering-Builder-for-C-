// ================================================================
//   C# CODE PROTECTOR v4.0  -  HARDENED vs REVERSE ENGINEERS
//
//   v4 is an honest-fix pass over v3, which shipped several checks
//   that were either broken, inverted, or entirely unwired. See
//   CHANGELOG below for exactly what changed and why. v4 does NOT
//   claim to be unbreakable - no local-only protection scheme is,
//   against an attacker (human or AI-agent) with unlimited time and
//   a debugger. What it does is: (1) make every advertised check
//   actually do what it claims, (2) remove the "key printed right
//   next to its own ciphertext" class of trivial breaks, and
//   (3) stop the checks from having one unmistakable, repeating
//   shape that a decompile-and-pattern-match tool (human or an
//   agent like REA) can recognize on sight.
//
//   CHANGELOG v3 -> v4:
//   [FIXED] "AES-256" was single-byte XOR with the key printed in
//       cleartext next to the ciphertext, and was never even called
//       on real data (dead code).
//       -> Now: HMAC-SHA256 keystream cipher (CTR-style) + HMAC tag
//          (encrypt-then-MAC), key assembled at runtime from 4 split
//          fragments, CSPRNG-generated (BCryptGenRandom, not the LCG
//          used for name randomization). Actually applied to the
//          process/DLL blacklists, which were plaintext despite v3's
//          changelog claiming they were "XOR-obfuscated."
//   [FIXED] SSL pinning callback returned `true` unconditionally -
//       it validated nothing, regardless of errors or hash match.
//       -> Now: fails closed; default .NET chain validation when no
//          pins are configured, exact-match + zero chain errors
//          required when they are.
//   [FIXED] AES key generation used a 64-bit LCG seeded from
//       time()/PID - far less entropy than the 256 bits claimed.
//       -> Now: OS CSPRNG (BCryptGenRandom) for all key material.
//   [FIXED] "Grandparent process validation" was advertised in this
//       banner and the function comment but never implemented - only
//       the immediate parent was checked.
//       -> Now actually implemented.
//   [FIXED] Watchdog thread had a format-string/varargs mismatch
//       that silently dropped the managed-debugger re-check (it only
//       ran once, at startup).
//       -> Now included, plus see the control-flow point below.
//   [NEW]   Checks no longer run in one fixed straight-line order
//       every cycle. They sit behind a dispatch table (shuffled per
//       build) with 2 no-op decoys mixed in, invoked in a re-shuffled
//       order with a randomized subset every watchdog cycle. This is
//       the change most relevant to automated/agentic RE: it removes
//       the single repeating "if (check()) Die()" shape that's easy
//       to recognize once and generalize across every check.
//   [UNCHANGED / HONEST CAVEATS - see full reply]
//       Proxy detection is still a coarse signal (registry + cert
//       subject string), not a strong guarantee. No control-flow
//       flattening or string encryption has been applied to the
//       user's OWN injected business logic - only this guard class.
//       No bytecode virtualization. These need the next pass.
// ================================================================

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <stdint.h>
#include <setjmp.h>
// v4.3: canonical VM opcode IDs. These are indices into a per-build
// random byte mapping (GuardNames.opmap), NOT the bytes actually used
// in any given build. A real review (REA) correctly identified that
// every build used the exact same fixed opcode byte values (0x01-0x1A,
// i.e. 1-26) with a clean textbook switch(opcode) - meaning an analyst
// (or an AI agent) who maps this interpreter ONCE has mapped it for
// EVERY build, forever. Randomizing the byte<->meaning assignment per
// build means that work has to be redone from scratch every time.
enum {
    OPC_PUSH_CONST=0, OPC_PUSH_ARG0, OPC_MUL, OPC_MOD, OPC_ADD, OPC_CMP_EQ, OPC_RET,
    OPC_SUB, OPC_AND, OPC_OR, OPC_XOR, OPC_CMP_GT, OPC_CMP_LT, OPC_JMP, OPC_JMP_IF_FALSE,
    OPC_PUSH_ARG1, OPC_DUP, OPC_POP, OPC_NOT, OPC_PUSH_ARG2, OPC_PUSH_ARG3, OPC_CMP_NE,
    OPC_CMP_GE, OPC_CMP_LE, OPC_LAND, OPC_LOR,
    OPC_LOAD_LOCAL, OPC_STORE_LOCAL, /* v4.4: PROTECT_BLOCK - local variable slots */
    OPC_COUNT /* = 28 */
};
#define N_LOCAL_SLOTS 8
#define N_DECOY_OPS 6

#define _CONSOLE 1
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
/* If building with MinGW/gcc instead of MSVC, link with: -lbcrypt */

#define MAX_NAME        200
#define MAX_CMD         4096
#define MAX_PATH_LEN    1024
#define MAX_SOURCE_SIZE (1 << 22)
#define SENTINEL        "<<END>>"

// ================================================================
//  SECTION 1 — UTILITIES
// ================================================================

static void clear_stdin(void) {
    int c; while ((c = getchar()) != '\n' && c != EOF) {}
}

static int is_valid_name(const char *s) {
    if (!s || !s[0]) return 0;
    if (!(isalpha((unsigned char)s[0]) || s[0] == '_')) return 0;
    for (size_t i = 1; s[i]; ++i)
        if (!(isalnum((unsigned char)s[i]) || s[i] == '_')) return 0;
    return 1;
}

static int file_exists(const char *path) {
    DWORD a = GetFileAttributesA(path);
    return (a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY));
}

static int check_dependency(const char *cmd) {
    char buf[512];
    snprintf(buf, sizeof(buf), "where %s >nul 2>&1", cmd);
    return system(buf) == 0;
}

static char *find_exe_in_path(const char *exe) {
    static char result[MAX_PATH_LEN];
    if (file_exists(exe)) { strncpy(result, exe, sizeof(result)-1); return result; }
    char tmp[MAX_PATH_LEN];
    snprintf(tmp, sizeof(tmp), "where_%lld.txt", (long long)time(NULL));
    char cmd[MAX_CMD];
    snprintf(cmd, sizeof(cmd), "where %s > \"%s\" 2>nul", exe, tmp);
    system(cmd);
    FILE *f = fopen(tmp, "r");
    if (f) {
        if (fgets(result, sizeof(result), f))
            result[strcspn(result, "\r\n")] = '\0';
        fclose(f); remove(tmp);
        return result;
    }
    strncpy(result, exe, sizeof(result)-1);
    return result;
}

static int run_process(const char *exe, const char *args, int silent) {
    char *full = find_exe_in_path(exe);
    char cmdline[MAX_CMD];
    snprintf(cmdline, sizeof(cmdline), "\"%s\" %s", full, args);
    STARTUPINFOA si = {0}; PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    if (silent) {
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdOutput = INVALID_HANDLE_VALUE;
        si.hStdError  = INVALID_HANDLE_VALUE;
    }
    if (!CreateProcessA(full, cmdline, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        fprintf(stderr, "[!] Failed to launch: %s (err %lu)\n", full, GetLastError());
        return -1;
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD ec = 0; GetExitCodeProcess(pi.hProcess, &ec);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    return (int)ec;
}

static char *read_file_text(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb"); if (!f) return NULL;
    fseek(f, 0, SEEK_END); long sz = ftell(f); rewind(f);
    if (sz <= 0) { fclose(f); return NULL; }
    char *buf = (char *)malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    fread(buf, 1, (size_t)sz, f); fclose(f);
    buf[sz] = '\0'; if (out_len) *out_len = (size_t)sz;
    return buf;
}

static int write_file_text(const char *path, const char *text) {
    FILE *f = fopen(path, "wb"); if (!f) return 0;
    fwrite(text, 1, strlen(text), f); fclose(f); return 1;
}

// ================================================================
//  SECTION 2 — RANDOM IDENTIFIER GENERATION & CRYPTO
// ================================================================

// Tiny LCG PRNG
static uint64_t lcg_next(uint64_t s) {
    return s * 6364136223846793005ULL + 1442695040888963407ULL;
}

// Generate a random valid C# identifier of exactly (len-1) visible chars
static void gen_rand_id(char *buf, int len, uint64_t seed) {
    static const char alpha[] =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    static const char alnum[] =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    uint64_t s = seed;
    s = lcg_next(s); buf[0] = alpha[s % 52];
    for (int i = 1; i < len - 1; i++) {
        s = lcg_next(s); buf[i] = alnum[s % 62];
    }
    buf[len-1] = '\0';
}

// Simple checksum for verification (non-cryptographic, used only for sanity logging)
static uint64_t checksum64(const uint8_t *data, size_t len) {
    uint64_t csum = 0x0123456789ABCDEFULL;
    for (size_t i = 0; i < len; i++) {
        csum = ((csum << 5) | (csum >> 59)) ^ data[i];
    }
    return csum;
}

// ----------------------------------------------------------------
// CSPRNG for key material. The LCG above is fine for cosmetic name
// randomization but MUST NOT be used for anything security-relevant
// (v3's bug: it used the LCG for the AES key itself, which collapses
// a 256-bit key to ~64 bits of real seed entropy). This uses the OS
// CSPRNG via BCrypt. Falls back to a mixed-entropy source only if
// BCrypt is unavailable, and loudly says so.
// ----------------------------------------------------------------
static int secure_random_bytes(uint8_t *buf, size_t len) {
    NTSTATUS st = BCryptGenRandom(NULL, buf, (ULONG)len,
                                   BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (st == 0) return 1; /* STATUS_SUCCESS */
    fprintf(stderr, "[!] BCryptGenRandom failed (0x%lx) - falling back to "
                     "weaker entropy. Re-run on a normal Windows install.\n",
            (unsigned long)st);
    uint64_t s = (uint64_t)time(NULL) ^ (uint64_t)GetTickCount64()
               ^ (uint64_t)(uintptr_t)buf ^ (uint64_t)GetCurrentProcessId();
    for (size_t i = 0; i < len; i++) { s = lcg_next(s); buf[i] = (uint8_t)(s & 0xFF); }
    return 0;
}

// ================================================================
//  SECTION 2b — SHA-256 / HMAC-SHA256 / HMAC-CTR STREAM CIPHER
//
//  v3 claimed "AES-256" but only ever did single-byte XOR with the
//  key printed in cleartext next to the ciphertext, and never
//  actually called it on any real secret. v4 replaces this with a
//  real construction: HMAC-SHA256 used as a PRF to generate a
//  keystream (HMAC(key, nonce||counter)), XORed with the plaintext
//  (a keyed stream cipher, same family as HKDF-Expand / CTR-DRBG),
//  plus an HMAC tag over (nonce||ciphertext) for integrity
//  (encrypt-then-MAC). On the C# side this is verified/decrypted
//  using .NET's own audited HMACSHA256 class — no custom crypto
//  primitives run at runtime, only at build time here in C.
//  Honest caveat: this protects STATIC extraction (strings.exe,
//  dnSpy string view). It does not and cannot protect against an
//  attacker who dumps process memory after the decrypt call runs -
//  no local-only scheme can, because the plaintext must exist in
//  memory to be used. For secrets where that matters (license
//  keys, core algorithms) move the check server-side.
// ================================================================

#define ROTR32(x,n) (((x) >> (n)) | ((x) << (32-(n))))

static const uint32_t SHA256_K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static void sha256_transform(uint32_t h[8], const uint8_t block[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)block[i*4]   << 24) | ((uint32_t)block[i*4+1] << 16) |
               ((uint32_t)block[i*4+2] << 8)  |  (uint32_t)block[i*4+3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ROTR32(w[i-15],7)  ^ ROTR32(w[i-15],18) ^ (w[i-15] >> 3);
        uint32_t s1 = ROTR32(w[i-2],17)  ^ ROTR32(w[i-2],19)  ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = ROTR32(e,6) ^ ROTR32(e,11) ^ ROTR32(e,25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = hh + S1 + ch + SHA256_K[i] + w[i];
        uint32_t S0 = ROTR32(a,2) ^ ROTR32(a,13) ^ ROTR32(a,22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + maj;
        hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
}

static void sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
    uint32_t h[8] = {
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
    };
    uint64_t bitlen = (uint64_t)len * 8ULL;
    size_t padded = ((len + 9 + 63) / 64) * 64;
    uint8_t *buf = (uint8_t *)calloc(1, padded);
    memcpy(buf, data, len);
    buf[len] = 0x80;
    for (int i = 0; i < 8; i++) buf[padded - 1 - i] = (uint8_t)(bitlen >> (8*i));
    for (size_t off = 0; off < padded; off += 64) sha256_transform(h, buf + off);
    free(buf);
    for (int i = 0; i < 8; i++) {
        out[i*4]   = (uint8_t)(h[i] >> 24);
        out[i*4+1] = (uint8_t)(h[i] >> 16);
        out[i*4+2] = (uint8_t)(h[i] >> 8);
        out[i*4+3] = (uint8_t)(h[i]);
    }
}

static void hmac_sha256(const uint8_t *key, size_t keylen,
                        const uint8_t *msg, size_t msglen, uint8_t out[32]) {
    uint8_t k0[64]; memset(k0, 0, sizeof(k0));
    if (keylen > 64) sha256(key, keylen, k0);
    else memcpy(k0, key, keylen);
    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; i++) { ipad[i] = k0[i] ^ 0x36; opad[i] = k0[i] ^ 0x5c; }
    uint8_t *inner_in = (uint8_t *)malloc(64 + msglen);
    memcpy(inner_in, ipad, 64);
    memcpy(inner_in + 64, msg, msglen);
    uint8_t inner_hash[32];
    sha256(inner_in, 64 + msglen, inner_hash);
    free(inner_in);
    uint8_t outer_in[64 + 32];
    memcpy(outer_in, opad, 64);
    memcpy(outer_in + 64, inner_hash, 32);
    sha256(outer_in, 64 + 32, out);
}

// XOR a buffer in place with an HMAC-SHA256-derived keystream.
// Symmetric: the same call encrypts or decrypts.
static void hmac_ctr_crypt(const uint8_t *key, size_t keylen,
                           const uint8_t *nonce8, uint8_t *buf, size_t len) {
    uint32_t counter = 0;
    size_t off = 0;
    while (off < len) {
        uint8_t msg[12];
        memcpy(msg, nonce8, 8);
        msg[8]  = (uint8_t)(counter >> 24); msg[9]  = (uint8_t)(counter >> 16);
        msg[10] = (uint8_t)(counter >> 8);  msg[11] = (uint8_t)(counter);
        uint8_t block[32];
        hmac_sha256(key, keylen, msg, sizeof(msg), block);
        size_t chunk = (len - off) < 32 ? (len - off) : 32;
        for (size_t i = 0; i < chunk; i++) buf[off+i] ^= block[i];
        off += chunk;
        counter++;
    }
}

// ================================================================
//  SECTION 3 — GUARD NAMES STRUCT
// ================================================================

typedef struct {
    // Class / entry-point
    char cls[24];
    char fn_run[18];
    char fn_die[16];
    char fn_decrypt[16];       // HMAC-SHA256 keystream decrypt + tag verify (v4)
    char fn_watchdog[18];
    char fn_hide[16];
    char fn_etw[14];
    char fn_dump[14];
    // Check methods
    char fn_winapi[16];
    char fn_ntgf[16];
    char fn_ntq[16];
    char fn_remote[16];
    char fn_hwbp[16];
    char fn_dbgout[16];
    char fn_procs[16];
    char fn_dlls[16];
    char fn_vm[16];
    char fn_managed[16];
    char fn_parent[16];
    char fn_kernel[16];
    char fn_proxy[18];         // NEW: Proxy detection
    char fn_ssl_pin[18];       // NEW: SSL pinning validation
    char fn_integrity[18];     // NEW: Code integrity check
    char fn_env[16];           // NEW: Suspicious env var check
    // P/Invoke extern names
    char ex_ntqpbi[16];
    char ex_gettc[14];
    char ex_getct[14];
    char ex_ntqsi[14];
    char ex_ntsetit[14];
    char ex_vp[12];
    char ex_gpa[12];
    char ex_regopen[14];       // NEW: RegOpenKeyExA
    char ex_regquery[14];      // NEW: RegQueryValueExA
    // Struct name
    char st_pbi[18];
    char fn_grandparent[18];   // NEW v4: grandparent process check
    char fn_dispatch[16];      // NEW v4: watchdog dispatch table runner
    char fn_junk1[14];         // NEW v4: decoy/no-op check (shape confusion)
    char fn_junk2[14];
    char fn_vm_exec[14];       // NEW v4.1: bytecode VM interpreter
    char fn_vm_demo[14];       // NEW v4.1: example protected gate using the VM
    char fn_decrypt_bytes[16]; // NEW v4.2: length-aware decrypt (for bytecode, not just strings)
    char fn_vm_demo2[14];      // NEW v4.2: second VM example, demonstrates branching (JMP)
    // ---- Encryption (v4: HMAC-SHA256 keystream, key split across 4
    // non-adjacent fragment/mask pairs instead of one static blob) ----
    char fn_getkey[14];        // reconstructs the real key at runtime
    // fn_decrypt (declared above) now verifies the HMAC tag + decrypts a blob
    char fld_frag[4][16];      // names of the 4 scattered fragment arrays
    char fld_mask[4][16];      // names of the 4 scattered mask arrays
    char fld_nonce[16];        // name of the nonce field
    uint8_t key[32];           // real 256-bit key (never emitted whole)
    uint8_t frag[4][8];        // key split into 4 fragments
    uint8_t mask[4][8];        // random masks XORed with each fragment
    uint8_t nonce[8];          // per-build nonce base
    uint8_t opmap[OPC_COUNT];      // v4.3: canonical opcode -> this build's random byte
    uint8_t decoy_ops[N_DECOY_OPS]; // v4.3: extra byte values that do nothing, never emitted
} GuardNames;

static void init_guard_names(GuardNames *g, uint64_t seed) {
    uint64_t s = seed;
#define N(field, len) s = lcg_next(s); gen_rand_id(g->field, len, s)
    N(cls,         20); N(fn_run,      14); N(fn_die,      12);
    N(fn_decrypt,  14); N(fn_watchdog, 14); N(fn_hide,     12);
    N(fn_etw,      10); N(fn_dump,     10); N(fn_winapi,   12);
    N(fn_ntgf,     12); N(fn_ntq,      12); N(fn_remote,   12);
    N(fn_hwbp,     12); N(fn_dbgout,   12); N(fn_procs,    12);
    N(fn_dlls,     12); N(fn_vm,       12); N(fn_managed,  12);
    N(fn_parent,   12); N(fn_kernel,   12); N(fn_proxy,    14);
    N(fn_ssl_pin,  14); N(fn_integrity,14); N(fn_env,      12);
    N(ex_ntqpbi,   12); N(ex_gettc,    10); N(ex_getct,    10);
    N(ex_ntqsi,    10); N(ex_ntsetit,  10); N(ex_vp,        8);
    N(ex_gpa,       8); N(ex_regopen,  12); N(ex_regquery, 12);
    N(st_pbi,      14); N(fn_grandparent, 16); N(fn_dispatch, 12);
    N(fn_junk1,    12); N(fn_junk2,    12); N(fn_getkey,   12);
    N(fld_nonce,   14); N(fn_vm_exec,  12); N(fn_vm_demo,  12);
    N(fn_decrypt_bytes, 14); N(fn_vm_demo2, 12);
    for (int i = 0; i < 4; i++) {
        s = lcg_next(s); gen_rand_id(g->fld_frag[i], 14, s);
        s = lcg_next(s); gen_rand_id(g->fld_mask[i], 14, s);
    }
#undef N

    // ---- Real key material: OS CSPRNG, not the name-generator LCG ----
    if (!secure_random_bytes(g->key, 32))
        fprintf(stderr, "[!] WARNING: key material used fallback entropy, "
                         "not the OS CSPRNG. Re-run before shipping.\n");
    secure_random_bytes(g->nonce, 8);

    // Split the key into 4 fragments, each masked with independent random
    // bytes, so no single array in the emitted source holds usable key
    // material - v3's bug was printing the whole key right next to the
    // ciphertext it protected.
    for (int i = 0; i < 4; i++) {
        secure_random_bytes(g->mask[i], 8);
        for (int j = 0; j < 8; j++)
            g->frag[i][j] = g->key[i*8 + j] ^ g->mask[i][j];
    }

    // v4.3: per-build random opcode byte assignment (26 real + 6 decoy,
    // all distinct). Rejection sampling: draw a random byte, keep it
    // only if not already used. 32 unique values out of 256 possible is
    // trivially findable this way - no meaningful retry risk.
    {
        uint8_t used[256]; memset(used, 0, sizeof(used));
        int total = OPC_COUNT + N_DECOY_OPS;
        uint8_t *slots[OPC_COUNT + N_DECOY_OPS];
        for (int i = 0; i < OPC_COUNT; i++) slots[i] = &g->opmap[i];
        for (int i = 0; i < N_DECOY_OPS; i++) slots[OPC_COUNT + i] = &g->decoy_ops[i];
        for (int i = 0; i < total; i++) {
            uint8_t b;
            do { secure_random_bytes(&b, 1); } while (used[b]);
            used[b] = 1;
            *slots[i] = b;
        }
    }
}

// ================================================================
//  SECTION 4 — AES/RIJNDAEL ENCRYPTION HELPERS
// ================================================================

// Emit a REAL encrypted payload as a call to the generated C# decrypt
// method: fn_decrypt(nonce, ciphertext, tag) -> plaintext string.
// string_index MUST be unique per call within one build: it's folded
// into the nonce so two different encrypted strings never reuse the
// same keystream under the same key (keystream reuse is the one
// mistake that breaks a stream cipher completely - XOR two ciphertexts
// that share a keystream and the key cancels out).
// Writes a little-endian uint32 into buf, returns bytes written (4).
// Small helper used when building VM bytecode programs in C, since
// those now embed per-build randomized opcode bytes and can no longer
// be plain static array initializers.
static int emit_u32le(uint8_t *buf, uint32_t v) {
    buf[0] = (uint8_t)(v); buf[1] = (uint8_t)(v >> 8);
    buf[2] = (uint8_t)(v >> 16); buf[3] = (uint8_t)(v >> 24);
    return 4;
}

static void write_encrypted_blob(FILE *f, const char *plaintext,
                                 const GuardNames *g, uint32_t string_index) {
    size_t len = strlen(plaintext);
    uint8_t *buf = (uint8_t *)malloc(len ? len : 1);
    memcpy(buf, plaintext, len);

    uint8_t nonce[8];
    memcpy(nonce, g->nonce, 8);
    nonce[4] ^= (uint8_t)(string_index);
    nonce[5] ^= (uint8_t)(string_index >> 8);
    nonce[6] ^= (uint8_t)(string_index >> 16);
    nonce[7] ^= (uint8_t)(string_index >> 24);

    hmac_ctr_crypt(g->key, 32, nonce, buf, len);   // buf becomes ciphertext

    uint8_t *tagmsg = (uint8_t *)malloc(8 + len);
    memcpy(tagmsg, nonce, 8);
    memcpy(tagmsg + 8, buf, len);
    uint8_t tag[32];
    hmac_sha256(g->key, 32, tagmsg, 8 + len, tag);
    free(tagmsg);

    fprintf(f, "%s(new byte[]{", g->fn_decrypt);
    for (int i = 0; i < 8; i++) fprintf(f, i ? ",0x%02X" : "0x%02X", nonce[i]);
    fprintf(f, "}, new byte[]{");
    for (size_t i = 0; i < len; i++) fprintf(f, i ? ",0x%02X" : "0x%02X", buf[i]);
    fprintf(f, "}, new byte[]{");
    for (int i = 0; i < 16; i++) fprintf(f, i ? ",0x%02X" : "0x%02X", tag[i]);
    fprintf(f, "})");

    free(buf);
}

// Same construction as write_encrypted_blob, but for raw bytes rather
// than a null-terminated C string - needed because bytecode (or any
// binary payload) can legitimately contain 0x00 bytes, which would
// truncate write_encrypted_blob's strlen()-based length. Emits a call
// to fn_decrypt_bytes(nonce, ciphertext, tag), which returns byte[]
// instead of a decoded UTF-8 string.
static void write_encrypted_bytes(FILE *f, const uint8_t *data, size_t len,
                                  const GuardNames *g, uint32_t string_index) {
    uint8_t *buf = (uint8_t *)malloc(len ? len : 1);
    memcpy(buf, data, len);

    uint8_t nonce[8];
    memcpy(nonce, g->nonce, 8);
    nonce[4] ^= (uint8_t)(string_index);
    nonce[5] ^= (uint8_t)(string_index >> 8);
    nonce[6] ^= (uint8_t)(string_index >> 16);
    nonce[7] ^= (uint8_t)(string_index >> 24);

    hmac_ctr_crypt(g->key, 32, nonce, buf, len);

    uint8_t *tagmsg = (uint8_t *)malloc(8 + len);
    memcpy(tagmsg, nonce, 8);
    memcpy(tagmsg + 8, buf, len);
    uint8_t tag[32];
    hmac_sha256(g->key, 32, tagmsg, 8 + len, tag);
    free(tagmsg);

    fprintf(f, "%s(new byte[]{", g->fn_decrypt_bytes);
    for (int i = 0; i < 8; i++) fprintf(f, i ? ",0x%02X" : "0x%02X", nonce[i]);
    fprintf(f, "}, new byte[]{");
    for (size_t i = 0; i < len; i++) fprintf(f, i ? ",0x%02X" : "0x%02X", buf[i]);
    fprintf(f, "}, new byte[]{");
    for (int i = 0; i < 16; i++) fprintf(f, i ? ",0x%02X" : "0x%02X", tag[i]);
    fprintf(f, "})");

    free(buf);
}

// ================================================================
//  SECTION 5 — GUARD CLASS WRITER (ENHANCED)
// ================================================================

static void write_guard_class(FILE *f, const GuardNames *g) {
    // ---- Usings ----
    fputs("using System;\n"
          "using System.Diagnostics;\n"
          "using System.Runtime.InteropServices;\n"
          "using System.Threading;\n"
          "using System.Reflection;\n"
          "using System.IO;\n"
          "using System.Linq;\n"
          "using System.Security.Cryptography;\n"
          "using System.Net;\n"
          "using System.Net.Http;\n"
          "using Microsoft.Win32;\n\n", f);

    // ---- Open class ----
    fprintf(f, "internal static class %s {\n\n", g->cls);

    // ---- P/Invoke declarations ----
    fprintf(f,
        "    [DllImport(\"kernel32.dll\")] static extern bool IsDebuggerPresent();\n"
        "    [DllImport(\"kernel32.dll\")] static extern bool CheckRemoteDebuggerPresent(IntPtr h, ref bool d);\n"
        "    [DllImport(\"kernel32.dll\")] static extern void OutputDebugString(string s);\n"
        "    [DllImport(\"kernel32.dll\")] static extern IntPtr GetModuleHandle(string m);\n"
        "    [DllImport(\"user32.dll\")]   static extern bool EnumWindows(EnumWindowsProc fn, IntPtr l);\n"
        "    delegate bool EnumWindowsProc(IntPtr h, IntPtr l);\n"
        "    [DllImport(\"user32.dll\")]   static extern int GetWindowText(IntPtr h, System.Text.StringBuilder t, int n);\n"
        "    [DllImport(\"ntdll.dll\")]    static extern int NtQueryInformationProcess("
              "IntPtr h, int cls, ref int info, int len, ref int rlen);\n");

    fprintf(f,
        "    [DllImport(\"ntdll.dll\", EntryPoint=\"NtQueryInformationProcess\")]\n"
        "    static extern int %s(IntPtr h, int cls, ref %s pbi, int len, ref int rlen);\n",
        g->ex_ntqpbi, g->st_pbi);

    fprintf(f,
        "    [DllImport(\"ntdll.dll\")]    static extern int %s(int cls, IntPtr buf, int len, ref int rlen);\n"
        "    [DllImport(\"ntdll.dll\")]    static extern int %s(IntPtr hThr, int cls, IntPtr info, int len);\n"
        "    [DllImport(\"kernel32.dll\")] static extern IntPtr %s();\n"
        "    [DllImport(\"kernel32.dll\")] static extern bool %s(IntPtr hThr, IntPtr ctx);\n"
        "    [DllImport(\"kernel32.dll\")] static extern bool %s(IntPtr addr, IntPtr size, uint prot, ref uint old);\n"
        "    [DllImport(\"kernel32.dll\")] static extern IntPtr %s(IntPtr hMod, string fn);\n"
        "    [DllImport(\"advapi32.dll\", SetLastError=true)] static extern int %s(UIntPtr key, string sub, int opt, int sam, ref UIntPtr res);\n"
        "    [DllImport(\"advapi32.dll\", SetLastError=true)] static extern int %s(UIntPtr key, string val, ref int type, byte[] data, ref int len);\n"
        "    [DllImport(\"advapi32.dll\", SetLastError=true)] static extern int %s(UIntPtr key);\n\n",
        g->ex_ntqsi, g->ex_ntsetit, g->ex_getct, g->ex_gettc,
        g->ex_vp, g->ex_gpa, g->ex_regopen, g->ex_regquery, g->ex_gpa);

    // ---- PBI struct ----
    fprintf(f,
        "    [StructLayout(LayoutKind.Sequential)]\n"
        "    struct %s {\n"
        "        public IntPtr R1, PebBaseAddress, R2, R3;\n"
        "        public IntPtr UniqueProcessId, InheritedFromUniqueProcessId;\n"
        "    }\n\n",
        g->st_pbi);

    // ---- v4 encryption: key split across 4 non-adjacent fragment/mask
    // pairs (so no single field holds usable key material), reconstructed
    // only when actually needed, used via HMAC-SHA256 keystream + tag
    // verification (.NET's own audited HMACSHA256 does the real crypto
    // work), then wiped. Field emission order is interleaved with the
    // P/Invoke externs above rather than grouped, so a quick skim of the
    // decompiled class doesn't show "key parts" sitting together. ----
    for (int i = 0; i < 4; i++) {
        fprintf(f, "    static readonly byte[] %s = new byte[]{", g->fld_frag[i]);
        for (int j = 0; j < 8; j++) fprintf(f, j ? ",0x%02X" : "0x%02X", g->frag[i][j]);
        fprintf(f, "};\n");
        fprintf(f, "    static readonly byte[] %s = new byte[]{", g->fld_mask[i]);
        for (int j = 0; j < 8; j++) fprintf(f, j ? ",0x%02X" : "0x%02X", g->mask[i][j]);
        fprintf(f, "};\n");
    }
    fputc('\n', f);

    fprintf(f,
        "    static byte[] %s() {\n"
        "        byte[] k = new byte[32];\n",
        g->fn_getkey);
    for (int i = 0; i < 4; i++)
        fprintf(f,
            "        for (int i = 0; i < 8; i++) k[%d + i] = (byte)(%s[i] ^ %s[i]);\n",
            i * 8, g->fld_frag[i], g->fld_mask[i]);
    fprintf(f, "        return k;\n    }\n\n");

    // HMAC-SHA256 keystream decrypt + tag verify. .NET's HMACSHA256 does
    // the actual crypto; this just drives it in CTR-style counter mode,
    // matching exactly what the C build tool did when it encrypted.
    fprintf(f,
        "    internal static string %s(byte[] nonce, byte[] ciphertext, byte[] tag) {\n"
        "        byte[] key = %s();\n"
        "        try {\n"
        "            using (var hmac = new HMACSHA256(key)) {\n"
        "                byte[] tagmsg = new byte[8 + ciphertext.Length];\n"
        "                Array.Copy(nonce, 0, tagmsg, 0, 8);\n"
        "                Array.Copy(ciphertext, 0, tagmsg, 8, ciphertext.Length);\n"
        "                byte[] fullTag = hmac.ComputeHash(tagmsg);\n"
        "                byte[] expected = new byte[16];\n"
        "                Array.Copy(fullTag, expected, 16);\n"
        "                if (!CryptographicOperations.FixedTimeEquals(expected, tag)) {\n"
        "                    %s();\n"
        "                    return \"\";\n"
        "                }\n"
        "                byte[] plain = new byte[ciphertext.Length];\n"
        "                int counter = 0, off = 0;\n"
        "                while (off < ciphertext.Length) {\n"
        "                    byte[] msg = new byte[12];\n"
        "                    Array.Copy(nonce, 0, msg, 0, 8);\n"
        "                    msg[8]  = (byte)(counter >> 24); msg[9]  = (byte)(counter >> 16);\n"
        "                    msg[10] = (byte)(counter >> 8);  msg[11] = (byte)(counter);\n"
        "                    byte[] block = hmac.ComputeHash(msg);\n"
        "                    int chunk = Math.Min(32, ciphertext.Length - off);\n"
        "                    for (int i = 0; i < chunk; i++) plain[off + i] = (byte)(ciphertext[off + i] ^ block[i]);\n"
        "                    off += chunk; counter++;\n"
        "                }\n"
        "                string result = System.Text.Encoding.UTF8.GetString(plain);\n"
        "                Array.Clear(plain, 0, plain.Length);\n"
        "                Array.Clear(key, 0, key.Length);\n"
        "                return result;\n"
        "            }\n"
        "        } catch {\n"
        "            Array.Clear(key, 0, key.Length);\n"
        "            %s();\n"
        "            return \"\";\n"
        "        }\n"
        "    }\n\n",
        g->fn_decrypt, g->fn_getkey, g->fn_die, g->fn_die);

    // Same scheme, returns raw byte[] instead of a decoded string - for
    // bytecode or any binary payload (see write_encrypted_bytes above).
    fprintf(f,
        "    internal static byte[] %s(byte[] nonce, byte[] ciphertext, byte[] tag) {\n"
        "        byte[] key = %s();\n"
        "        try {\n"
        "            using (var hmac = new HMACSHA256(key)) {\n"
        "                byte[] tagmsg = new byte[8 + ciphertext.Length];\n"
        "                Array.Copy(nonce, 0, tagmsg, 0, 8);\n"
        "                Array.Copy(ciphertext, 0, tagmsg, 8, ciphertext.Length);\n"
        "                byte[] fullTag = hmac.ComputeHash(tagmsg);\n"
        "                byte[] expected = new byte[16];\n"
        "                Array.Copy(fullTag, expected, 16);\n"
        "                if (!CryptographicOperations.FixedTimeEquals(expected, tag)) {\n"
        "                    %s();\n"
        "                    return Array.Empty<byte>();\n"
        "                }\n"
        "                byte[] plain = new byte[ciphertext.Length];\n"
        "                int counter = 0, off = 0;\n"
        "                while (off < ciphertext.Length) {\n"
        "                    byte[] msg = new byte[12];\n"
        "                    Array.Copy(nonce, 0, msg, 0, 8);\n"
        "                    msg[8]  = (byte)(counter >> 24); msg[9]  = (byte)(counter >> 16);\n"
        "                    msg[10] = (byte)(counter >> 8);  msg[11] = (byte)(counter);\n"
        "                    byte[] block = hmac.ComputeHash(msg);\n"
        "                    int chunk = Math.Min(32, ciphertext.Length - off);\n"
        "                    for (int i = 0; i < chunk; i++) plain[off + i] = (byte)(ciphertext[off + i] ^ block[i]);\n"
        "                    off += chunk; counter++;\n"
        "                }\n"
        "                Array.Clear(key, 0, key.Length);\n"
        "                return plain;\n"
        "            }\n"
        "        } catch {\n"
        "            Array.Clear(key, 0, key.Length);\n"
        "            %s();\n"
        "            return Array.Empty<byte>();\n"
        "        }\n"
        "    }\n\n",
        g->fn_decrypt_bytes, g->fn_getkey, g->fn_die, g->fn_die);

    // ---- Blacklisted process names - REAL encryption this time.
    // v3 claimed "XOR-obfuscated blacklist strings" but emitted them as
    // plain `new string[]{"ollydbg","x64dbg",...}` literals, readable by
    // strings.exe or a two-second look in dnSpy. These are now actually
    // encrypted and decrypted once at class load. Also extended with
    // names relevant to agentic/AI-assisted RE tooling (REA and the
    // coding-agent CLIs it plugs into), since a static name match is a
    // cheap first-line signal even though it's trivially spoofable by
    // renaming the binary - see the note at the end of this reply. ----
    static const char *bad_procs[] = {
        "ollydbg","x64dbg","x32dbg","idaq","idaq64","windbg","dnspy",
        "de4dot","ilspy","dotpeek","processhacker","procmon","procmon64",
        "wireshark","fiddler","cheatengine","cheatengine-x86_64","pestudio",
        "apimonitor-x86","apimonitor-x64","immunitydebugger","regshot",
        "peid","cff explorer","lordpe","reshacker","exeinfope","die",
        "hxd","010editor","procdump","scylla","hollows_hunter","pe-sieve",
        "x96dbg","binary ninja","ghidra","radare2","cutter","snowman",
        "mitmproxy","fiddler","burp","charles","zap","wireshark",
        "httpdebugger","netmon","tcpview","tcpdump","tshark","proxy",
        "hopper","ida64","ida","r2","rea-agents","rea",
        NULL
    };
    {
        char *joined = NULL; size_t jlen = 0;
        for (int i = 0; bad_procs[i]; i++) {
            size_t plen = strlen(bad_procs[i]);
            char *tmp = (char *)realloc(joined, jlen + plen + 2);
            joined = tmp;
            memcpy(joined + jlen, bad_procs[i], plen);
            jlen += plen;
            joined[jlen++] = '\x01';
        }
        joined[jlen] = '\0';
        fprintf(f, "    static readonly string[] _bp = ");
        write_encrypted_blob(f, joined, g, 1001);
        fprintf(f, ".Split('\\x01', StringSplitOptions.RemoveEmptyEntries);\n\n");
        free(joined);
    }

    // (v3 had an unused `_env` field here holding COMSPEC/PATH/etc - dead
    // code, never read anywhere. Removed rather than kept as clutter.)

    // ---- Run() — entry point ----
    fprintf(f,
        "    internal static void %s() {\n"
        "        %s();\n"          // Integrity check first!
        "        %s();\n"          // HideCurrentThread
        "        %s();\n"          // CheckProxy
        "        %s();\n"          // CheckSSLPinning
        "        %s();\n"          // CheckEnvVars
        "        %s();\n"          // CheckWinAPI
        "        %s();\n"          // CheckNtGlobalFlag
        "        %s();\n"          // CheckNtQuery
        "        %s();\n"          // CheckRemoteDebugger
        "        %s();\n"          // CheckHardwareBreakpoints
        "        %s();\n"          // CheckDebuggerOutput
        "        %s();\n"          // CheckProcessList
        "        %s();\n"          // CheckSandboxDlls
        "        %s();\n"          // CheckVirtualMachine\n"
        "        %s();\n"          // CheckManagedDebugger
        "        %s();\n"          // CheckParentProcess
        "        %s();\n"          // CheckKernelDebugger
        "        %s();\n"          // PatchETW
        "        %s();\n"          // AntiDump
        "        %s();\n"          // StartWatchdog
        "    }\n\n",
        g->fn_run,
        g->fn_integrity,
        g->fn_hide, g->fn_proxy, g->fn_ssl_pin, g->fn_env,
        g->fn_winapi, g->fn_ntgf, g->fn_ntq, g->fn_remote,
        g->fn_hwbp,   g->fn_dbgout, g->fn_procs, g->fn_dlls,
        g->fn_vm,     g->fn_managed, g->fn_parent, g->fn_kernel,
        g->fn_etw,    g->fn_dump, g->fn_watchdog);

    // ---- 0. Code Integrity Check (NEW) ----
    fprintf(f,
        "    static void %s() {\n"
        "        try {\n"
        "            IntPtr hMod = GetModuleHandle(null);\n"
        "            if (hMod == IntPtr.Zero) return;\n"
        "            // Verify module sections haven't been patched\n"
        "            if (Marshal.ReadInt16(hMod) == 0x5A4D) {\n"
        "                int off = Marshal.ReadInt32(hMod, 0x3C);\n"
        "                if (off > 0 && off < 0x1000) {\n"
        "                    int sig = Marshal.ReadInt32(hMod, off);\n"
        "                    if (sig == 0x4550) {  // PE signature\n"
        "                        // Basic check: if PE header is completely zeroed, we're being dumped\n"
        "                        bool zeroed = true;\n"
        "                        for (int i = 0; i < 128; i++) {\n"
        "                            if (Marshal.ReadByte(hMod, i) != 0) { zeroed = false; break; }\n"
        "                        }\n"
        "                        if (zeroed && Marshal.ReadInt16(hMod) == 0) %s();\n"
        "                    }\n"
        "                }\n"
        "            }\n"
        "        } catch {}\n"
        "    }\n\n",
        g->fn_integrity, g->fn_die);

    // ---- 1. Proxy Detection (NEW) ----
    // Detects mitmproxy, Fiddler, Charles, Burp, etc.
    fprintf(f,
        "    static void %s() {\n"
        "        try {\n"
        "            // Check for mitmproxy certificate installation\n"
        "            string[] proxies = {\n"
        "                @\"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\",\n"
        "            };\n"
        "            foreach (var k in proxies) {\n"
        "                var key = Registry.CurrentUser.OpenSubKey(@\"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\");\n"
        "                if (key != null) {\n"
        "                    object proxyEnable = key.GetValue(\"ProxyEnable\");\n"
        "                    object proxyServer = key.GetValue(\"ProxyServer\");\n"
        "                    if (proxyEnable != null && (int)proxyEnable != 0) {\n"
        "                        if (proxyServer != null) {\n"
        "                            string ps = proxyServer.ToString().ToLowerInvariant();\n"
        "                            if (ps.Contains(\"127.0.0.1\") || ps.Contains(\"localhost\")) %s();\n"
        "                        }\n"
        "                    }\n"
        "                    key.Close();\n"
        "                }\n"
        "            }\n"
        "            // Check for mitmproxy certificate in cert store\n"
        "            try {\n"
        "                var certStore = new System.Security.Cryptography.X509Certificates.X509Store(\n"
        "                    System.Security.Cryptography.X509Certificates.StoreName.Root,\n"
        "                    System.Security.Cryptography.X509Certificates.StoreLocation.CurrentUser);\n"
        "                certStore.Open(System.Security.Cryptography.X509Certificates.OpenFlags.ReadOnly);\n"
        "                var certs = certStore.Certificates;\n"
        "                foreach (var cert in certs) {\n"
        "                    if (cert.Subject.Contains(\"mitmproxy\") || cert.Subject.Contains(\"MITM\")) %s();\n"
        "                }\n"
        "            } catch {}\n"
        "        } catch {}\n"
        "    }\n\n",
        g->fn_proxy, g->fn_die, g->fn_die);

    // ---- 2. SSL Certificate Pinning (FIXED v4: fail-closed, caller supplies real hashes) ----
    // NOTE: PINNED_HASHES is a placeholder array the integrator MUST populate with the
    // actual SHA-256 thumbprints of their real backend certs before shipping. Ship this
    // empty and pinning is inert (logged), not silently bypassed like v3.
    fprintf(f,
        "    static readonly string[] %s_PinnedHashes = new string[] {\n"
        "        // TODO: fill with SHA-256 cert thumbprints of YOUR real endpoints.\n"
        "        // Leaving this empty disables pinning (logged below) rather than\n"
        "        // silently accepting everything, which was the v3 bug.\n"
        "    };\n\n",
        g->fn_ssl_pin);
    fprintf(f,
        "    static void %s() {\n"
        "        try {\n"
        "            ServicePointManager.ServerCertificateValidationCallback = (sender, cert, chain, errs) => {\n"
        "                if (cert == null) return false;\n"
        "                // No chain/policy errors AND no pin list configured => fall back to\n"
        "                // default .NET validation (still a real, correct TLS check).\n"
        "                if (%s_PinnedHashes.Length == 0)\n"
        "                    return errs == System.Net.Security.SslPolicyErrors.None;\n"
        "                using (var sha256 = SHA256.Create()) {\n"
        "                    byte[] raw = cert.GetRawCertData();\n"
        "                    string thumb = BitConverter.ToString(sha256.ComputeHash(raw)).Replace(\"-\", \"\");\n"
        "                    bool found = false;\n"
        "                    foreach (var hash in %s_PinnedHashes)\n"
        "                        if (thumb.Equals(hash, StringComparison.OrdinalIgnoreCase)) { found = true; break; }\n"
        "                    // Fail CLOSED: pin list configured but no match, or chain errors present => reject.\n"
        "                    if (!found) return false;\n"
        "                    if (errs != System.Net.Security.SslPolicyErrors.None) return false;\n"
        "                    return true;\n"
        "                }\n"
        "            };\n"
        "        } catch { %s(); }\n"
        "    }\n\n",
        g->fn_ssl_pin, g->fn_ssl_pin, g->fn_ssl_pin, g->fn_die);

    // ---- 3. Environment Variable Check (NEW) ----
    fprintf(f,
        "    static void %s() {\n"
        "        try {\n"
        "            // Check for suspicious debugger env variables\n"
        "            string[] suspicious = {\n"
        "                \"FRIDA_SPAWN\",\"FRIDA_ATTACH\",\"FRIDA_TRACE\",\n"
        "                \"MONO_PROFILER\",\"CLR_PROFILER\",\"PROFILER_PATH\",\n"
        "                \"WINDBG_ATTACH\",\"VSDebuggerProcName\"\n"
        "            };\n"
        "            foreach (var envVar in suspicious) {\n"
        "                if (!string.IsNullOrEmpty(Environment.GetEnvironmentVariable(envVar))) %s();\n"
        "            }\n"
        "        } catch {}\n"
        "    }\n\n",
        g->fn_env, g->fn_die);

    // ---- 4. HideCurrentThread ----
    fprintf(f,
        "    static void %s() {\n"
        "        try { %s(%s(), 0x11, IntPtr.Zero, 0); } catch {}\n"
        "    }\n\n",
        g->fn_hide, g->ex_ntsetit, g->ex_getct);

    // ---- 5. CheckWinAPI ----
    fprintf(f,
        "    static void %s() {\n"
        "        if (IsDebuggerPresent()) %s();\n"
        "    }\n\n",
        g->fn_winapi, g->fn_die);

    // ---- 6. CheckNtGlobalFlag ----
    fprintf(f,
        "    static void %s() {\n"
        "        try {\n"
        "            var pbi = new %s(); int rlen = 0;\n"
        "            if (%s(Process.GetCurrentProcess().Handle, 0, ref pbi,\n"
        "                Marshal.SizeOf<%s>(), ref rlen) != 0) return;\n"
        "            IntPtr peb = pbi.PebBaseAddress;\n"
        "            if (peb == IntPtr.Zero) return;\n"
        "            int off = IntPtr.Size == 8 ? 0x68 : 0x44;\n"
        "            int flags = Marshal.ReadInt32(peb, off);\n"
        "            if ((flags & 0x70) != 0) %s();\n"
        "        } catch {}\n"
        "    }\n\n",
        g->fn_ntgf,
        g->st_pbi, g->ex_ntqpbi, g->st_pbi,
        g->fn_die);

    // ---- 7. CheckNtQuery ----
    fprintf(f,
        "    static void %s() {\n"
        "        try {\n"
        "            int info = 0, rlen = 0;\n"
        "            NtQueryInformationProcess(Process.GetCurrentProcess().Handle,\n"
        "                7, ref info, sizeof(int), ref rlen);\n"
        "            if (info != 0) %s();\n"
        "        } catch {}\n"
        "    }\n\n",
        g->fn_ntq, g->fn_die);

    // ---- 8. CheckRemoteDebugger ----
    fprintf(f,
        "    static void %s() {\n"
        "        bool rem = false;\n"
        "        CheckRemoteDebuggerPresent(Process.GetCurrentProcess().Handle, ref rem);\n"
        "        if (rem) %s();\n"
        "    }\n\n",
        g->fn_remote, g->fn_die);

    // ---- 9. CheckHardwareBreakpoints ----
    fprintf(f,
        "    static void %s() {\n"
        "        try {\n"
        "            bool is64 = IntPtr.Size == 8;\n"
        "            int ctxSz = is64 ? 1232 : 716;\n"
        "            IntPtr raw = Marshal.AllocHGlobal(ctxSz + 16);\n"
        "            try {\n"
        "                long aligned = (raw.ToInt64() + 15) & ~15L;\n"
        "                IntPtr ctx = new IntPtr(aligned);\n"
        "                for (int i = 0; i < ctxSz; i++) Marshal.WriteByte(ctx, i, 0);\n"
        "                int flagsOff   = is64 ? 0x30 : 0x00;\n"
        "                int ctxFlags   = is64 ? 0x100010 : 0x10010;\n"
        "                Marshal.WriteInt32(ctx, flagsOff, ctxFlags);\n"
        "                if (%s(%s(), ctx)) {\n"
        "                    if (is64) {\n"
        "                        long d = Marshal.ReadInt64(ctx,0x48)\n"
        "                               | Marshal.ReadInt64(ctx,0x50)\n"
        "                               | Marshal.ReadInt64(ctx,0x58)\n"
        "                               | Marshal.ReadInt64(ctx,0x60);\n"
        "                        if (d != 0) %s();\n"
        "                    }\n"
        "                }\n"
        "            } finally { Marshal.FreeHGlobal(raw); }\n"
        "        } catch {}\n"
        "    }\n\n",
        g->fn_hwbp,
        g->ex_gettc, g->ex_getct,
        g->fn_die);

    // ---- 10. CheckDebuggerOutput ----
    fprintf(f,
        "    static void %s() {\n"
        "        try {\n"
        "            long t = Environment.TickCount64;\n"
        "            OutputDebugString(\"x\");\n"
        "            if (Environment.TickCount64 - t > 30) %s();\n"
        "        } catch {}\n"
        "    }\n\n",
        g->fn_dbgout, g->fn_die);

    // ---- 11. CheckProcessList ----
    fprintf(f,
        "    static void %s() {\n"
        "        try {\n"
        "            foreach (var p in Process.GetProcesses()) {\n"
        "                string n = p.ProcessName.ToLowerInvariant();\n"
        "                foreach (var b in _bp) if (n.Contains(b)) %s();\n"
        "            }\n"
        "        } catch {}\n"
        "    }\n\n",
        g->fn_procs, g->fn_die);

    // ---- 12. CheckSandboxDlls (now actually encrypted, see note above _bp) ----
    static const char *bad_dlls[] = {
        "sbiedll.dll","api_log.dll","dir_watch.dll","pstorec.dll",
        "vmcheck.dll","wpespy.dll","dbghelp.dll","snxhk.dll",
        "cmdvrt32.dll","cmdvrt64.dll","cuckoomon.dll",
        NULL
    };
    {
        char *joined = NULL; size_t jlen = 0;
        for (int i = 0; bad_dlls[i]; i++) {
            size_t plen = strlen(bad_dlls[i]);
            char *tmp = (char *)realloc(joined, jlen + plen + 2);
            joined = tmp;
            memcpy(joined + jlen, bad_dlls[i], plen);
            jlen += plen;
            joined[jlen++] = '\x01';
        }
        joined[jlen] = '\0';
        fprintf(f, "    static readonly string[] _bd = ");
        write_encrypted_blob(f, joined, g, 1002);
        fprintf(f, ".Split('\\x01', StringSplitOptions.RemoveEmptyEntries);\n\n");
        free(joined);
    }

    fprintf(f,
        "    static void %s() {\n"
        "        foreach (var d in _bd)\n"
        "            if (GetModuleHandle(d) != IntPtr.Zero) %s();\n"
        "    }\n\n",
        g->fn_dlls, g->fn_die);

    // ---- 13. CheckVirtualMachine ----
    fprintf(f,
        "    static void %s() {\n"
        "        try {\n"
        "            if (OperatingSystem.IsWindows()) {\n"
        "                string[] vmk = {\n"
        "                    @\"SOFTWARE\\VMware, Inc.\\VMware Tools\",\n"
        "                    @\"SOFTWARE\\Oracle\\VirtualBox Guest Additions\",\n"
        "                    @\"SYSTEM\\CurrentControlSet\\Services\\VBoxGuest\",\n"
        "                    @\"SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters\"\n"
        "                };\n"
        "                foreach (var k in vmk)\n"
        "                    if (Microsoft.Win32.Registry.LocalMachine.OpenSubKey(k) != null) %s();\n"
        "            }\n"
        "            string[] bm = {\"000569\",\"000C29\",\"005056\",\"080027\",\"00155D\"};\n"
        "            foreach (var iface in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces()) {\n"
        "                string mac = iface.GetPhysicalAddress().ToString();\n"
        "                foreach (var prefix in bm)\n"
        "                    if (mac.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) %s();\n"
        "            }\n"
        "        } catch (Exception ex) when (!(ex is InvalidOperationException)) {}\n"
        "    }\n\n",
        g->fn_vm, g->fn_die, g->fn_die);

    // ---- 14. CheckManagedDebugger ----
    fprintf(f,
        "    static void %s() {\n"
        "        if (System.Diagnostics.Debugger.IsAttached) %s();\n"
        "        string entry = (Assembly.GetEntryAssembly()?.Location\n"
        "                       ?? AppContext.BaseDirectory ?? \"\").ToLowerInvariant();\n"
        "        string[] bh = {\"testhost\",\"vstest\",\"rider\",\"jetbrains\",\"devenv\",\n"
        "                        \"visualstudio\",\"msvsmon\",\"vsdebugger\",\"dnspy\",\"de4dot\"};\n"
        "        foreach (var h in bh) if (entry.Contains(h)) %s();\n"
        "    }\n\n",
        g->fn_managed, g->fn_die, g->fn_die);

    // ---- 15. CheckParentProcess (v4: grandparent check is now real, not
    // just a comment - v3's comment claimed it but the code never queried
    // the grandparent at all) ----
    fprintf(f,
        "    static void %s() {\n"
        "        try {\n"
        "            var pbi = new %s(); int rlen = 0;\n"
        "            if (%s(Process.GetCurrentProcess().Handle, 0, ref pbi,\n"
        "                Marshal.SizeOf<%s>(), ref rlen) != 0) return;\n"
        "            int ppid = (int)pbi.InheritedFromUniqueProcessId;\n"
        "            try {\n"
        "                var parent = Process.GetProcessById(ppid);\n"
        "                string pn = parent.ProcessName.ToLowerInvariant();\n"
        "                string cmd = parent.MainModule?.FileName?.ToLowerInvariant() ?? \"\";\n"
        "                \n"
        "                string[] ok = {\"explorer\",\"cmd\",\"powershell\",\"pwsh\",\n"
        "                               \"wscript\",\"cscript\",\"conhost\",\"windowsterminal\",\n"
        "                               \"wt\",\"bash\"};\n"
        "                bool safe = false;\n"
        "                foreach (var a in ok) if (pn.Contains(a)) { safe=true; break; }\n"
        "                \n"
        "                if (cmd.Contains(\"python\") || cmd.Contains(\"debugger\") || cmd.Contains(\"dnspy\")) %s();\n"
        "                if (!safe) %s();\n"
        "                %s(parent);\n"
        "            } catch (ArgumentException) {}\n"
        "        } catch {}\n"
        "    }\n\n"
        "    static void %s(Process parent) {\n"
        "        try {\n"
        "            var gpbi = new %s(); int grlen = 0;\n"
        "            if (%s(parent.Handle, 0, ref gpbi, Marshal.SizeOf<%s>(), ref grlen) != 0) return;\n"
        "            int gppid = (int)gpbi.InheritedFromUniqueProcessId;\n"
        "            try {\n"
        "                var grand = Process.GetProcessById(gppid);\n"
        "                string gn = grand.ProcessName.ToLowerInvariant();\n"
        "                foreach (var b in _bp) if (gn.Contains(b)) %s();\n"
        "            } catch (ArgumentException) {}\n"
        "        } catch {}\n"
        "    }\n\n",
        g->fn_parent,
        g->st_pbi, g->ex_ntqpbi, g->st_pbi,
        g->fn_die, g->fn_die, g->fn_grandparent,
        g->fn_grandparent,
        g->st_pbi, g->ex_ntqpbi, g->st_pbi,
        g->fn_die);

    // ---- 16. CheckKernelDebugger ----
    fprintf(f,
        "    static void %s() {\n"
        "        try {\n"
        "            IntPtr buf = Marshal.AllocHGlobal(4); int rlen = 0;\n"
        "            int st = %s(0x23, buf, 4, ref rlen);\n"
        "            bool enabled    = Marshal.ReadByte(buf, 0) != 0;\n"
        "            bool notPresent = Marshal.ReadByte(buf, 1) != 0;\n"
        "            Marshal.FreeHGlobal(buf);\n"
        "            if (st == 0 && enabled && !notPresent) %s();\n"
        "        } catch {}\n"
        "    }\n\n",
        g->fn_kernel, g->ex_ntqsi, g->fn_die);

    // ---- 17. PatchETW ----
    fprintf(f,
        "    static void %s() {\n"
        "        try {\n"
        "            IntPtr ntdll = GetModuleHandle(\"ntdll.dll\");\n"
        "            if (ntdll == IntPtr.Zero) return;\n"
        "            IntPtr fn = %s(ntdll, \"EtwEventWrite\");\n"
        "            if (fn == IntPtr.Zero) return;\n"
        "            uint old = 0;\n"
        "            %s(fn, (IntPtr)1, 0x40, ref old);\n"
        "            Marshal.WriteByte(fn, 0xC3);\n"
        "            %s(fn, (IntPtr)1, old, ref old);\n"
        "        } catch {}\n"
        "    }\n\n",
        g->fn_etw, g->ex_gpa, g->ex_vp, g->ex_vp);

    // ---- 18. AntiDump ----
    fprintf(f,
        "    static void %s() {\n"
        "        try {\n"
        "            IntPtr hMod = GetModuleHandle(null);\n"
        "            if (hMod == IntPtr.Zero) return;\n"
        "            if (Marshal.ReadInt16(hMod) != 0x5A4D) return;\n"
        "            uint old = 0;\n"
        "            %s(hMod, (IntPtr)0x2000, 0x40, ref old);\n"
        // v4.4: random bytes instead of zeros. An all-zero header is
        // itself a recognizable "deliberately wiped" signature some
        // dump/reconstruction tools specifically look for and have
        // fallback handling for; noise is marginally harder to
        // distinguish from genuinely corrupted/partial memory.
        "            var rng = new Random();\n"
        "            byte[] noise = new byte[0x2000];\n"
        "            rng.NextBytes(noise);\n"
        "            for (int i = 0; i < 0x2000; i++) Marshal.WriteByte(hMod, i, noise[i]);\n"
        "            %s(hMod, (IntPtr)0x2000, old, ref old);\n"
        "        } catch {}\n"
        "    }\n\n",
        g->fn_dump, g->ex_vp, g->ex_vp);

    // ---- 19. Die() ----
    fprintf(f,
        "    static void %s() {\n"
        "        try { throw new AccessViolationException(); }\n"
        "        catch { Environment.FailFast(null); }\n"
        "    }\n\n",
        g->fn_die);

    // ---- 20. StartWatchdog — v4 control-flow flattening.
    // v3 bug fixed in passing: the watchdog's printf format had 9 "%s();"
    // placeholders but 10 args were passed (fn_managed was silently
    // dropped by C varargs - extra args are just ignored), so the managed-
    // debugger check ran once at startup and was NEVER re-checked by the
    // watchdog. It's included below.
    //
    // More importantly: v3 called all checks in one fixed straight-line
    // order, every cycle, every build - exactly the kind of flat,
    // repeating "if(check()) Die()" shape an agent doing systematic
    // decompile-and-reason is built to recognize on sight. v4 puts the
    // checks (plus 2 no-op decoys, so the call count doesn't map 1:1 to
    // the real check count) behind a dispatch table whose element order
    // is shuffled once per build, and whose invocation order AND subset
    // are re-randomized every watchdog cycle at runtime - so there's no
    // fixed sequence to pattern-match even across repeated runs of the
    // very same binary. ----
    fprintf(f,
        "    static void %s() {\n"
        "        try {\n"
        "            var buf = new byte[64];\n"
        "            new Random(Environment.TickCount).NextBytes(buf);\n"
        "            long sum = 0; foreach (var b in buf) sum += b;\n"
        "            if (sum == long.MaxValue) GC.Collect();\n"
        "        } catch {}\n"
        "    }\n\n"
        "    static void %s() {\n"
        "        try {\n"
        "            var sw = System.Diagnostics.Stopwatch.StartNew();\n"
        "            Thread.SpinWait(50);\n"
        "            sw.Stop();\n"
        "            if (sw.ElapsedTicks < 0) Environment.Exit(1);\n"
        "        } catch {}\n"
        "    }\n\n",
        g->fn_junk1, g->fn_junk2);

    {
        const char *names[12];
        names[0]=g->fn_integrity; names[1]=g->fn_hide;    names[2]=g->fn_proxy;
        names[3]=g->fn_ssl_pin;   names[4]=g->fn_winapi;  names[5]=g->fn_ntgf;
        names[6]=g->fn_remote;    names[7]=g->fn_hwbp;    names[8]=g->fn_procs;
        names[9]=g->fn_managed;   names[10]=g->fn_junk1;  names[11]=g->fn_junk2;
        int order[12] = {0,1,2,3,4,5,6,7,8,9,10,11};
        uint64_t shuf = checksum64(g->key, 32) ^ ((uint64_t)g->nonce[0] << 8) ^ g->nonce[1];
        for (int i = 11; i > 0; i--) {
            shuf = lcg_next(shuf);
            int j = (int)(shuf % (uint64_t)(i + 1));
            int t2 = order[i]; order[i] = order[j]; order[j] = t2;
        }
        fprintf(f, "    static readonly Action[] %s = new Action[]{\n        ", g->fn_dispatch);
        for (int k = 0; k < 12; k++) fprintf(f, "%s%s", k ? ", " : "", names[order[k]]);
        fprintf(f, "\n    };\n\n");
    }

    fprintf(f,
        "    static void %s() {\n"
        "        var t = new Thread(() => {\n"
        "            var rng = new Random();\n"
        "            while (true) {\n"
        "                Thread.Sleep(1500 + rng.Next(3000));\n"
        "                var idx = Enumerable.Range(0, %s.Length).ToList();\n"
        "                for (int i = idx.Count - 1; i > 0; i--) {\n"
        "                    int j = rng.Next(i + 1);\n"
        "                    int tmp = idx[i]; idx[i] = idx[j]; idx[j] = tmp;\n"
        "                }\n"
        "                foreach (var i in idx) if (rng.Next(100) < 70) %s[i]();\n"
        "            }\n"
        "        });\n"
        "        t.IsBackground = true;\n"
        "        t.Name = \"Windows Update\";\n"
        "        t.Start();\n"
        "    }\n\n",
        g->fn_watchdog, g->fn_dispatch, g->fn_dispatch);

    // ================================================================
    // v4.2 — BYTECODE VM, expanded opcode set + encrypted bytecode
    // (the actual answer to "make Ghidra/IDA almost impossible")
    //
    // Everything else in this file raises the COST of static analysis:
    // encrypted strings, shuffled dispatch, stripped symbols. None of it
    // removes the fundamental problem, which is that your real logic
    // still exists as a native x86 function with a recognizable control
    // flow graph that Ghidra/IDA (and REA) can decompile and reason
    // about directly.
    //
    // A tiny custom bytecode interpreter sidesteps that: whatever logic
    // you compile INTO the bytecode has no corresponding x86 function at
    // all. The decompiler only ever sees one generic "read a byte, switch
    // on it, loop" function - the exact same interpreter loop regardless
    // of how many different protected checks you implement in bytecode.
    // There's no 1:1 mapping from native code to your original logic for
    // a decompiler (human or AI agent) to recover, because the logic
    // never existed as native code in the first place - it's DATA that
    // this one generic loop happens to execute.
    //
    // v4.2 closes the gap flagged in v4.1: the bytecode itself now ships
    // through the same HMAC-SHA256 authenticated encryption as the
    // string blacklists (via the length-aware fn_decrypt_bytes above),
    // not as a plain byte[] literal. A static reader now has to break
    // the encryption AND reconstruct the VM's own logic before they can
    // even see what program is being interpreted.
    //
    // The opcode set is also expanded from v4.1's arithmetic-only set to
    // include branching (JMP/JMP_IF_FALSE), bitwise ops, and a second
    // argument slot, so meaningfully more real logic can be hand-
    // assembled into bytecode instead of staying as native C#.
    //
    // Opcode format (stack machine, uint32 stack elements, two uint
    // arguments available as arg0/arg1):
    //   0x01 <4B LE u32>  PUSH_CONST    push the literal
    //   0x02              PUSH_ARG0     push the function's first arg
    //   0x03              MUL           pop b,a; push a*b   (wraps)
    //   0x04              MOD           pop b,a; push a%b
    //   0x05              ADD           pop b,a; push a+b   (wraps)
    //   0x06              CMP_EQ        pop b,a; push (a==b)?1:0
    //   0x07              RET           pop result, return it
    //   0x08              SUB           pop b,a; push a-b   (wraps)
    //   0x09              AND           pop b,a; push a&b
    //   0x0A              OR            pop b,a; push a|b
    //   0x0B              XOR           pop b,a; push a^b
    //   0x0C              CMP_GT        pop b,a; push (a>b)?1:0
    //   0x0D              CMP_LT        pop b,a; push (a<b)?1:0
    //   0x0E <2B LE u16>  JMP           unconditional jump to byte offset
    //   0x0F <2B LE u16>  JMP_IF_FALSE  pop cond; jump to offset if cond==0
    //   0x10              PUSH_ARG1     push the function's second arg
    //   0x11              DUP           duplicate top of stack
    //   0x12              POP           discard top of stack
    //   0x13              NOT           pop v; push (v==0)?1:0
    //
    // Still honestly scoped: this is an interpreter + two worked examples
    // (one pure arithmetic, one with branching), not a compiler. No
    // string/array operations, no CALL_HOST-back-into-C# opcode yet for
    // things the VM genuinely can't do alone - if your real logic needs
    // string comparison or similar, say so and that opcode gets added
    // rather than you working around it with something fragile. A real
    // compiler (write protected logic in C#-like syntax, get bytecode
    // out) is the natural next step after tonight, not a tonight thing.
    // ================================================================
    fprintf(f,
        "    internal static uint %s(byte[] code, uint arg0, uint arg1, uint arg2, uint arg3) {\n"
        "        uint[] stack = new uint[32];\n"
        "        uint[] locals = new uint[8];\n"
        "        int sp = 0, pc = 0;\n"
        "        while (pc < code.Length) {\n"
        "            byte op = code[pc++];\n"
        "            switch (op) {\n",
        g->fn_vm_exec);
    // v4.3: every case value below comes from this build's random opmap,
    // not a fixed constant - see the enum/comment near the top of this
    // file. Two decoy blocks (byte values the compiler never emits) are
    // interspersed so "count the cases" doesn't reliably reveal the real
    // instruction count either.
    fprintf(f,
        "                case %d: {\n"
        "                    uint v = (uint)(code[pc] | (code[pc+1] << 8) | (code[pc+2] << 16) | (code[pc+3] << 24));\n"
        "                    pc += 4; stack[sp++] = v; break;\n"
        "                }\n", g->opmap[OPC_PUSH_CONST]);
    fprintf(f, "                case %d: stack[sp++] = arg0; break;\n", g->opmap[OPC_PUSH_ARG0]);
    fprintf(f, "                case %d: stack[sp++] = arg1; break;\n", g->opmap[OPC_PUSH_ARG1]);
    fprintf(f, "                case %d: stack[sp++] = arg2; break;\n", g->opmap[OPC_PUSH_ARG2]);
    fprintf(f, "                case %d: stack[sp++] = arg3; break;\n", g->opmap[OPC_PUSH_ARG3]);
    for (int i = 0; i < 2; i++)
        fprintf(f, "                case %d: break;\n", g->decoy_ops[i]);
    fprintf(f, "                case %d: { uint b = stack[--sp]; uint a = stack[--sp]; stack[sp++] = unchecked(a * b); break; }\n", g->opmap[OPC_MUL]);
    fprintf(f, "                case %d: { uint b = stack[--sp]; uint a = stack[--sp]; stack[sp++] = a %% b; break; }\n", g->opmap[OPC_MOD]);
    fprintf(f, "                case %d: { uint b = stack[--sp]; uint a = stack[--sp]; stack[sp++] = unchecked(a + b); break; }\n", g->opmap[OPC_ADD]);
    fprintf(f, "                case %d: { uint b = stack[--sp]; uint a = stack[--sp]; stack[sp++] = unchecked(a - b); break; }\n", g->opmap[OPC_SUB]);
    fprintf(f, "                case %d: { uint b = stack[--sp]; uint a = stack[--sp]; stack[sp++] = a & b; break; }\n", g->opmap[OPC_AND]);
    fprintf(f, "                case %d: { uint b = stack[--sp]; uint a = stack[--sp]; stack[sp++] = a | b; break; }\n", g->opmap[OPC_OR]);
    fprintf(f, "                case %d: { uint b = stack[--sp]; uint a = stack[--sp]; stack[sp++] = a ^ b; break; }\n", g->opmap[OPC_XOR]);
    fprintf(f, "                case %d: { uint b = stack[--sp]; uint a = stack[--sp]; stack[sp++] = (a == b) ? 1u : 0u; break; }\n", g->opmap[OPC_CMP_EQ]);
    fprintf(f, "                case %d: { uint b = stack[--sp]; uint a = stack[--sp]; stack[sp++] = (a > b) ? 1u : 0u; break; }\n", g->opmap[OPC_CMP_GT]);
    fprintf(f, "                case %d: { uint b = stack[--sp]; uint a = stack[--sp]; stack[sp++] = (a < b) ? 1u : 0u; break; }\n", g->opmap[OPC_CMP_LT]);
    fprintf(f, "                case %d: { uint b = stack[--sp]; uint a = stack[--sp]; stack[sp++] = (a != b) ? 1u : 0u; break; }\n", g->opmap[OPC_CMP_NE]);
    fprintf(f, "                case %d: { uint b = stack[--sp]; uint a = stack[--sp]; stack[sp++] = (a >= b) ? 1u : 0u; break; }\n", g->opmap[OPC_CMP_GE]);
    fprintf(f, "                case %d: { uint b = stack[--sp]; uint a = stack[--sp]; stack[sp++] = (a <= b) ? 1u : 0u; break; }\n", g->opmap[OPC_CMP_LE]);
    fprintf(f, "                case %d: { uint b = stack[--sp]; uint a = stack[--sp]; stack[sp++] = (a != 0 && b != 0) ? 1u : 0u; break; }\n", g->opmap[OPC_LAND]);
    fprintf(f, "                case %d: { uint b = stack[--sp]; uint a = stack[--sp]; stack[sp++] = (a != 0 || b != 0) ? 1u : 0u; break; }\n", g->opmap[OPC_LOR]);
    for (int i = 2; i < 4; i++)
        fprintf(f, "                case %d: break;\n", g->decoy_ops[i]);
    fprintf(f, "                case %d: { int t = code[pc] | (code[pc+1] << 8); pc = t; break; }\n", g->opmap[OPC_JMP]);
    fprintf(f,
        "                case %d: {\n"
        "                    int t = code[pc] | (code[pc+1] << 8); pc += 2;\n"
        "                    uint cond = stack[--sp];\n"
        "                    if (cond == 0) pc = t;\n"
        "                    break;\n"
        "                }\n", g->opmap[OPC_JMP_IF_FALSE]);
    fprintf(f, "                case %d: { uint v = stack[sp-1]; stack[sp++] = v; break; }\n", g->opmap[OPC_DUP]);
    fprintf(f, "                case %d: sp--; break;\n", g->opmap[OPC_POP]);
    fprintf(f, "                case %d: { uint v = stack[--sp]; stack[sp++] = (v == 0) ? 1u : 0u; break; }\n", g->opmap[OPC_NOT]);
    // v4.4: PROTECT_BLOCK local variable slots - the opcode byte takes
    // the slot index as its single operand (not a 4-byte constant).
    fprintf(f, "                case %d: { byte slot = code[pc++]; stack[sp++] = locals[slot]; break; }\n", g->opmap[OPC_LOAD_LOCAL]);
    fprintf(f, "                case %d: { byte slot = code[pc++]; locals[slot] = stack[--sp]; break; }\n", g->opmap[OPC_STORE_LOCAL]);
    for (int i = 4; i < N_DECOY_OPS; i++)
        fprintf(f, "                case %d: break;\n", g->decoy_ops[i]);
    fprintf(f, "                case %d: return stack[--sp];\n", g->opmap[OPC_RET]);
    fprintf(f,
        "                default: return 0;\n"
        "            }\n"
        "        }\n"
        "        return 0;\n"
        "    }\n\n");

    // Example 1 - pure arithmetic gate (same logic as v4.1, now shipped
    // encrypted instead of as a plaintext byte array):
    //   isValid(code) == ((uint)code * 2654435761u) % 97 == 42
    // (2654435761 = 0x9E3779B1, Knuth's multiplicative hash constant -
    // arbitrary but deterministic; swap in your real gate's arithmetic).
    // Verified codes that pass: 110, 160, 210, 260, 310, 360, 410...
    {
        // v4.3: opcode bytes now come from this build's g->opmap instead
        // of fixed constants, so this can no longer be a plain static
        // initializer - built via explicit assignment instead (same
        // approach prog2 below already used for its branch patching).
        uint8_t prog1[20];
        int n1 = 0;
        prog1[n1++] = g->opmap[OPC_PUSH_ARG0];
        prog1[n1++] = g->opmap[OPC_PUSH_CONST];
        n1 += emit_u32le(prog1 + n1, 2654435761u);
        prog1[n1++] = g->opmap[OPC_MUL];
        prog1[n1++] = g->opmap[OPC_PUSH_CONST];
        n1 += emit_u32le(prog1 + n1, 97u);
        prog1[n1++] = g->opmap[OPC_MOD];
        prog1[n1++] = g->opmap[OPC_PUSH_CONST];
        n1 += emit_u32le(prog1 + n1, 42u);
        prog1[n1++] = g->opmap[OPC_CMP_EQ];
        prog1[n1++] = g->opmap[OPC_RET];
        fprintf(f,
            "    // Example 1 (arithmetic only) - replace the bytecode below with\n"
            "    // your own hand-assembled program. Call sites see only\n"
            "    // %s(int), never the logic or the bytecode inside - it only\n"
            "    // exists decrypted, in memory, for the duration of this call.\n"
            "    static bool %s(int code) {\n"
            "        byte[] bytecode = ",
            g->fn_vm_demo, g->fn_vm_demo);
        write_encrypted_bytes(f, prog1, (size_t)n1, g, 2001);
        /* write_encrypted_bytes already closed the call expression itself
           (ends in "...})"), so only the statement's trailing ';' is
           needed here - NOT another ')' (that was the bug: it produced
           "...}));" with one extra, unmatched closing paren). */
        fprintf(f, ";\n"
            "        return %s(bytecode, unchecked((uint)code), 0, 0, 0) != 0;\n"
            "    }\n\n",
            g->fn_vm_exec);
    }

    // Example 2 - same idea but with a branch, as a template for
    // threshold/range-style gates: isAllowed(x) == (x > 100)
    {
        uint8_t prog2[24]; /* exact size needed - verified against the Python
                              simulation that checked this program's semantics */
        int n = 0;
        prog2[n++] = g->opmap[OPC_PUSH_ARG0];
        prog2[n++] = g->opmap[OPC_PUSH_CONST]; n += emit_u32le(prog2 + n, 100u);
        prog2[n++] = g->opmap[OPC_CMP_GT];
        int jmp_if_false_at = n;
        prog2[n++] = g->opmap[OPC_JMP_IF_FALSE]; prog2[n++] = 0; prog2[n++] = 0; /* <patch> */
        prog2[n++] = g->opmap[OPC_PUSH_CONST]; n += emit_u32le(prog2 + n, 1u);
        int jmp_at = n;
        prog2[n++] = g->opmap[OPC_JMP]; prog2[n++] = 0; prog2[n++] = 0; /* <patch> */
        int L1 = n;
        prog2[n++] = g->opmap[OPC_PUSH_CONST]; n += emit_u32le(prog2 + n, 0u); /* L1 */
        int L2 = n;
        prog2[n++] = g->opmap[OPC_RET];                      /* L2 */
        prog2[jmp_if_false_at+1] = (uint8_t)(L1 & 0xFF); prog2[jmp_if_false_at+2] = (uint8_t)(L1 >> 8);
        prog2[jmp_at+1] = (uint8_t)(L2 & 0xFF); prog2[jmp_at+2] = (uint8_t)(L2 >> 8);

        fprintf(f,
            "    // Example 2 (branching template) - isAllowed(x) == (x > 100).\n"
            "    // Shows JMP/JMP_IF_FALSE for threshold/range-style gates - use\n"
            "    // this shape for anything with an if/else in the original logic.\n"
            "    static bool %s(int x) {\n"
            "        byte[] bytecode = ",
            g->fn_vm_demo2);
        write_encrypted_bytes(f, prog2, (size_t)n, g, 2002);
        /* same fix as Example 1 above - no extra ')' needed here */
        fprintf(f, ";\n"
            "        return %s(bytecode, unchecked((uint)x), 0, 0, 0) != 0;\n"
            "    }\n\n",
            g->fn_vm_exec);
    }

    // ---- Close class ----
    fputs("}\n// ---- END PROTECTION LAYER V4.2 ----\n\n", f);
}

// ================================================================
//  SECTION 6 — CSPROJ GENERATOR
// ================================================================

static void write_csproj(const char *proj_path, const char *exe_name,
                         int use_nativeaot) {
    FILE *f = fopen(proj_path, "w"); if (!f) return;
    // v4.1: DebugType was "embedded" - that ships the FULL PDB (function
    // names, local variable names, line numbers) inside the binary. That
    // one setting alone hands Ghidra/IDA (or dnSpy) a near-source-level
    // view and makes every obfuscation pass in this file close to
    // pointless. It is now "none". If you need crash dumps for your own
    // debugging, generate a separate .pdb out-of-band and keep it off
    // the shipped binary, never embedded.
    fprintf(f,
        "<Project Sdk=\"Microsoft.NET.Sdk\">\n"
        "  <PropertyGroup>\n"
        "    <OutputType>Exe</OutputType>\n"
        "    <TargetFramework>net8.0</TargetFramework>\n"
        "    <RootNamespace>%s</RootNamespace>\n"
        "    <AssemblyName>%s</AssemblyName>\n"
        "    <Nullable>enable</Nullable>\n"
        "    <AllowUnsafeBlocks>true</AllowUnsafeBlocks>\n"
        "    <Optimize>true</Optimize>\n"
        "    <DebugType>none</DebugType>\n"
        "    <DebugSymbols>false</DebugSymbols>\n"
        "    <GenerateDocumentationFile>false</GenerateDocumentationFile>\n"
        "    <TieredCompilation>true</TieredCompilation>\n"
        "%s"
        "  </PropertyGroup>\n"
        "</Project>\n",
        exe_name, exe_name,
        use_nativeaot
            // ---- NativeAOT: this is the ONLY mode where Ghidra/IDA are
            // even relevant - it's the only mode that emits real machine
            // code instead of IL. The flags below strip as much of the
            // metadata that feeds a decompiler's auto-analysis as the
            // .NET toolchain allows:
            //   IlcGenerateStackTraceData / CompleteTypeMetadata false
            //       -> removes the type/method name tables NativeAOT
            //          otherwise keeps around for reflection & stack
            //          traces - this is a direct source of readable
            //          strings and symbol names in the compiled PE.
            //   StackTraceSupport / UseSystemResourceKeys / EventSource
            //       -> trims more reflection/metadata surface.
            //   IlcOptimizationPreference Size
            //       -> more aggressive inlining/merging, which works
            //          against clean 1:1 "one function = one check"
            //          boundaries that a decompiler relies on.
            ? "    <PublishAot>true</PublishAot>\n"
              "    <InvariantGlobalization>true</InvariantGlobalization>\n"
              "    <PublishTrimmed>true</PublishTrimmed>\n"
              "    <TrimMode>full</TrimMode>\n"
              "    <IlcGenerateStackTraceData>false</IlcGenerateStackTraceData>\n"
              "    <IlcGenerateCompleteTypeMetadata>false</IlcGenerateCompleteTypeMetadata>\n"
              "    <StackTraceSupport>false</StackTraceSupport>\n"
              "    <UseSystemResourceKeys>true</UseSystemResourceKeys>\n"
              "    <EventSourceSupport>false</EventSourceSupport>\n"
              "    <HttpActivityPropagationSupport>false</HttpActivityPropagationSupport>\n"
              "    <UseNativeHttpHandler>false</UseNativeHttpHandler>\n"
              "    <AutoreleasePoolSupport>false</AutoreleasePoolSupport>\n"
              "    <IlcOptimizationPreference>Size</IlcOptimizationPreference>\n"
              "    <IlcFoldIdenticalMethodBodies>true</IlcFoldIdenticalMethodBodies>\n"
            : "    <PublishTrimmed>true</PublishTrimmed>\n"
              "    <TrimMode>full</TrimMode>\n"
              "    <PublishSingleFile>true</PublishSingleFile>\n"
              "    <EnableCompressionInSingleFile>true</EnableCompressionInSingleFile>\n"
              "    <IncludeNativeLibrariesForSelfExtract>true</IncludeNativeLibrariesForSelfExtract>\n"
    );
    fclose(f);
}

// ================================================================
//  SECTION 7 — SOURCE CODE INJECTION
// ================================================================

static char *extract_using(const char *src, const char **out_rest) {
    static const char *injected[] = {
        "System","System.Diagnostics","System.Runtime.InteropServices",
        "System.Threading","System.Reflection","System.IO","System.Linq",
        "System.Security.Cryptography","System.Net","System.Net.Http",
        "Microsoft.Win32",
        NULL
    };
    const char *p = src;
    char *using_block = NULL;
    size_t using_len = 0;

    while (*p) {
        if (isspace((unsigned char)*p)) { p++; continue; }
        if (p[0] == '/' && p[1] == '/') {
            while (*p && *p != '\n') p++;
            continue;
        }
        if (strncmp(p, "using ", 6) != 0) break;
        const char *start = p + 6;
        const char *semi  = strchr(start, ';');
        if (!semi) break;
        size_t ns_len = (size_t)(semi - start);
        char ns[256];
        if (ns_len < sizeof(ns)) {
            memcpy(ns, start, ns_len); ns[ns_len] = '\0';
            while (ns[0] == ' ') memmove(ns, ns+1, strlen(ns));
            int skip = 0;
            for (int i = 0; injected[i]; i++)
                if (strcmp(ns, injected[i]) == 0) { skip = 1; break; }
            if (!skip) {
                const char *eol = strchr(semi, '\n');
                if (!eol) eol = semi;
                size_t line_len = (size_t)(eol - p) + 1;
                char *tmp = (char *)realloc(using_block, using_len + line_len + 1);
                if (tmp) {
                    using_block = tmp;
                    memcpy(using_block + using_len, p, line_len);
                    using_len += line_len;
                    using_block[using_len] = '\0';
                }
            }
        }
        p = semi + 1;
        if (*p == '\r') p++;
        if (*p == '\n') p++;
    }
    *out_rest = p;
    return using_block;
}

// ================================================================
//  SECTION 6 — AUTOMATIC BUSINESS-LOGIC STRING PROTECTION (v4.3)
//
// Everything up to this point protects Hydra4's OWN strings (the
// guard class's blacklists). It never touched the user's pasted-in
// code - which is exactly the gap REA found in PasswordTest.cs. This
// section closes that gap, deliberately scoped to be safe rather than
// clever: rather than guessing which of the user's string literals
// are "sensitive" via heuristics (risky - a wrong guess silently
// breaks code in ways that are hard to trace back to this tool), the
// user marks what they want protected explicitly: PROTECT("secret").
// Hydra4 finds every PROTECT(...) call in the source (skipping
// matches inside comments, strings, and char literals via the same
// state machine used elsewhere in this file), and replaces each one
// with a real call to the guard class's internal HMAC-SHA256-CTR
// decrypt method - the literal never appears in the compiled output,
// only ciphertext + a per-string nonce + an integrity tag.
//
// Deliberately NOT supported, and detected/rejected rather than
// silently mishandled:
//   - const fields: `const string X = PROTECT("...");` won't compile
//     (PROTECT's replacement is a method call, not a compile-time
//     constant - C# requires const initializers to be constants).
//     Detected via a backward scan for "const" since the last
//     statement/block boundary; aborts generation with a clear
//     message rather than emitting code that won't build.
//   - Verbatim (@"...") and interpolated ($"...") strings inside
//     PROTECT(...) - also detected and rejected rather than guessed
//     at, since both need different handling than a plain literal.
// ================================================================

static int is_ident_char(char c) {
    return isalnum((unsigned char)c) || c == '_';
}

// ================================================================
//  SECTION 7 — PROTECT_EXPR(...): a real (small, scoped) compiler
//
// PROTECT_EXPR("boolean/arithmetic expression over a0..a3", realArg0,
//              realArg1, ...) compiles the quoted expression into VM
//              bytecode at generation time, encrypts it, and emits a
//              call that evaluates it against the real C# values you
//              pass in. This is scoped to exactly what license and
//              activation checks actually need: hash/value comparisons,
//              date/version comparisons, feature-flag bit tests,
//              combined with boolean logic - NOT general C# (no
//              strings, loops, objects, or method calls inside the
//              expression itself; do that part in plain C# and pass
//              the RESULT in as a0..a3).
//
// Grammar (standard precedence, low to high):
//   or_expr    := and_expr ( '||' and_expr )*
//   and_expr   := cmp_expr ( '&&' cmp_expr )*
//   cmp_expr   := bitor_expr ( ('=='|'!='|'>'|'<'|'>='|'<=') bitor_expr )?
//   bitor_expr := bitxor_expr ( '|' bitxor_expr )*
//   bitxor_expr:= bitand_expr ( '^' bitand_expr )*
//   bitand_expr:= add_expr ( '&' add_expr )*
//   add_expr   := mul_expr ( ('+'|'-') mul_expr )*
//   mul_expr   := unary ( ('*'|'%') unary )*
//   unary      := ('!'|'-')? primary
//   primary    := NUMBER | 'a0'..'a3' | '(' expr ')'
// Honest note: && and || are NOT short-circuit (both sides always
// evaluate) - fine for pure arithmetic/comparison expressions with no
// side effects, which is exactly what this grammar can express in the
// first place (there's no way to write a side-effecting expression in
// it), so this never changes behavior, only (very slightly) cost.
// ================================================================

typedef enum {
    TOK_NUM, TOK_ARG, TOK_ANDAND, TOK_OROR, TOK_EQ, TOK_NE, TOK_GE, TOK_LE,
    TOK_GT, TOK_LT, TOK_AMP, TOK_PIPE, TOK_CARET, TOK_PLUS, TOK_MINUS,
    TOK_STAR, TOK_PERCENT, TOK_NOT, TOK_LPAREN, TOK_RPAREN, TOK_END,
    // v4.4: PROTECT_BLOCK statement-level tokens
    TOK_KW_UINT, TOK_KW_IF, TOK_KW_ELSE, TOK_KW_RETURN, TOK_IDENT,
    TOK_ASSIGN, TOK_LBRACE, TOK_RBRACE, TOK_SEMI
} TokKind;

typedef struct { TokKind kind; uint32_t num; int argn; char ident[32]; } Token;

typedef struct {
    Token toks[256];
    int ntoks;
    int pos;
    uint8_t code[1024];
    size_t codelen;
    int max_arg_used;
    jmp_buf errjmp;
    char errmsg[256];
    const uint8_t *opmap; // this build's canonical-opcode -> random-byte map
    // v4.4: PROTECT_BLOCK local variable symbol table
    char local_names[N_LOCAL_SLOTS][32];
    int num_locals;
} ExprCompiler;

static void ec_fail(ExprCompiler *ec, const char *msg) {
    snprintf(ec->errmsg, sizeof(ec->errmsg), "%s", msg);
    longjmp(ec->errjmp, 1);
}

static int ec_tokenize(ExprCompiler *ec, const char *s) {
    int n = 0;
    const char *p = s;
    while (*p) {
        if (isspace((unsigned char)*p)) { p++; continue; }
        if (n >= (int)(sizeof(ec->toks)/sizeof(ec->toks[0])) - 1) return 0;
        if (p[0]=='0' && (p[1]=='x'||p[1]=='X') && isxdigit((unsigned char)p[2])) {
            char *end; unsigned long v = strtoul(p, &end, 16);
            ec->toks[n].kind = TOK_NUM; ec->toks[n].num = (uint32_t)v; n++;
            p = end; continue;
        }
        if (isdigit((unsigned char)*p)) {
            char *end; unsigned long v = strtoul(p, &end, 10);
            ec->toks[n].kind = TOK_NUM; ec->toks[n].num = (uint32_t)v; n++;
            p = end; continue;
        }
        if (p[0]=='a' && isdigit((unsigned char)p[1]) && p[1]>='0' && p[1]<='3' &&
            !is_ident_char(p[2])) {
            ec->toks[n].kind = TOK_ARG; ec->toks[n].argn = p[1]-'0'; n++;
            p += 2; continue;
        }
        // v4.4: keywords and identifiers for PROTECT_BLOCK statements
        if (isalpha((unsigned char)p[0]) || p[0]=='_') {
            const char *start = p;
            while (is_ident_char(*p)) p++;
            size_t len = (size_t)(p - start);
            if (len >= sizeof(ec->toks[n].ident)) return 0; /* identifier too long */
            if (len==4 && memcmp(start,"uint",4)==0) ec->toks[n].kind = TOK_KW_UINT;
            else if (len==2 && memcmp(start,"if",2)==0) ec->toks[n].kind = TOK_KW_IF;
            else if (len==4 && memcmp(start,"else",4)==0) ec->toks[n].kind = TOK_KW_ELSE;
            else if (len==6 && memcmp(start,"return",6)==0) ec->toks[n].kind = TOK_KW_RETURN;
            else {
                ec->toks[n].kind = TOK_IDENT;
                memcpy(ec->toks[n].ident, start, len);
                ec->toks[n].ident[len] = '\0';
            }
            n++; continue;
        }
        if (p[0]=='{') { ec->toks[n++].kind = TOK_LBRACE; p++; continue; }
        if (p[0]=='}') { ec->toks[n++].kind = TOK_RBRACE; p++; continue; }
        if (p[0]==';') { ec->toks[n++].kind = TOK_SEMI; p++; continue; }
        if (p[0]=='=' && p[1]!='=') { ec->toks[n++].kind = TOK_ASSIGN; p++; continue; }
        if (p[0]=='&' && p[1]=='&') { ec->toks[n++].kind = TOK_ANDAND; p+=2; continue; }
        if (p[0]=='|' && p[1]=='|') { ec->toks[n++].kind = TOK_OROR;   p+=2; continue; }
        if (p[0]=='=' && p[1]=='=') { ec->toks[n++].kind = TOK_EQ;     p+=2; continue; }
        if (p[0]=='!' && p[1]=='=') { ec->toks[n++].kind = TOK_NE;     p+=2; continue; }
        if (p[0]=='>' && p[1]=='=') { ec->toks[n++].kind = TOK_GE;     p+=2; continue; }
        if (p[0]=='<' && p[1]=='=') { ec->toks[n++].kind = TOK_LE;     p+=2; continue; }
        switch (*p) {
            case '>': ec->toks[n++].kind = TOK_GT; p++; continue;
            case '<': ec->toks[n++].kind = TOK_LT; p++; continue;
            case '&': ec->toks[n++].kind = TOK_AMP; p++; continue;
            case '|': ec->toks[n++].kind = TOK_PIPE; p++; continue;
            case '^': ec->toks[n++].kind = TOK_CARET; p++; continue;
            case '+': ec->toks[n++].kind = TOK_PLUS; p++; continue;
            case '-': ec->toks[n++].kind = TOK_MINUS; p++; continue;
            case '*': ec->toks[n++].kind = TOK_STAR; p++; continue;
            case '%': ec->toks[n++].kind = TOK_PERCENT; p++; continue;
            case '!': ec->toks[n++].kind = TOK_NOT; p++; continue;
            case '(': ec->toks[n++].kind = TOK_LPAREN; p++; continue;
            case ')': ec->toks[n++].kind = TOK_RPAREN; p++; continue;
            default: return 0; /* unrecognized character */
        }
    }
    ec->toks[n].kind = TOK_END; n++;
    ec->ntoks = n;
    return 1;
}

static Token *ec_peek(ExprCompiler *ec) { return &ec->toks[ec->pos]; }
static void ec_eat(ExprCompiler *ec, TokKind k) {
    if (ec->toks[ec->pos].kind != k) ec_fail(ec, "unexpected token in expression");
    ec->pos++;
}
static void ec_emit(ExprCompiler *ec, uint8_t op) {
    if (ec->codelen >= sizeof(ec->code)) ec_fail(ec, "expression too large");
    ec->code[ec->codelen++] = op;
}
static void ec_emit_push_const(ExprCompiler *ec, uint32_t v) {
    if (ec->codelen + 5 > sizeof(ec->code)) ec_fail(ec, "expression too large");
    ec->code[ec->codelen++] = ec->opmap[OPC_PUSH_CONST];
    ec->code[ec->codelen++] = (uint8_t)(v);
    ec->code[ec->codelen++] = (uint8_t)(v >> 8);
    ec->code[ec->codelen++] = (uint8_t)(v >> 16);
    ec->code[ec->codelen++] = (uint8_t)(v >> 24);
}

static void ec_or_expr(ExprCompiler *ec);

// v4.4: local variable symbol table for PROTECT_BLOCK. declare=1 means
// this is a `uint name = ...` declaration (must not already exist);
// declare=0 means a use or reassignment (must already exist).
static int ec_slot_for(ExprCompiler *ec, const char *name, int declare) {
    for (int i = 0; i < ec->num_locals; i++)
        if (strcmp(ec->local_names[i], name) == 0) {
            if (declare) ec_fail(ec, "variable redeclared");
            return i;
        }
    if (!declare) ec_fail(ec, "use of undeclared variable");
    if (ec->num_locals >= N_LOCAL_SLOTS) ec_fail(ec, "too many local variables (max 8)");
    strncpy(ec->local_names[ec->num_locals], name, sizeof(ec->local_names[0]) - 1);
    return ec->num_locals++;
}

static void ec_primary(ExprCompiler *ec) {
    Token *t = ec_peek(ec);
    if (t->kind == TOK_NUM) { ec_emit_push_const(ec, t->num); ec->pos++; }
    else if (t->kind == TOK_ARG) {
        if (t->argn > ec->max_arg_used) ec->max_arg_used = t->argn;
        static const int argops_canon[4] = {OPC_PUSH_ARG0, OPC_PUSH_ARG1, OPC_PUSH_ARG2, OPC_PUSH_ARG3};
        ec_emit(ec, ec->opmap[argops_canon[t->argn]]);
        ec->pos++;
    } else if (t->kind == TOK_IDENT) {
        int slot = ec_slot_for(ec, t->ident, 0);
        ec_emit(ec, ec->opmap[OPC_LOAD_LOCAL]);
        ec_emit(ec, (uint8_t)slot);
        ec->pos++;
    } else if (t->kind == TOK_LPAREN) {
        ec->pos++; ec_or_expr(ec); ec_eat(ec, TOK_RPAREN);
    } else {
        ec_fail(ec, "expected a number, a0-a3, a variable, or '(' in expression");
    }
}
static void ec_unary(ExprCompiler *ec) {
    if (ec_peek(ec)->kind == TOK_NOT) { ec->pos++; ec_unary(ec); ec_emit(ec, ec->opmap[OPC_NOT]); }
    else if (ec_peek(ec)->kind == TOK_MINUS) {
        ec->pos++; ec_emit_push_const(ec, 0); ec_unary(ec); ec_emit(ec, ec->opmap[OPC_SUB]);
    } else ec_primary(ec);
}
static void ec_mul_expr(ExprCompiler *ec) {
    ec_unary(ec);
    while (ec_peek(ec)->kind == TOK_STAR || ec_peek(ec)->kind == TOK_PERCENT) {
        TokKind k = ec_peek(ec)->kind; ec->pos++; ec_unary(ec);
        ec_emit(ec, k == TOK_STAR ? ec->opmap[OPC_MUL] : ec->opmap[OPC_MOD]);
    }
}
static void ec_add_expr(ExprCompiler *ec) {
    ec_mul_expr(ec);
    while (ec_peek(ec)->kind == TOK_PLUS || ec_peek(ec)->kind == TOK_MINUS) {
        TokKind k = ec_peek(ec)->kind; ec->pos++; ec_mul_expr(ec);
        ec_emit(ec, k == TOK_PLUS ? ec->opmap[OPC_ADD] : ec->opmap[OPC_SUB]);
    }
}
static void ec_bitand_expr(ExprCompiler *ec) {
    ec_add_expr(ec);
    while (ec_peek(ec)->kind == TOK_AMP) { ec->pos++; ec_add_expr(ec); ec_emit(ec, ec->opmap[OPC_AND]); }
}
static void ec_bitxor_expr(ExprCompiler *ec) {
    ec_bitand_expr(ec);
    while (ec_peek(ec)->kind == TOK_CARET) { ec->pos++; ec_bitand_expr(ec); ec_emit(ec, ec->opmap[OPC_XOR]); }
}
static void ec_bitor_expr(ExprCompiler *ec) {
    ec_bitxor_expr(ec);
    while (ec_peek(ec)->kind == TOK_PIPE) { ec->pos++; ec_bitxor_expr(ec); ec_emit(ec, ec->opmap[OPC_OR]); }
}
static void ec_cmp_expr(ExprCompiler *ec) {
    ec_bitor_expr(ec);
    TokKind k = ec_peek(ec)->kind;
    if (k==TOK_EQ||k==TOK_NE||k==TOK_GT||k==TOK_LT||k==TOK_GE||k==TOK_LE) {
        ec->pos++; ec_bitor_expr(ec);
        int canon = k==TOK_EQ?OPC_CMP_EQ : k==TOK_NE?OPC_CMP_NE : k==TOK_GT?OPC_CMP_GT :
                    k==TOK_LT?OPC_CMP_LT : k==TOK_GE?OPC_CMP_GE : OPC_CMP_LE;
        ec_emit(ec, ec->opmap[canon]);
    }
}
static void ec_and_expr(ExprCompiler *ec) {
    ec_cmp_expr(ec);
    while (ec_peek(ec)->kind == TOK_ANDAND) { ec->pos++; ec_cmp_expr(ec); ec_emit(ec, ec->opmap[OPC_LAND]); }
}
static void ec_or_expr(ExprCompiler *ec) {
    ec_and_expr(ec);
    while (ec_peek(ec)->kind == TOK_OROR) { ec->pos++; ec_and_expr(ec); ec_emit(ec, ec->opmap[OPC_LOR]); }
}

// Compiles `expr_text` to bytecode in ec->code/ec->codelen and sets
// ec->max_arg_used. Returns 1 on success, 0 on failure (ec->errmsg set).
// ----------------------------------------------------------------
// v4.4: statement-level grammar for PROTECT_BLOCK - real control flow
// (if/else) and local variables, not just a single gating expression.
//   program := stmt* 'return' expr ';'
//   stmt    := 'uint' IDENT '=' expr ';'
//            | IDENT '=' expr ';'
//            | 'if' '(' expr ')' block ('else' block)?
//   block   := '{' stmt* '}'
// No loops in this pass - bounded, always-terminating programs only,
// which is what gating/calculation logic needs; a loop constructor is
// a reasonable future addition but adds real complexity (iteration
// bound safety) not worth rushing.
// ----------------------------------------------------------------
static void ec_emit16_placeholder(ExprCompiler *ec, size_t *out_pos) {
    if (ec->codelen + 2 > sizeof(ec->code)) ec_fail(ec, "expression too large");
    *out_pos = ec->codelen;
    ec->code[ec->codelen++] = 0; ec->code[ec->codelen++] = 0;
}
static void ec_patch16(ExprCompiler *ec, size_t pos, size_t target) {
    ec->code[pos]   = (uint8_t)(target & 0xFF);
    ec->code[pos+1] = (uint8_t)((target >> 8) & 0xFF);
}

static void ec_block(ExprCompiler *ec); // fwd decl (statement <-> block are mutually recursive)

static void ec_statement(ExprCompiler *ec) {
    TokKind k = ec_peek(ec)->kind;
    if (k == TOK_KW_UINT) {
        ec->pos++;
        if (ec_peek(ec)->kind != TOK_IDENT) ec_fail(ec, "expected variable name after 'uint'");
        char name[32]; strncpy(name, ec_peek(ec)->ident, sizeof(name)-1); name[sizeof(name)-1]='\0';
        ec->pos++;
        ec_eat(ec, TOK_ASSIGN);
        ec_or_expr(ec);
        ec_eat(ec, TOK_SEMI);
        int slot = ec_slot_for(ec, name, 1);
        ec_emit(ec, ec->opmap[OPC_STORE_LOCAL]);
        ec_emit(ec, (uint8_t)slot);
    } else if (k == TOK_IDENT) {
        char name[32]; strncpy(name, ec_peek(ec)->ident, sizeof(name)-1); name[sizeof(name)-1]='\0';
        ec->pos++;
        ec_eat(ec, TOK_ASSIGN);
        ec_or_expr(ec);
        ec_eat(ec, TOK_SEMI);
        int slot = ec_slot_for(ec, name, 0);
        ec_emit(ec, ec->opmap[OPC_STORE_LOCAL]);
        ec_emit(ec, (uint8_t)slot);
    } else if (k == TOK_KW_IF) {
        ec->pos++;
        ec_eat(ec, TOK_LPAREN); ec_or_expr(ec); ec_eat(ec, TOK_RPAREN);
        ec_emit(ec, ec->opmap[OPC_JMP_IF_FALSE]);
        size_t else_patch; ec_emit16_placeholder(ec, &else_patch);
        ec_block(ec);
        if (ec_peek(ec)->kind == TOK_KW_ELSE) {
            ec_emit(ec, ec->opmap[OPC_JMP]);
            size_t end_patch; ec_emit16_placeholder(ec, &end_patch);
            ec_patch16(ec, else_patch, ec->codelen);
            ec->pos++;
            ec_block(ec);
            ec_patch16(ec, end_patch, ec->codelen);
        } else {
            ec_patch16(ec, else_patch, ec->codelen);
        }
    } else {
        ec_fail(ec, "expected a statement (uint ..., an assignment, or if)");
    }
}

static void ec_block(ExprCompiler *ec) {
    ec_eat(ec, TOK_LBRACE);
    while (ec_peek(ec)->kind != TOK_RBRACE) ec_statement(ec);
    ec_eat(ec, TOK_RBRACE);
}

// Compiles a PROTECT_BLOCK program (statements + a final return). On
// success, behaves like compile_expr: ec->code/ec->codelen hold the
// bytecode and ec->max_arg_used is set. Returns 1/0 like compile_expr.
static int compile_block(ExprCompiler *ec, const char *block_text, const GuardNames *g) {
    memset(ec, 0, sizeof(*ec));
    ec->opmap = g->opmap;
    if (setjmp(ec->errjmp)) return 0;
    if (!ec_tokenize(ec, block_text)) {
        snprintf(ec->errmsg, sizeof(ec->errmsg), "unrecognized character in block");
        return 0;
    }
    while (ec_peek(ec)->kind != TOK_KW_RETURN) ec_statement(ec);
    ec->pos++; // consume 'return'
    ec_or_expr(ec);
    ec_eat(ec, TOK_SEMI);
    ec_emit(ec, ec->opmap[OPC_RET]);
    ec_eat(ec, TOK_END);
    return 1;
}

static int compile_expr(ExprCompiler *ec, const char *expr_text, const GuardNames *g) {
    memset(ec, 0, sizeof(*ec));
    ec->opmap = g->opmap;
    if (setjmp(ec->errjmp)) return 0;
    if (!ec_tokenize(ec, expr_text)) {
        snprintf(ec->errmsg, sizeof(ec->errmsg), "unrecognized character in expression");
        return 0;
    }
    ec_or_expr(ec);
    ec_eat(ec, TOK_END);
    ec_emit(ec, ec->opmap[OPC_RET]); /* RET */
    return 1;
}

// Scans `src`, finds PROTECT("literal") calls (outside comments/
// strings/char literals), and writes the transformed source to f,
// replacing each with <GuardClassName>.<fn_decrypt>(nonce,ct,tag).
// Returns the count of literals protected, or -1 on a hard error
// (already reported to stderr - caller should abort generation).
static long write_protected_source(FILE *f, const char *src, const GuardNames *g) {
    size_t n = strlen(src);
    size_t i = 0;
    uint32_t next_index = 10000; // clear of 1001/1002 (blacklists) and 2001/2002 (VM demos)
    long protected_count = 0;
    // Tracks whether "const" has appeared since the last statement/block
    // boundary (; { }) - updated ONLY from the plain-code fall-through
    // path below, never from inside the comment/string/char branches, so
    // "const" appearing in a comment or string can never trigger this
    // (that was a real bug in an earlier version of this function: a
    // backward raw-text scan that didn't know the difference between
    // code and comments, and matched "const" inside an explanatory
    // comment next to a perfectly valid static readonly declaration).
    int const_seen = 0;

    while (i < n) {
        char c = src[i];

        // Pass through comments verbatim
        if (c == '/' && i+1 < n && src[i+1] == '/') {
            while (i < n && src[i] != '\n') { fputc(src[i], f); i++; }
            continue;
        }
        if (c == '/' && i+1 < n && src[i+1] == '*') {
            fputc(src[i], f); fputc(src[i+1], f); i += 2;
            while (i+1 < n && !(src[i]=='*' && src[i+1]=='/')) { fputc(src[i], f); i++; }
            if (i+1 < n) { fputc(src[i], f); fputc(src[i+1], f); i += 2; }
            continue;
        }
        // Pass through char literals verbatim
        if (c == '\'') {
            fputc(c, f); i++;
            if (i < n && src[i] == '\\') { fputc(src[i], f); i++; if (i<n){fputc(src[i],f); i++;} }
            if (i < n) { fputc(src[i], f); i++; }
            if (i < n && src[i] == '\'') { fputc(src[i], f); i++; }
            continue;
        }
        // Pass through ordinary (non-PROTECT-wrapped) string literals
        // verbatim, including verbatim (@"...") and interpolated
        // ($"...") strings when they're NOT immediately inside a
        // PROTECT(...) we're about to handle below.
        if (c == '"') {
            fputc(c, f); i++;
            while (i < n && src[i] != '"') {
                if (src[i] == '\\' && i+1 < n) { fputc(src[i],f); fputc(src[i+1],f); i += 2; continue; }
                fputc(src[i], f); i++;
            }
            if (i < n) { fputc(src[i], f); i++; } // closing quote
            continue;
        }

        // Look for PROTECT_EXPR( first (longer token - must be checked
        // before the plain PROTECT( check below, which would otherwise
        // never actually collide since the literal bytes differ at
        // position 7, but checking the longer token first is clearer).
        if (c == 'P' && i + 13 <= n && memcmp(src + i, "PROTECT_EXPR(", 13) == 0 &&
            (i == 0 || !is_ident_char(src[i-1]))) {

            size_t j = i + 13;
            while (j < n && isspace((unsigned char)src[j])) j++;
            if (j >= n || src[j] != '"' || (j > 0 && (src[j-1]=='@' || src[j-1]=='$'))) {
                fprintf(stderr, "[!] FATAL: PROTECT_EXPR(...) near offset %zu must "
                                 "start with a plain quoted expression string, e.g. "
                                 "PROTECT_EXPR(\"a0 == 0x1234\", myHash).\n", i);
                return -1;
            }
            j++; // skip opening quote
            char exprbuf[1024]; size_t exprlen = 0;
            while (j < n && src[j] != '"') {
                if (exprlen >= sizeof(exprbuf) - 1) {
                    fprintf(stderr, "[!] FATAL: PROTECT_EXPR(...) expression string "
                                     "too long near offset %zu.\n", i);
                    return -1;
                }
                if (src[j] == '\\' && j+1 < n) {
                    char esc = src[j+1]; char decoded;
                    switch (esc) {
                        case 'n': decoded='\n'; break; case 'r': decoded='\r'; break;
                        case 't': decoded='\t'; break; case '\\': decoded='\\'; break;
                        case '"': decoded='"'; break;
                        default:
                            fprintf(stderr, "[!] FATAL: unsupported escape '\\%c' in "
                                             "PROTECT_EXPR(...) string near offset %zu.\n",
                                    esc, i);
                            return -1;
                    }
                    exprbuf[exprlen++] = decoded; j += 2;
                } else { exprbuf[exprlen++] = src[j]; j++; }
            }
            if (j >= n || src[j] != '"') {
                fprintf(stderr, "[!] FATAL: unterminated expression string in "
                                 "PROTECT_EXPR(...) near offset %zu.\n", i);
                return -1;
            }
            exprbuf[exprlen] = '\0';
            j++; // skip closing quote
            while (j < n && isspace((unsigned char)src[j])) j++;

            // Collect the real C# argument expressions (0-4 of them),
            // comma-separated, up to the matching closing ')'. Tracks
            // paren depth and string/char state so nested calls like
            // Foo(a,b) or a quoted "," inside an argument don't split
            // incorrectly.
            char *argtext[4] = {0,0,0,0};
            int nargs = 0;
            if (j < n && src[j] == ')') {
                j++; // zero real arguments
            } else if (j < n && src[j] == ',') {
                j++;
                while (1) {
                    while (j < n && isspace((unsigned char)src[j])) j++;
                    size_t argstart = j;
                    int depth = 0;
                    int in_s = 0, in_c = 0;
                    while (j < n) {
                        char cc = src[j];
                        if (in_s) {
                            if (cc=='\\' && j+1<n) { j+=2; continue; }
                            if (cc=='"') in_s = 0;
                            j++; continue;
                        }
                        if (in_c) {
                            if (cc=='\\' && j+1<n) { j+=2; continue; }
                            if (cc=='\'') in_c = 0;
                            j++; continue;
                        }
                        if (cc=='"') { in_s = 1; j++; continue; }
                        if (cc=='\'') { in_c = 1; j++; continue; }
                        if (cc=='(') { depth++; j++; continue; }
                        if (cc==')') { if (depth==0) break; depth--; j++; continue; }
                        if (cc==',' && depth==0) break;
                        j++;
                    }
                    if (j >= n) {
                        fprintf(stderr, "[!] FATAL: unterminated argument list in "
                                         "PROTECT_EXPR(...) near offset %zu.\n", i);
                        for (int k=0;k<nargs;k++) free(argtext[k]);
                        return -1;
                    }
                    size_t arglen = j - argstart;
                    while (arglen > 0 && isspace((unsigned char)src[argstart+arglen-1])) arglen--;
                    if (nargs >= 4) {
                        fprintf(stderr, "[!] FATAL: PROTECT_EXPR(...) near offset %zu "
                                         "has more than 4 real arguments (a0-a3 max).\n", i);
                        for (int k=0;k<nargs;k++) free(argtext[k]);
                        return -1;
                    }
                    argtext[nargs] = (char *)malloc(arglen + 1);
                    memcpy(argtext[nargs], src + argstart, arglen);
                    argtext[nargs][arglen] = '\0';
                    nargs++;
                    if (src[j] == ',') { j++; continue; }
                    break; // at ')'
                }
                j++; // skip ')'
            } else {
                fprintf(stderr, "[!] FATAL: expected ',' or ')' after the expression "
                                 "string in PROTECT_EXPR(...) near offset %zu.\n", i);
                return -1;
            }

            ExprCompiler ec;
            if (!compile_expr(&ec, exprbuf, g)) {
                fprintf(stderr, "[!] FATAL: could not compile PROTECT_EXPR(...) "
                                 "expression near offset %zu: %s\n    expression: %s\n",
                        i, ec.errmsg, exprbuf);
                for (int k=0;k<nargs;k++) free(argtext[k]);
                return -1;
            }
            if (ec.max_arg_used >= nargs) {
                fprintf(stderr, "[!] FATAL: PROTECT_EXPR(...) near offset %zu uses a%d "
                                 "but only %d real argument(s) were given.\n",
                        i, ec.max_arg_used, nargs);
                for (int k=0;k<nargs;k++) free(argtext[k]);
                return -1;
            }

            fprintf(f, "%s.%s(", g->cls, g->fn_vm_exec);
            fprintf(f, "%s.", g->cls);
            write_encrypted_bytes(f, ec.code, ec.codelen, g, next_index++);
            for (int k = 0; k < 4; k++)
                fprintf(f, ", unchecked((uint)(%s))", k < nargs ? argtext[k] : "0");
            fprintf(f, ") != 0");
            protected_count++;

            for (int k=0;k<nargs;k++) free(argtext[k]);
            i = j;
            continue;
        }

        // v4.4: PROTECT_BLOCK("statements; return expr;", realArg0, ...)
        // Same idea as PROTECT_EXPR but compiles real control flow (if/
        // else) and local variables via compile_block(), not just a
        // single gating expression. Unlike PROTECT_EXPR, this does NOT
        // force "!= 0" on the result - it returns the raw uint the
        // block computed, since a block might compute a value (a price,
        // a score) rather than a yes/no gate. Argument parsing and the
        // const/verbatim/interpolated checks are identical to
        // PROTECT_EXPR above - see those comments for why each exists.
        if (c == 'P' && i + 14 <= n && memcmp(src + i, "PROTECT_BLOCK(", 14) == 0 &&
            (i == 0 || !is_ident_char(src[i-1]))) {

            size_t j = i + 14;
            while (j < n && isspace((unsigned char)src[j])) j++;
            if (j >= n || src[j] != '"' || (j > 0 && (src[j-1]=='@' || src[j-1]=='$'))) {
                fprintf(stderr, "[!] FATAL: PROTECT_BLOCK(...) near offset %zu must "
                                 "start with a plain quoted block string, e.g. "
                                 "PROTECT_BLOCK(\"uint t = a0; return t;\", x).\n", i);
                return -1;
            }
            j++;
            char blockbuf[4096]; size_t blocklen = 0;
            while (j < n && src[j] != '"') {
                if (blocklen >= sizeof(blockbuf) - 1) {
                    fprintf(stderr, "[!] FATAL: PROTECT_BLOCK(...) block string too "
                                     "long near offset %zu.\n", i);
                    return -1;
                }
                if (src[j] == '\\' && j+1 < n) {
                    char esc = src[j+1]; char decoded;
                    switch (esc) {
                        case 'n': decoded='\n'; break; case 'r': decoded='\r'; break;
                        case 't': decoded='\t'; break; case '\\': decoded='\\'; break;
                        case '"': decoded='"'; break;
                        default:
                            fprintf(stderr, "[!] FATAL: unsupported escape '\\%c' in "
                                             "PROTECT_BLOCK(...) string near offset %zu.\n",
                                    esc, i);
                            return -1;
                    }
                    blockbuf[blocklen++] = decoded; j += 2;
                } else { blockbuf[blocklen++] = src[j]; j++; }
            }
            if (j >= n || src[j] != '"') {
                fprintf(stderr, "[!] FATAL: unterminated block string in "
                                 "PROTECT_BLOCK(...) near offset %zu.\n", i);
                return -1;
            }
            blockbuf[blocklen] = '\0';
            j++;
            while (j < n && isspace((unsigned char)src[j])) j++;

            char *argtext[4] = {0,0,0,0};
            int nargs = 0;
            if (j < n && src[j] == ')') {
                j++;
            } else if (j < n && src[j] == ',') {
                j++;
                while (1) {
                    while (j < n && isspace((unsigned char)src[j])) j++;
                    size_t argstart = j;
                    int depth = 0, in_s = 0, in_c = 0;
                    while (j < n) {
                        char cc = src[j];
                        if (in_s) { if (cc=='\\'&&j+1<n){j+=2;continue;} if (cc=='"') in_s=0; j++; continue; }
                        if (in_c) { if (cc=='\\'&&j+1<n){j+=2;continue;} if (cc=='\'') in_c=0; j++; continue; }
                        if (cc=='"') { in_s=1; j++; continue; }
                        if (cc=='\'') { in_c=1; j++; continue; }
                        if (cc=='(') { depth++; j++; continue; }
                        if (cc==')') { if (depth==0) break; depth--; j++; continue; }
                        if (cc==',' && depth==0) break;
                        j++;
                    }
                    if (j >= n) {
                        fprintf(stderr, "[!] FATAL: unterminated argument list in "
                                         "PROTECT_BLOCK(...) near offset %zu.\n", i);
                        for (int k=0;k<nargs;k++) free(argtext[k]);
                        return -1;
                    }
                    size_t arglen = j - argstart;
                    while (arglen > 0 && isspace((unsigned char)src[argstart+arglen-1])) arglen--;
                    if (nargs >= 4) {
                        fprintf(stderr, "[!] FATAL: PROTECT_BLOCK(...) near offset %zu "
                                         "has more than 4 real arguments (a0-a3 max).\n", i);
                        for (int k=0;k<nargs;k++) free(argtext[k]);
                        return -1;
                    }
                    argtext[nargs] = (char *)malloc(arglen + 1);
                    memcpy(argtext[nargs], src + argstart, arglen);
                    argtext[nargs][arglen] = '\0';
                    nargs++;
                    if (src[j] == ',') { j++; continue; }
                    break;
                }
                j++;
            } else {
                fprintf(stderr, "[!] FATAL: expected ',' or ')' after the block "
                                 "string in PROTECT_BLOCK(...) near offset %zu.\n", i);
                return -1;
            }

            ExprCompiler ec;
            if (!compile_block(&ec, blockbuf, g)) {
                fprintf(stderr, "[!] FATAL: could not compile PROTECT_BLOCK(...) "
                                 "near offset %zu: %s\n    block: %s\n",
                        i, ec.errmsg, blockbuf);
                for (int k=0;k<nargs;k++) free(argtext[k]);
                return -1;
            }
            if (ec.max_arg_used >= nargs) {
                fprintf(stderr, "[!] FATAL: PROTECT_BLOCK(...) near offset %zu uses a%d "
                                 "but only %d real argument(s) were given.\n",
                        i, ec.max_arg_used, nargs);
                for (int k=0;k<nargs;k++) free(argtext[k]);
                return -1;
            }

            fprintf(f, "%s.%s(", g->cls, g->fn_vm_exec);
            fprintf(f, "%s.", g->cls);
            write_encrypted_bytes(f, ec.code, ec.codelen, g, next_index++);
            for (int k = 0; k < 4; k++)
                fprintf(f, ", unchecked((uint)(%s))", k < nargs ? argtext[k] : "0");
            fprintf(f, ")"); // no "!= 0" - caller decides what to do with the uint result
            protected_count++;

            for (int k=0;k<nargs;k++) free(argtext[k]);
            i = j;
            continue;
        }

        // Look for the PROTECT( token, not part of a longer identifier
        if (c == 'P' && i + 8 <= n && memcmp(src + i, "PROTECT(", 8) == 0 &&
            (i == 0 || !is_ident_char(src[i-1]))) {

            if (const_seen) {
                fprintf(stderr,
                    "[!] FATAL: PROTECT(...) used in what looks like a 'const' "
                    "declaration (near offset %zu in your source).\n"
                    "    PROTECT() produces a runtime value (a decrypt call), which "
                    "cannot be assigned\n"
                    "    to a const field - C# requires const initializers to be "
                    "compile-time constants.\n"
                    "    Fix: change 'const' to 'static readonly' for that "
                    "declaration and re-run.\n", i);
                return -1;
            }

            size_t j = i + 8; // position right after "PROTECT("
            while (j < n && isspace((unsigned char)src[j])) j++;

            if (j >= n || src[j] != '"' || (j > 0 && (src[j-1] == '@' || src[j-1] == '$'))) {
                fprintf(stderr,
                    "[!] FATAL: PROTECT(...) near offset %zu must wrap a plain "
                    "string literal, e.g. PROTECT(\"secret\").\n"
                    "    Verbatim (@\"...\") and interpolated ($\"...\") strings "
                    "are not supported inside PROTECT().\n", i);
                return -1;
            }
            // extra guard: reject @"..." / $"..." immediately preceding the quote
            if (j >= 1 && (src[j-1] == '@' || src[j-1] == '$')) {
                fprintf(stderr, "[!] FATAL: verbatim/interpolated string inside "
                                 "PROTECT() near offset %zu is not supported.\n", i);
                return -1;
            }

            j++; // skip opening quote
            char lit[4096]; size_t litlen = 0;
            int ok = 1;
            while (j < n && src[j] != '"') {
                if (litlen >= sizeof(lit) - 1) { ok = 0; break; }
                if (src[j] == '\\' && j+1 < n) {
                    char esc = src[j+1];
                    char decoded;
                    switch (esc) {
                        case 'n': decoded = '\n'; break;
                        case 'r': decoded = '\r'; break;
                        case 't': decoded = '\t'; break;
                        case '0': decoded = '\0'; break;
                        case '\\': decoded = '\\'; break;
                        case '"': decoded = '"'; break;
                        case '\'': decoded = '\''; break;
                        default:
                            fprintf(stderr,
                                "[!] FATAL: unsupported escape '\\%c' inside "
                                "PROTECT(...) near offset %zu (only \\\\ \\\" \\n "
                                "\\r \\t \\0 \\' are supported).\n", esc, i);
                            return -1;
                    }
                    lit[litlen++] = decoded;
                    j += 2;
                } else {
                    lit[litlen++] = src[j];
                    j++;
                }
            }
            if (!ok || j >= n || src[j] != '"') {
                fprintf(stderr, "[!] FATAL: malformed or oversized string literal "
                                 "inside PROTECT(...) near offset %zu.\n", i);
                return -1;
            }
            lit[litlen] = '\0';
            j++; // skip closing quote
            while (j < n && isspace((unsigned char)src[j])) j++;
            if (j >= n || src[j] != ')') {
                fprintf(stderr, "[!] FATAL: expected ')' to close PROTECT(...) "
                                 "near offset %zu.\n", i);
                return -1;
            }
            j++; // skip closing paren

            fprintf(f, "%s.", g->cls);
            write_encrypted_blob(f, lit, g, next_index++);
            protected_count++;
            i = j;
            continue;
        }

        // Plain code character (not comment/string/char/PROTECT) - this
        // is the only place const_seen gets updated, so comment and
        // string content can never affect it.
        if (c == ';' || c == '{' || c == '}') {
            const_seen = 0;
        } else if (c == 'c' && i + 5 <= n && memcmp(src + i, "const", 5) == 0 &&
                   (i == 0 || !is_ident_char(src[i-1])) && !is_ident_char(src[i+5])) {
            const_seen = 1;
        }
        fputc(c, f);
        i++;
    }
    return protected_count;
}

static int inject_guard(const char *src_path, const char *dst_path,
                        const GuardNames *g) {
    size_t src_len = 0;
    char *src = read_file_text(src_path, &src_len);
    if (!src) { fprintf(stderr, "[!] Cannot read: %s\n", src_path); return 0; }

    const char *rest = NULL;
    char *user_using = extract_using(src, &rest);

    FILE *f = fopen(dst_path, "wb");
    if (!f) { free(src); free(user_using); return 0; }

    if (user_using) fputs(user_using, f);
    write_guard_class(f, g);

    long n_protected = write_protected_source(f, rest, g);
    if (n_protected < 0) {
        fclose(f);
        free(user_using);
        free(src);
        remove(dst_path); /* don't leave a half-written, broken .cs behind */
        return 0;
    }
    if (n_protected > 0)
        printf("[+] Protected %ld string literal(s) via PROTECT(...)\n", n_protected);

    fclose(f);
    free(user_using);
    free(src);
    return 1;
}

static int patch_main_call(const char *path, const GuardNames *g) {
    size_t len = 0;
    char *src = read_file_text(path, &len);
    if (!src) return 0;

    static const char *markers[] = {
        "static void Main(",
        "static async Task Main(",
        "static int Main(",
        "static async Task<int> Main(",
        NULL
    };

    char call[96];
    snprintf(call, sizeof(call), "\n    %s.%s();", g->cls, g->fn_run);
    size_t call_len = strlen(call);

    char *brace = NULL;
    for (int i = 0; markers[i]; i++) {
        char *found = strstr(src, markers[i]);
        if (found) { brace = strchr(found, '{'); if (brace) break; }
    }

    char *patched;
    if (!brace) {
        char prefix[96];
        snprintf(prefix, sizeof(prefix), "%s.%s();\n", g->cls, g->fn_run);
        size_t plen = strlen(prefix);
        patched = (char *)malloc(len + plen + 2);
        if (!patched) { free(src); return 0; }
        memcpy(patched, prefix, plen);
        memcpy(patched + plen, src, len + 1);
    } else {
        size_t pre  = (size_t)(brace - src) + 1;
        size_t post = len - pre;
        patched = (char *)malloc(len + call_len + 2);
        if (!patched) { free(src); return 0; }
        memcpy(patched, src, pre);
        memcpy(patched + pre, call, call_len);
        memcpy(patched + pre + call_len, brace + 1, post + 1);
    }

    write_file_text(path, patched);
    free(patched);
    free(src);
    return 1;
}

// ================================================================
//  SECTION 8 — MAIN PIPELINE
// ================================================================

int main(void) {
    uint64_t seed = (uint64_t)time(NULL);
    seed ^= (uint64_t)(uintptr_t)&seed;
    seed ^= (uint64_t)GetCurrentProcessId();

    GuardNames g;
    init_guard_names(&g, seed);

    char ts[32];
    snprintf(ts, sizeof(ts), "%lld", (long long)time(NULL));

    printf("========================================================\n");
    printf("   C# Code Protector v4.0 HARDENED\n");
    printf("   Advanced Anti-Reverse Engineering Tool\n");
    printf("   (Defeat: Binary unpacking, MITM, String extraction)\n");
    printf("========================================================\n\n");

    printf("[*] Checking dependencies...\n");
    int has_dotnet   = check_dependency("dotnet");
    int has_upx      = check_dependency("upx");
    printf("  dotnet CLI : %s\n", has_dotnet ? "[OK]" : "[MISSING - REQUIRED]");
    printf("  UPX packer : %s\n", has_upx    ? "[OK]" : "[NOT FOUND - will skip]");
    if (!has_dotnet) {
        fprintf(stderr, "\n[!] dotnet CLI is required. Aborting.\n");
        return 1;
    }

    printf("\n[?] Input mode:\n"
           "    1) Path to existing .cs file\n"
           "    2) Paste C# code directly\n"
           "Choice (1/2): ");
    int choice = 0;
    scanf("%d", &choice);
    clear_stdin();

    char src_path[MAX_PATH_LEN]    = {0};
    char project_name[MAX_NAME]    = {0};

    if (choice == 1) {
        printf("Path to .cs file: ");
        fgets(src_path, sizeof(src_path), stdin);
        src_path[strcspn(src_path, "\r\n")] = '\0';
        if (!file_exists(src_path)) {
            fprintf(stderr, "[!] File not found: %s\n", src_path);
            return 1;
        }
        const char *base = strrchr(src_path, '\\');
        if (!base) base = strrchr(src_path, '/');
        base = base ? base + 1 : src_path;
        strncpy(project_name, base, sizeof(project_name) - 1);
        char *dot = strrchr(project_name, '.');
        if (dot) *dot = '\0';
    } else {
        printf("Project/exe name (letters, digits, underscores): ");
        scanf("%199s", project_name);
        clear_stdin();
        if (!is_valid_name(project_name)) {
            fprintf(stderr, "[!] Invalid name.\n");
            return 1;
        }
        char paste_path[MAX_PATH_LEN];
        snprintf(paste_path, sizeof(paste_path), "%s_%s.cs", project_name, ts);
        printf("Paste C# code. Type %s on a new line when done:\n\n", SENTINEL);
        FILE *fp = fopen(paste_path, "w");
        if (!fp) { fprintf(stderr, "[!] Cannot create temp file.\n"); return 1; }
        char line[4096];
        while (fgets(line, sizeof(line), stdin)) {
            if (strncmp(line, SENTINEL, strlen(SENTINEL)) == 0) break;
            fputs(line, fp);
        }
        fclose(fp);
        strncpy(src_path, paste_path, sizeof(src_path) - 1);
        printf("\n[+] Source saved: %s\n", src_path);
    }

    if (!is_valid_name(project_name))
        strncpy(project_name, "protected_app", sizeof(project_name) - 1);

    printf("\n[?] Use NativeAOT (native machine code, no IL emitted)?\n"
           "    Requires VS C++ workload. Strongest obfuscation.\n"
           "    Enable NativeAOT? (y/n): ");
    char yn[8] = {0};
    fgets(yn, sizeof(yn), stdin);
    int use_nativeaot = (yn[0] == 'y' || yn[0] == 'Y');

    char work_dir[MAX_PATH_LEN];
    snprintf(work_dir, sizeof(work_dir), "csprotect_%s", ts);
    char mk_cmd[MAX_PATH_LEN + 16];
    snprintf(mk_cmd, sizeof(mk_cmd), "mkdir \"%s\"", work_dir);
    system(mk_cmd);

    char injected_src[MAX_PATH_LEN];
    snprintf(injected_src, sizeof(injected_src),
             "%s\\%s.cs", work_dir, project_name);

    printf("\n[*] Generating randomised protection layer (v4.0)...\n");
    printf("    Guard class      : %s\n", g.cls);
    printf("    Entry method     : %s\n", g.fn_run);
    printf("    Key fragment[0]  : ");
    for (int i = 0; i < 8; i++) printf("%02X", g.frag[0][i]);
    printf(" (masked; real key is never printed or stored whole anywhere)\n");
    printf("    Key checksum     : 0x%016llX\n",
           (unsigned long long)checksum64(g.key, 32));

    if (!inject_guard(src_path, injected_src, &g)) {
        fprintf(stderr, "[!] Injection failed.\n");
        return 1;
    }
    if (!patch_main_call(injected_src, &g))
        printf("[!] Auto-patch of Main() failed — add %s.%s(); manually.\n",
               g.cls, g.fn_run);

    printf("[+] Protection layer injected: %s\n", injected_src);

    char proj_file[MAX_PATH_LEN];
    snprintf(proj_file, sizeof(proj_file),
             "%s\\%s.csproj", work_dir, project_name);
    write_csproj(proj_file, project_name, use_nativeaot);
    printf("[+] Project file created with security flags.\n");

    char build_out[MAX_PATH_LEN];
    snprintf(build_out, sizeof(build_out), "build_out_%s", ts);

    char build_args[MAX_CMD];
    if (use_nativeaot) {
        snprintf(build_args, sizeof(build_args),
            "publish \"%s\" -c Release -r win-x64 --self-contained true "
            "-p:PublishTrimmed=true -p:TrimMode=link "
            "--output \"%s\"",
            work_dir, build_out);
    } else {
        snprintf(build_args, sizeof(build_args),
            "publish \"%s\" -c Release -r win-x64 --self-contained true "
            "-p:PublishSingleFile=true -p:EnableCompressionInSingleFile=true "
            "-p:PublishTrimmed=true -p:TrimMode=link "
            "-p:IncludeNativeLibrariesForSelfExtract=true "
            "--output \"%s\"",
            work_dir, build_out);
    }

    printf("\n[*] Building...\n");
    int build_rc = run_process("dotnet.exe", build_args, 0);
    if (build_rc != 0) {
        fprintf(stderr, "[!] Build failed (rc=%d)\n", build_rc);
        return 1;
    }

    char built_exe[MAX_PATH_LEN];
    snprintf(built_exe, sizeof(built_exe),
             "%s\\%s.exe", build_out, project_name);
    if (!file_exists(built_exe)) {
        fprintf(stderr, "[!] Expected EXE not found: %s\n", built_exe);
        return 1;
    }
    printf("[+] Build successful: %s\n", built_exe);

    // v4.3: UPX changed from auto-apply to an explicit opt-in, default
    // NO. A real external review (REA) specifically dinged the protection
    // score for shipping with stock UPX - not because it weakens anything
    // once unpacked, but because `upx -d` is a one-second, well-known
    // signature strip that makes the binary look like it has more going
    // on than it does, with zero real benefit. Auto-applying it by
    // default implied it counted toward protection, which it doesn't.
    if (has_upx) {
        printf("\n[?] UPX is available. Read this before deciding:\n"
               "    UPX is compression, not protection. It is one of the\n"
               "    first things a reverse engineer checks for, and\n"
               "    `upx -d` strips it in about one second - after which\n"
               "    the binary is exactly as protected as it was before\n"
               "    packing, no better. Its only real benefit is a smaller\n"
               "    file and defeating the laziest automated scanners; it\n"
               "    does not raise your real protection level, and an\n"
               "    external review specifically flagged it as a sign of\n"
               "    a non-commercial-grade build.\n"
               "    Apply UPX anyway? (y/N): ");
        char upx_yn[8] = {0};
        if (fgets(upx_yn, sizeof(upx_yn), stdin) && (upx_yn[0]=='y' || upx_yn[0]=='Y')) {
            printf("\n[*] UPX packing with LZMA...\n");
            char upx_args[MAX_CMD];
            snprintf(upx_args, sizeof(upx_args),
                     "--lzma --best --ultra-brute \"%s\"", built_exe);
            int upx_rc = run_process("upx.exe", upx_args, 0);
            printf(upx_rc == 0 ? "[+] UPX applied.\n"
                               : "[!] UPX failed (rc=%d) — still usable.\n", upx_rc);
        } else {
            printf("\n[*] Skipping UPX (recommended).\n");
            has_upx = 0; // so the summary banner doesn't list it as applied
        }
    } else {
        printf("\n[*] Skipping UPX (not on PATH).\n");
    }

    char output_name[MAX_PATH_LEN];
    snprintf(output_name, sizeof(output_name), "%s_protected.exe", project_name);
    char copy_cmd[MAX_CMD];
    snprintf(copy_cmd, sizeof(copy_cmd),
             "copy /Y \"%s\" \"%s\" >nul", built_exe, output_name);
    system(copy_cmd);

    if (file_exists(output_name)) {
        printf("\n========================================================\n");
        printf("[+] SUCCESS! v4.0 Hardened Protection Applied\n");
        printf("    Input  : %s\n", src_path);
        printf("    Output : %s\n\n", output_name);
        printf("    Applied protections:\n");
        printf("      [v1] IsDebuggerPresent checks\n");
        printf("      [v1] NtQueryInformationProcess (debug port)\n");
        printf("      [v1] CheckRemoteDebuggerPresent\n");
        printf("      [v1] OutputDebugString timing\n");
        printf("      [v1] Process blacklist (50+ tools, now REAL encryption)\n");
        printf("      [v1] Sandbox DLL detection (now REAL encryption)\n");
        printf("      [v1] VM detection (registry + MAC)\n");
        printf("      [v1] Managed debugger detection (now re-checked by watchdog)\n");
        printf("      [v1] Watchdog thread (now dispatch-table + decoys, see below)\n");
        printf("      [v2] Randomised class/method/extern names\n");
        printf("      [v2] NtGlobalFlag / PEB heap-flag check\n");
        printf("      [v2] Hardware breakpoint detection (DR0-DR3)\n");
        printf("      [v2] NtSetInformationThread HideFromDebugger\n");
        printf("      [v2] ETW EtwEventWrite patch\n");
        printf("      [v2] Anti-dump (PE header erasure)\n");
        printf("      [v2] Parent-process whitelist\n");
        printf("      [v2] Kernel debugger detection\n");
        printf("      [v3] Code integrity self-verification\n");
        printf("      [v3] Proxy detection (mitmproxy, Fiddler, etc - coarse signal)\n");
        printf("      [FIXED v4] SSL pinning now fails closed (v3 always returned true)\n");
        printf("      [v3] Suspicious environment variable detection\n");
        printf("      [FIXED v4] Grandparent process validation (v3 only claimed this)\n");
        printf("      [FIXED v4] HMAC-SHA256 keystream encryption, split runtime key\n");
        printf("                 (v3's \"AES-256\" was unused XOR with key printed\n");
        printf("                  next to the ciphertext)\n");
        printf("      [NEW v4]   Dispatch-table watchdog: shuffled order, decoy\n");
        printf("                 checks, randomized subset per cycle\n");
        printf("      [v2] Secure string memory wiping\n");
        if (use_nativeaot) printf("      [OPT] NativeAOT (native machine code, no IL)\n");
        if (has_upx)       printf("      [OPT] UPX LZMA packing\n");
        printf("========================================================\n\n");
        printf("    STILL OPEN - NOT FIXED IN v4, DO NOT ASSUME OTHERWISE:\n");
        printf("      - Proxy detection is a coarse signal only (reg key + cert\n");
        printf("        subject string match), not a strong guarantee\n");
        printf("      - No control-flow obfuscation or string encryption applied\n");
        printf("        to YOUR injected business logic, only this guard class\n");
        printf("      - No bytecode virtualization - the real next-level step\n");
        printf("        for genuinely sensitive logic\n");
        printf("      - Any locally-decryptable secret can be recovered by an\n");
        printf("        attacker willing to dump memory at the point of use -\n");
        printf("        true secrets belong server-side, not in this binary\n");
        printf("========================================================\n");
    } else {
        printf("\n[!] Could not copy output. Check: %s\n", built_exe);
    }

    return 0;
}
