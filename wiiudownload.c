/*
  wiiudownload - Download Wii U NUS content from Nintendo's CDN
  Converted from wiiu_cdndownload.py, tikgen.py, keygen.py
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <ctype.h>
#include <sys/stat.h>
#include <curl/curl.h>
#include <zlib.h>

#ifdef _WIN32
#include <windows.h>
#endif

#include "utf8.h"
#include "util.h"
#include "aes.h"
#include "sha1.h"
#include "md5.h"

#ifndef SHA_DIGEST_LENGTH
#define SHA_DIGEST_LENGTH 20
#endif

// DIR_MAX   — for directory paths (TID + "_v" + version digits)
// FPATH_MAX — for full file paths (dir + separator + filename)
// FPATH_MAX must be strictly larger than DIR_MAX + longest filename so
// GCC's format-truncation analysis is satisfied.
#define DIR_MAX   (PATH_MAX + 32)
#define FPATH_MAX (DIR_MAX  + 64)

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#define CDN_BASE  "http://ccs.cdn.c.shop.nintendowifi.net/ccs/download/"
#define DEF_PASS  "mypass"
#define TIK_SIZE  0x350

static const uint8_t WiiUCommonKey[16] = {
    0xD7, 0xB0, 0x04, 0x02, 0x65, 0x9B, 0xA2, 0xAB,
    0xD2, 0xCB, 0x0D, 0xB2, 0x7F, 0xA2, 0xB6, 0x56
};

static const char* const SYSTITLE_CATS[] = {
    "00050010", "0005001B", "00050030", "0005000E", NULL
};

// All known Wii U title versions to probe when downloading all versions
static const int KNOWN_VERSIONS[] = {
    0, 1, 2, 3, 4, 5, 6, 7, 15, 16,
    17, 18, 19, 22, 32, 33, 34, 48, 49, 50,
    64, 65, 80, 81, 82, 96, 97, 98, 112, 113,
    114, 128, 129, 144, 160, 161, 176, 192, 193, 208,
    209, 224, 240, 256, 272, 288, 304, 320, 336, 352,
    368, 384, 400, 416, 432, 448, 464, 480, 496, 512,
    528, 544, 560, 576, 592, 608, 624, 640, 656, 672,
    688, 704, 720, 736, 752, 768, 784, 800, 816, 832,
    848, 864, 880, 896, 912, 928, 944, 960, 976, 992,
    1008, 1024, 1040, 1056, 1072, 1088, 1104, 1120, 1136, 1152,
    1168, 1184, 1200, 1216, 1232, 1248, 1264, 1280, 1296, 1312,
    1328, 1344, 1360, 1376, 1392, 1408, 1424, 1440, 1456, 1472,
    1488, 1504, 1520, 1536, 1552, 1568, 1584, 1600, 1616, 1632,
    1648, 1664, 1680, 1696, 1712, 1728, 1744, 1760, 1776, 1792,
    1808, 1824, 1840, 1856, 1872, 1888, 1904, 1920, 1936, 1952,
    1968, 1984, 2000, 2016, 2032, 2048, 2064, 2080, 2096, 2112,
    2128, 2144, 2160, 2176, 2192, 2208, 2224, 2240, 2256, 2272,
    2288, 2304, 2320, 2336, 2352, 2384, 2400, 2416, 2432, 2448,
    2464, 2480, 2496, 2512, 2528, 2544, 2560, 2576, 2592, 2608,
    2624, 2640, 2656, 2672, 2688, 2704, 2720, 2736, 2752, 2768,
    2784, 2800, 2816, 2832, 2848, 2864, 2880, 2896, 2912, 2928,
    2944, 2960, 2976, 2992, 3008, 3024, 3040, 3056, 3072, 3088,
    3104, 3120, 3136, 3152, 3168, 3184, 3200, 3216, 3232, 3248,
    3264, 3280, 3296, 3312, 3328, 3344, 3360, 3376, 3392, 3408,
    3424, 3440, 3456, 3472, 3488, 3504, 3520, 3536, 3552, 3568,
    3584, 3600, 3616, 3632, 3648, 3664, 3680, 3696, 3744, 3760,
    3776, 3792, 3808, 3824, 3840, 3856, 3872, 3888, 3904, 3920,
    3936, 3952, 3968, 3984, 4000, 4016, 4032, 4048, 4064, 4080,
    4096, 4112, 4128, 4144, 4160, 4176, 4192, 4208, 4224, 4240,
    4256, 4272, 4288, 4304, 4320, 4336, 4352, 4368, 4384, 4400,
    4416, 4432, 4448, 4464, 4480, 4496, 4512, 4528, 4544, 4560,
    4576, 4592, 4608, 4624, 4640, 4656, 4672, 4688, 4704, 4720,
    4736, 4752, 4768, 4784, 4800, 4816, 4832, 4848, 4864, 4880,
    4896, 4912, 4928, 4944, 4960, 4976, 4992, 5008, 5024, 5040,
    5056, 5072, 5088, 5104, 5120, 5136, 5152, 5168, 5184, 5200,
    5216, 5232, 5248, 5264, 5280, 5296, 5312, 5328, 5344, 5360,
    5376, 5392, 5408, 5424, 5440, 5456, 5472, 5504, 5520, 5536,
    5552, 5568, 5584, 5600, 5616, 5632, 5648, 5664, 5680, 5696,
    5712, 5728, 5744, 5760, 5776, 5792, 5808, 5824, 5840, 5856,
    5872, 5888, 5904,
};
#define KNOWN_VERSIONS_COUNT (int)(sizeof(KNOWN_VERSIONS) / sizeof(KNOWN_VERSIONS[0]))

// base64(zlib(title.cert chain)) — verbatim from wiiu_cdndownload.py
static const char TITLECERT_B64[] = "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";

// ---------------------------------------------------------------------------
// wuptool integration
// ---------------------------------------------------------------------------

// Path to wuptool found at startup; empty string means not found.
static char g_wuptool_path[FPATH_MAX] = {0};

// Locate wuptool next to this executable, then fall back to CWD, then PATH.
// Returns true if a concrete file was found; false means PATH-only fallback.
static bool find_wuptool(void)
{
#ifdef _WIN32
    // 1. Same directory as wiiudownload.exe
    char self[MAX_PATH];
    if (GetModuleFileNameA(NULL, self, sizeof(self))) {
        char* sep = strrchr(self, '\\');
        if (!sep) sep = strrchr(self, '/');
        if (sep) {
            *(sep + 1) = '\0';
            snprintf(g_wuptool_path, sizeof(g_wuptool_path), "%swuptool.exe", self);
            struct stat st;
            if (stat(g_wuptool_path, &st) == 0) return true;
        }
    }
    // 2. Current working directory
    snprintf(g_wuptool_path, sizeof(g_wuptool_path), "wuptool.exe");
    {
        struct stat st;
        if (stat(g_wuptool_path, &st) == 0) return true;
    }
#else
    // 1. Current working directory
    snprintf(g_wuptool_path, sizeof(g_wuptool_path), "./wuptool");
    {
        struct stat st;
        if (stat(g_wuptool_path, &st) == 0) return true;
    }
#endif
    // 3. Rely on PATH — set a bare name and return false to indicate uncertainty
#ifdef _WIN32
    snprintf(g_wuptool_path, sizeof(g_wuptool_path), "wuptool.exe");
#else
    snprintf(g_wuptool_path, sizeof(g_wuptool_path), "wuptool");
#endif
    return false;
}

// Run: wuptool decrypt "<out_dir>"
// Quotes the directory path to handle spaces.
static void run_wuptool_decrypt(const char* out_dir)
{
    // Command buffer: wuptool path + " decrypt " + quoted dir + NUL
    char cmd[FPATH_MAX * 2 + 32];
    #ifdef _WIN32
	snprintf(cmd, sizeof(cmd), "cmd /c \"\"%s\" decrypt \"%s\"\"", g_wuptool_path, out_dir);
	#else
	snprintf(cmd, sizeof(cmd), "\"%s\" decrypt \"%s\"", g_wuptool_path, out_dir);
	#endif
    printf("\n--- Running wuptool ---\n%s\n", cmd);
    int ret = system(cmd);
    if (ret != 0)
        fprintf(stderr, "WARNING: wuptool decrypt exited with code %d for '%s'\n",
                ret, out_dir);
    else
        printf("--- wuptool finished ---\n");
}

// ---------------------------------------------------------------------------
// Memory buffer for curl downloads to RAM
// ---------------------------------------------------------------------------

typedef struct { uint8_t* data; size_t size; } MemBuf;

static size_t mem_write_cb(void* ptr, size_t size, size_t nmemb, void* ud)
{
    MemBuf* buf = (MemBuf*)ud;
    size_t add = size * nmemb;
    uint8_t* tmp = realloc(buf->data, buf->size + add + 1);
    if (!tmp) return 0;
    buf->data = tmp;
    memcpy(buf->data + buf->size, ptr, add);
    buf->size += add;
    buf->data[buf->size] = 0;
    return add;
}

static size_t file_write_cb(void* ptr, size_t size, size_t nmemb, void* ud)
{
    return fwrite(ptr, size, nmemb, (FILE*)ud);
}

// ---------------------------------------------------------------------------
// Progress display
// ---------------------------------------------------------------------------

typedef struct { const char* prefix; const char* suffix; } ProgressCtx;

static int progress_cb(void* ud, curl_off_t dltotal, curl_off_t dlnow,
                        curl_off_t ultotal, curl_off_t ulnow)
{
    (void)ultotal; (void)ulnow;
    ProgressCtx* ctx = (ProgressCtx*)ud;
    if (dltotal > 0) {
        double pct = (double)dlnow / (double)dltotal * 100.0;
        printf("\r%-29s %5.1f%% %10" PRId64 " / %10" PRId64 " %s",
               ctx->prefix, pct, (int64_t)dlnow, (int64_t)dltotal,
               ctx->suffix ? ctx->suffix : "");
        fflush(stdout);
    }
    return 0;
}

// ---------------------------------------------------------------------------
// Base64 decoder
// ---------------------------------------------------------------------------

static int b64_val(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static bool base64_decode(const char* src, uint8_t** out, size_t* out_len)
{
    size_t src_len = strlen(src);
    *out = malloc((src_len / 4 + 1) * 3);
    if (!*out) return false;

    size_t j = 0;
    int val[4], v_idx = 0;

    for (size_t i = 0; i < src_len; i++) {
        if (src[i] == '=') break;
        int v = b64_val(src[i]);
        if (v < 0) continue;
        val[v_idx++] = v;
        if (v_idx == 4) {
            (*out)[j++] = (uint8_t)((val[0] << 2) | (val[1] >> 4));
            (*out)[j++] = (uint8_t)((val[1] << 4) | (val[2] >> 2));
            (*out)[j++] = (uint8_t)((val[2] << 6) |  val[3]);
            v_idx = 0;
        }
    }
    if (v_idx == 2) {
        (*out)[j++] = (uint8_t)((val[0] << 2) | (val[1] >> 4));
    } else if (v_idx == 3) {
        (*out)[j++] = (uint8_t)((val[0] << 2) | (val[1] >> 4));
        (*out)[j++] = (uint8_t)((val[1] << 4) | (val[2] >> 2));
    }
    *out_len = j;
    return true;
}

// ---------------------------------------------------------------------------
// zlib inflate
// ---------------------------------------------------------------------------

static bool zlib_inflate_buf(const uint8_t* in, size_t in_len,
                              uint8_t** out, size_t* out_len)
{
    z_stream strm;
    memset(&strm, 0, sizeof(strm));
    strm.next_in  = (Bytef*)in;
    strm.avail_in = (uInt)in_len;
    if (inflateInit(&strm) != Z_OK) return false;

    size_t cap = (in_len * 4 < 4096) ? 4096 : in_len * 4;
    uint8_t* buf = malloc(cap);
    if (!buf) { inflateEnd(&strm); return false; }

    strm.next_out  = (Bytef*)buf;
    strm.avail_out = (uInt)cap;

    for (;;) {
        int ret = inflate(&strm, Z_FINISH);
        if (ret == Z_STREAM_END) break;
        if (ret == Z_BUF_ERROR || ret == Z_OK) {
            size_t used = strm.total_out;
            cap *= 2;
            uint8_t* tmp = realloc(buf, cap);
            if (!tmp) { free(buf); inflateEnd(&strm); return false; }
            buf = tmp;
            strm.next_out  = (Bytef*)(buf + used);
            strm.avail_out = (uInt)(cap - used);
            continue;
        }
        free(buf); inflateEnd(&strm); return false;
    }

    *out     = buf;
    *out_len = strm.total_out;
    inflateEnd(&strm);
    return true;
}

// ---------------------------------------------------------------------------
// HMAC-SHA1
// ---------------------------------------------------------------------------

#define HMAC_BLOCK 64

static void hmac_sha1(const uint8_t* key, size_t key_len,
                       const uint8_t* data, size_t data_len,
                       uint8_t out[SHA_DIGEST_LENGTH])
{
    uint8_t k[HMAC_BLOCK] = {0};
    uint8_t tmp_key[SHA_DIGEST_LENGTH];

    if (key_len > HMAC_BLOCK) {
        sha1(key, (uint32_t)key_len, tmp_key);
        key = tmp_key;
        key_len = SHA_DIGEST_LENGTH;
    }
    memcpy(k, key, key_len);

    uint8_t ipad[HMAC_BLOCK], opad[HMAC_BLOCK];
    for (int i = 0; i < HMAC_BLOCK; i++) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5C;
    }

    uint8_t* inner_buf = malloc(HMAC_BLOCK + data_len);
    uint8_t  inner_hash[SHA_DIGEST_LENGTH];
    memcpy(inner_buf, ipad, HMAC_BLOCK);
    memcpy(inner_buf + HMAC_BLOCK, data, data_len);
    sha1(inner_buf, (uint32_t)(HMAC_BLOCK + data_len), inner_hash);
    free(inner_buf);

    uint8_t outer_buf[HMAC_BLOCK + SHA_DIGEST_LENGTH];
    memcpy(outer_buf, opad, HMAC_BLOCK);
    memcpy(outer_buf + HMAC_BLOCK, inner_hash, SHA_DIGEST_LENGTH);
    sha1(outer_buf, (uint32_t)(HMAC_BLOCK + SHA_DIGEST_LENGTH), out);
}

// ---------------------------------------------------------------------------
// PBKDF2-SHA1
// ---------------------------------------------------------------------------

static void pbkdf2_sha1(const uint8_t* pwd, size_t pwd_len,
                         const uint8_t* salt, size_t salt_len,
                         uint32_t iters, uint8_t* out, size_t out_len)
{
    uint32_t blocks = (uint32_t)((out_len + SHA_DIGEST_LENGTH - 1) / SHA_DIGEST_LENGTH);

    for (uint32_t b = 1; b <= blocks; b++) {
        uint8_t* sb = malloc(salt_len + 4);
        memcpy(sb, salt, salt_len);
        sb[salt_len + 0] = (b >> 24) & 0xFF;
        sb[salt_len + 1] = (b >> 16) & 0xFF;
        sb[salt_len + 2] = (b >>  8) & 0xFF;
        sb[salt_len + 3] =  b        & 0xFF;

        uint8_t U[SHA_DIGEST_LENGTH], T[SHA_DIGEST_LENGTH];
        hmac_sha1(pwd, pwd_len, sb, salt_len + 4, U);
        free(sb);
        memcpy(T, U, SHA_DIGEST_LENGTH);

        for (uint32_t i = 1; i < iters; i++) {
            hmac_sha1(pwd, pwd_len, U, SHA_DIGEST_LENGTH, U);
            for (int j = 0; j < SHA_DIGEST_LENGTH; j++)
                T[j] ^= U[j];
        }

        size_t off  = (b - 1) * SHA_DIGEST_LENGTH;
        size_t copy = ((off + SHA_DIGEST_LENGTH) <= out_len)
                      ? (size_t)SHA_DIGEST_LENGTH : (out_len - off);
        memcpy(out + off, T, copy);
    }
}

// ---------------------------------------------------------------------------
// keygen: generate encrypted title key
// ---------------------------------------------------------------------------

static void gen_enc_title_key(const char* tid_upper, uint8_t enc_key[16])
{
    static const uint8_t prefix[10] = {
        0xfd, 0x04, 0x01, 0x05, 0x06, 0x0b, 0x11, 0x1c, 0x2d, 0x49
    };

    uint8_t secret[17];
    memcpy(secret, prefix, 10);
    for (int i = 0; i < 7; i++) {
        unsigned int b = 0;
        sscanf(tid_upper + 2 + i * 2, "%02X", &b);
        secret[10 + i] = (uint8_t)b;
    }

    uint8_t hashed_secret[16];
    md5_ctx mctx;
    md5_init(&mctx);
    md5_update(&mctx, secret, 17);
    md5_final(hashed_secret, &mctx);

    uint8_t title_key_plain[16];
    pbkdf2_sha1((const uint8_t*)DEF_PASS, strlen(DEF_PASS),
                hashed_secret, 16, 20, title_key_plain, 16);

    uint8_t iv[16] = {0};
    for (int i = 0; i < 8; i++) {
        unsigned int b = 0;
        sscanf(tid_upper + i * 2, "%02X", &b);
        iv[i] = (uint8_t)b;
    }

    aes_context ctx;
    aes_setkey_enc(&ctx, WiiUCommonKey, 128);
    aes_crypt_cbc(&ctx, AES_ENCRYPT, 16, iv, title_key_plain, enc_key);
}

// ---------------------------------------------------------------------------
// tikgen: build and write title.tik
// ---------------------------------------------------------------------------

// Hardcoded basetik template derived from a real ticket.
// Only the encrypted title key (0x1BF, 16 bytes) and
// title ID (0x1DC, 8 bytes) are patched per-title.
// Everything else — signature pattern, issuer, footer — is correct as-is.
static const uint8_t BASETIK[TIK_SIZE] = {
    0x00, 0x01, 0x00, 0x04, 0xd1, 0x5e, 0xa5, 0xed, 0x15, 0xab, 0xe1, 0x1a, 0xd1, 0x5e, 0xa5, 0xed,
    0x15, 0xab, 0xe1, 0x1a, 0xd1, 0x5e, 0xa5, 0xed, 0x15, 0xab, 0xe1, 0x1a, 0xd1, 0x5e, 0xa5, 0xed,
    0x15, 0xab, 0xe1, 0x1a, 0xd1, 0x5e, 0xa5, 0xed, 0x15, 0xab, 0xe1, 0x1a, 0xd1, 0x5e, 0xa5, 0xed,
    0x15, 0xab, 0xe1, 0x1a, 0xd1, 0x5e, 0xa5, 0xed, 0x15, 0xab, 0xe1, 0x1a, 0xd1, 0x5e, 0xa5, 0xed,
    0x15, 0xab, 0xe1, 0x1a, 0xd1, 0x5e, 0xa5, 0xed, 0x15, 0xab, 0xe1, 0x1a, 0xd1, 0x5e, 0xa5, 0xed,
    0x15, 0xab, 0xe1, 0x1a, 0xd1, 0x5e, 0xa5, 0xed, 0x15, 0xab, 0xe1, 0x1a, 0xd1, 0x5e, 0xa5, 0xed,
    0x15, 0xab, 0xe1, 0x1a, 0xd1, 0x5e, 0xa5, 0xed, 0x15, 0xab, 0xe1, 0x1a, 0xd1, 0x5e, 0xa5, 0xed,
    0x15, 0xab, 0xe1, 0x1a, 0xd1, 0x5e, 0xa5, 0xed, 0x15, 0xab, 0xe1, 0x1a, 0xd1, 0x5e, 0xa5, 0xed,
    0x15, 0xab, 0xe1, 0x1a, 0xd1, 0x5e, 0xa5, 0xed, 0x15, 0xab, 0xe1, 0x1a, 0xd1, 0x5e, 0xa5, 0xed,
    0x15, 0xab, 0xe1, 0x1a, 0xd1, 0x5e, 0xa5, 0xed, 0x15, 0xab, 0xe1, 0x1a, 0xd1, 0x5e, 0xa5, 0xed,
    0x15, 0xab, 0xe1, 0x1a, 0xd1, 0x5e, 0xa5, 0xed, 0x15, 0xab, 0xe1, 0x1a, 0xd1, 0x5e, 0xa5, 0xed,
    0x15, 0xab, 0xe1, 0x1a, 0xd1, 0x5e, 0xa5, 0xed, 0x15, 0xab, 0xe1, 0x1a, 0xd1, 0x5e, 0xa5, 0xed,
    0x15, 0xab, 0xe1, 0x1a, 0xd1, 0x5e, 0xa5, 0xed, 0x15, 0xab, 0xe1, 0x1a, 0xd1, 0x5e, 0xa5, 0xed,
    0x15, 0xab, 0xe1, 0x1a, 0xd1, 0x5e, 0xa5, 0xed, 0x15, 0xab, 0xe1, 0x1a, 0xd1, 0x5e, 0xa5, 0xed,
    0x15, 0xab, 0xe1, 0x1a, 0xd1, 0x5e, 0xa5, 0xed, 0x15, 0xab, 0xe1, 0x1a, 0xd1, 0x5e, 0xa5, 0xed,
    0x15, 0xab, 0xe1, 0x1a, 0xd1, 0x5e, 0xa5, 0xed, 0x15, 0xab, 0xe1, 0x1a, 0xd1, 0x5e, 0xa5, 0xed,
    0x15, 0xab, 0xe1, 0x1a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x52, 0x6f, 0x6f, 0x74, 0x2d, 0x43, 0x41, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x33, 0x2d,
    0x58, 0x53, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x63, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xfe, 0xed, 0xfa, 0xce, 0xfe, 0xed, 0xfa, 0xce, 0xfe, 0xed, 0xfa, 0xce, 0xfe, 0xed, 0xfa, 0xce,
    0xfe, 0xed, 0xfa, 0xce, 0xfe, 0xed, 0xfa, 0xce, 0xfe, 0xed, 0xfa, 0xce, 0xfe, 0xed, 0xfa, 0xce,
    0xfe, 0xed, 0xfa, 0xce, 0xfe, 0xed, 0xfa, 0xce, 0xfe, 0xed, 0xfa, 0xce, 0xfe, 0xed, 0xfa, 0xce,
    0xfe, 0xed, 0xfa, 0xce, 0xfe, 0xed, 0xfa, 0xce, 0xfe, 0xed, 0xfa, 0xce, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x14, 0x00, 0x00, 0x00, 0xac, 0x00, 0x00, 0x00, 0x14,
    0x00, 0x01, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x84, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static bool write_ticket(const char* tid_upper, const char* out_dir)
{
    uint8_t tik[TIK_SIZE];

    // Start from the correct template — signature, issuer, footer all pre-filled
    memcpy(tik, BASETIK, TIK_SIZE);

    // Patch encrypted title key at 0x1BF (16 bytes)
    uint8_t enc_key[16];
    gen_enc_title_key(tid_upper, enc_key);
    memcpy(tik + 0x1BF, enc_key, 16);

    // Patch title ID at 0x1DC (8 bytes, big-endian)
    for (int i = 0; i < 8; i++) {
        unsigned int b = 0;
        sscanf(tid_upper + i * 2, "%02X", &b);
        tik[0x1DC + i] = (uint8_t)b;
    }

    char path[FPATH_MAX];
    snprintf(path, sizeof(path), "%s%ctitle.tik", out_dir, PATH_SEP);
    FILE* f = fopen_utf8(path, "wb");
    if (!f) { fprintf(stderr, "ERROR: Could not create '%s'\n", path); return false; }
    bool ok = (fwrite(tik, 1, TIK_SIZE, f) == TIK_SIZE);
    fclose(f);
    return ok;
}

// ---------------------------------------------------------------------------
// curl helpers
// ---------------------------------------------------------------------------

static bool dl_to_mem(const char* url, MemBuf* buf)
{
    buf->data = NULL;
    buf->size = 0;
    CURL* curl = curl_easy_init();
    if (!curl) return false;
    curl_easy_setopt(curl, CURLOPT_URL,            url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,  mem_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA,      buf);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_FAILONERROR,    1L);
    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    if (res != CURLE_OK) {
        free(buf->data); buf->data = NULL; buf->size = 0;
        return false;
    }
    return true;
}

static bool dl_to_file(const char* url, const char* path,
                        const char* prefix, const char* suffix)
{
    FILE* f = fopen_utf8(path, "wb");
    if (!f) { fprintf(stderr, "ERROR: Could not create '%s'\n", path); return false; }

    ProgressCtx pctx = { prefix ? prefix : "", suffix ? suffix : "" };
    CURL* curl = curl_easy_init();
    if (!curl) { fclose(f); return false; }

    curl_easy_setopt(curl, CURLOPT_URL,              url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,    file_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA,        f);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION,   1L);
    curl_easy_setopt(curl, CURLOPT_FAILONERROR,      1L);
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS,       0L);
    curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, progress_cb);
    curl_easy_setopt(curl, CURLOPT_XFERINFODATA,     &pctx);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    fclose(f);

    if (res != CURLE_OK) {
        fprintf(stderr, "\nERROR: Download failed for '%s': %s\n",
                url, curl_easy_strerror(res));
        remove(path);
        return false;
    }
    printf("\n");
    return true;
}

// ---------------------------------------------------------------------------
// File size helper
// ---------------------------------------------------------------------------

static long file_size_on_disk(const char* path)
{
    struct stat st;
    if (stat(path, &st) != 0) return -1;
    return (long)st.st_size;
}

// ---------------------------------------------------------------------------
// Big-endian read helpers
// ---------------------------------------------------------------------------

static uint16_t read_be16(const uint8_t* p) { return (uint16_t)(p[0] << 8 | p[1]); }

static uint64_t read_be64(const uint8_t* p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}

// ---------------------------------------------------------------------------
// is_sys_title
// ---------------------------------------------------------------------------

static bool is_sys_title(const char* tid_upper)
{
    for (int i = 0; SYSTITLE_CATS[i]; i++)
        if (strncmp(tid_upper, SYSTITLE_CATS[i], 8) == 0)
            return true;
    return false;
}

// ---------------------------------------------------------------------------
// run_download_version — download one specific version into <tid>_v<ver>/
// Returns 0 on success, 1 if version doesn't exist, -1 on hard error.
// ---------------------------------------------------------------------------

static int run_download_version(const char* tid, const char* base,
                                 bool sys, int version)
{
    char out_dir[DIR_MAX];
    snprintf(out_dir, sizeof(out_dir), "%s_v%d", tid, version);
    create_path(out_dir);

    if (sys) {
        char tik_url[512], tik_path[FPATH_MAX];
        snprintf(tik_url,  sizeof(tik_url),  "%s/cetk", base);
        snprintf(tik_path, sizeof(tik_path), "%s%ctitle.tik", out_dir, PATH_SEP);
        if (!dl_to_file(tik_url, tik_path, "Downloading: title.tik...", NULL)) {
            fprintf(stderr,
                "Error downloading ticket - system title %s may not be on CDN\n", tid);
            return -1;
        }
    } else {
        if (!write_ticket(tid, out_dir)) return -1;
    }

    char tmd_url[512];
    snprintf(tmd_url, sizeof(tmd_url), "%s/tmd.%d", base, version);

    MemBuf tmd_buf = {NULL, 0};
    if (!dl_to_mem(tmd_url, &tmd_buf)) {
        char tik_path[FPATH_MAX];
        snprintf(tik_path, sizeof(tik_path), "%s%ctitle.tik", out_dir, PATH_SEP);
        remove(tik_path);
        rmdir(out_dir);
        return 1;
    }

    if (tmd_buf.size < 0x1E0) {
        fprintf(stderr, "ERROR: TMD too short for version %d\n", version);
        free(tmd_buf.data);
        return -1;
    }

    uint16_t count = read_be16(tmd_buf.data + 0x1DE);
    printf("  Contents: %u\n", count);

    typedef struct { char id[9]; uint16_t type; uint64_t size; } ContentEntry;
    ContentEntry* contents = calloc(count, sizeof(ContentEntry));
    if (!contents) { free(tmd_buf.data); return -1; }

    uint64_t total_size = 0;
    for (uint16_t c = 0; c < count; c++) {
        size_t off = 0xB04 + (size_t)c * 0x30;
        if (off + 0x10 > tmd_buf.size) break;
        for (int j = 0; j < 4; j++)
            snprintf(contents[c].id + j * 2, 3, "%02x", tmd_buf.data[off + j]);
        contents[c].type = read_be16(tmd_buf.data + off + 0x06);
        contents[c].size = read_be64(tmd_buf.data + off + 0x08);
        total_size += contents[c].size;
    }

    printf("  Total size: 0x%" PRIX64 " (%.2f MiB)\n",
           total_size, (double)total_size / (1024.0 * 1024.0));

    // Write TMD
    {
        char tmd_path[FPATH_MAX];
        snprintf(tmd_path, sizeof(tmd_path), "%s%ctitle.tmd", out_dir, PATH_SEP);
        FILE* f = fopen_utf8(tmd_path, "wb");
        if (f) { fwrite(tmd_buf.data, 1, tmd_buf.size, f); fclose(f); }
    }
    free(tmd_buf.data);

    // Write title.cert
    {
        char cert_path[FPATH_MAX];
        snprintf(cert_path, sizeof(cert_path), "%s%ctitle.cert", out_dir, PATH_SEP);

        uint8_t* b64_dec = NULL;
        size_t   b64_len = 0;
        if (!base64_decode(TITLECERT_B64, &b64_dec, &b64_len)) {
            fprintf(stderr, "ERROR: base64 decode of cert failed\n");
        } else {
            uint8_t* cert_data = NULL;
            size_t   cert_len  = 0;
            if (!zlib_inflate_buf(b64_dec, b64_len, &cert_data, &cert_len)) {
                fprintf(stderr, "ERROR: zlib inflate of cert failed\n");
            } else {
                FILE* f = fopen_utf8(cert_path, "wb");
                if (f) { fwrite(cert_data, 1, cert_len, f); fclose(f); }
                free(cert_data);
            }
            free(b64_dec);
        }
    }

    // Download .app and .h3 files
    for (uint16_t c = 0; c < count; c++) {
        char app_path[FPATH_MAX], app_url[512];
        snprintf(app_path, sizeof(app_path), "%s%c%s.app", out_dir, PATH_SEP, contents[c].id);
        snprintf(app_url,  sizeof(app_url),  "%s/%s", base, contents[c].id);

        long on_disk = file_size_on_disk(app_path);
        if (on_disk > 0 && (uint64_t)on_disk == contents[c].size) {
            printf("  Skipping %s.app - already exists with correct size\n", contents[c].id);
        } else {
            char prefix[64], suffix[64];
            snprintf(prefix, sizeof(prefix), "Downloading: %s.app...", contents[c].id);
            snprintf(suffix, sizeof(suffix), "(%.2f MiB)", (double)contents[c].size / (1024.0 * 1024.0));
            if (!dl_to_file(app_url, app_path, prefix, suffix)) {
                free(contents);
                return -1;
            }
        }

        if (contents[c].type & 0x0002) {
            char h3_path[FPATH_MAX], h3_url[512];
            snprintf(h3_path, sizeof(h3_path), "%s%c%s.h3", out_dir, PATH_SEP, contents[c].id);
            snprintf(h3_url,  sizeof(h3_url),  "%s/%s.h3",  base, contents[c].id);
            char prefix[64];
            snprintf(prefix, sizeof(prefix), "Downloading: %s.h3...", contents[c].id);
            if (!dl_to_file(h3_url, h3_path, prefix, NULL)) {
                free(contents);
                return -1;
            }
        }
    }

    free(contents);
    printf("  Download finished: %s - Version %d -> %s\n", tid, version, out_dir);

    // Automatically decrypt with wuptool if available
    if (g_wuptool_path[0] != '\0')
        run_wuptool_decrypt(out_dir);

    return 0;
}

// ---------------------------------------------------------------------------
// run_download — entry point for one title ID
// ---------------------------------------------------------------------------

static int run_download(const char* tid_in, const char* version)
{
    char tid[17];
    strncpy(tid, tid_in, 16);
    tid[16] = '\0';
    for (int i = 0; tid[i]; i++) tid[i] = (char)toupper((unsigned char)tid[i]);

    char base[256];
    snprintf(base, sizeof(base), "%s%s", CDN_BASE, tid);

    bool sys = is_sys_title(tid);
    if (sys)
        printf("Detected System title.\n");

    if (version != NULL) {
        char* end;
        int ver = (int)strtol(version, &end, 10);
        if (*end != '\0') {
            fprintf(stderr, "ERROR: Invalid version number '%s'\n", version);
            return 1;
        }
        printf("Downloading %s version %d...\n", tid, ver);
        int ret = run_download_version(tid, base, sys, ver);
        if (ret == 1)
            printf("Version %d not found.\n", ver);
        return ret != 0 ? 1 : 0;
    }

    printf("No version specified, probing all %d known versions for %s...\n",
           KNOWN_VERSIONS_COUNT, tid);

    int found = 0;
    for (int i = 0; i < KNOWN_VERSIONS_COUNT; i++) {
        int ver = KNOWN_VERSIONS[i];
        printf("[%d/%d] Trying version %d...\n", i + 1, KNOWN_VERSIONS_COUNT, ver);
        int ret = run_download_version(tid, base, sys, ver);
        if (ret == 0) {
            found++;
        } else if (ret == -1) {
            fprintf(stderr, "Hard error on version %d, aborting.\n", ver);
            return 1;
        }
    }

    printf("\nFinished probing all versions. Found %d version(s) for %s.\n", found, tid);
    return 0;
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main(int argc, char** argv)
{
    if (argc < 2 || strlen(argv[1]) != 16) {
        fprintf(stderr, "Invalid or missing Title ID.\n");
        fprintf(stderr, "Usage: %s <TitleID> [version]\n", argv[0]);
        fprintf(stderr, "  TitleID : 16-character Wii U title ID (e.g. 0005000010152D00)\n");
        fprintf(stderr, "  version : specific version number to download\n");
        fprintf(stderr, "            omit to probe and download all known versions\n");
        return 1;
    }

    if (argc > 3) {
        fprintf(stderr, "Too many arguments.\n");
        fprintf(stderr, "Usage: %s <TitleID> [version]\n", argv[0]);
        return 1;
    }

    // Locate wuptool for automatic post-download decryption
    bool wuptool_found = find_wuptool();
    if (wuptool_found)
        printf("wuptool found: %s\n", g_wuptool_path);
    else if (g_wuptool_path[0] != '\0')
        printf("wuptool not found in exe directory or CWD, will try PATH: %s\n",
               g_wuptool_path);
    else
        printf("WARNING: wuptool not found — downloads will not be auto-decrypted.\n");

    curl_global_init(CURL_GLOBAL_ALL);
    int ret = run_download(argv[1], argc == 3 ? argv[2] : NULL);
    curl_global_cleanup();
    return ret;
}