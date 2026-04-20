/*
  cdecrypt - Decrypt Wii U NUS content files

  Copyright © 2013-2015 crediar <https://code.google.com/p/cdecrypt/>
  Copyright © 2020-2022 VitaSmith <https://github.com/VitaSmith/cdecrypt>

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utf8.h"
#include "util.h"
#include "aes.h"
#include "md5.h"
#include "cpack.h"

// We use part of the root cert name used by TMD/TIK to identify them
#define TMD_MAGIC       0x4350303030303030ULL   // 'CP000000'
#define TIK_MAGIC       0x5853303030303030ULL   // 'XS000000'
#define T_MAGIC_OFFSET  0x0150
#define DECRYPTED_SUFFIX "_decrypted"

static const uint8_t WiiUCommonDevKey[16] =
    { 0x2F, 0x5C, 0x1B, 0x29, 0x44, 0xE7, 0xFD, 0x6F, 0xC3, 0x97, 0x96, 0x4B, 0x05, 0x76, 0x91, 0xFA };
static const uint8_t WiiUCommonKey[16] =
    { 0xD7, 0xB0, 0x04, 0x02, 0x65, 0x9B, 0xA2, 0xAB, 0xD2, 0xCB, 0x0D, 0xB2, 0x7F, 0xA2, 0xB6, 0x56 };

aes_context     ctx;
uint8_t         title_id[16];
uint8_t         title_key[16];

#pragma pack(1)

typedef struct
{
    uint32_t ID;                    //  0  0xB04
    uint16_t Index;                 //  4  0xB08
    uint16_t Type;                  //  6  0xB0A
    uint64_t Size;                  //  8  0xB0C
    uint8_t  SHA2[32];              //  16 0xB14
} Content;

typedef struct
{
    uint16_t IndexOffset;           //  0  0x204
    uint16_t CommandCount;          //  2  0x206
    uint8_t  SHA2[32];              //  12 0x208
} ContentInfo;

typedef struct
{
    uint32_t SignatureType;         // 0x000
    uint8_t  Signature[0x100];      // 0x004
    uint8_t  Padding0[0x3C];        // 0x104
    uint8_t  Issuer[0x40];          // 0x140
    uint8_t  Version;               // 0x180
    uint8_t  CACRLVersion;          // 0x181
    uint8_t  SignerCRLVersion;      // 0x182
    uint8_t  Padding1;              // 0x183
    uint64_t SystemVersion;         // 0x184
    uint64_t TitleID;               // 0x18C
    uint32_t TitleType;             // 0x194
    uint16_t GroupID;               // 0x198
    uint8_t  Reserved[62];          // 0x19A
    uint32_t AccessRights;          // 0x1D8
    uint16_t TitleVersion;          // 0x1DC
    uint16_t ContentCount;          // 0x1DE
    uint16_t BootIndex;             // 0x1E0
    uint8_t  Padding3[2];           // 0x1E2
    uint8_t  SHA2[32];              // 0x1E4
    ContentInfo ContentInfos[64];
    Content  Contents[];
} TitleMetaData;

// ---------------------------------------------------------------------------
// Strip one trailing path separator from a directory string, in place.
// Needed before rename() so we operate on the directory itself, not its
// contents (some platforms treat "foo/" and "foo" differently).
// ---------------------------------------------------------------------------
static void strip_trailing_sep(char* path)
{
    size_t len = strlen(path);
    if (len > 1 && (path[len - 1] == '/' || path[len - 1] == '\\'))
        path[len - 1] = '\0';
}

// ---------------------------------------------------------------------------
// Returns true if str ends with suffix (case-sensitive).
// ---------------------------------------------------------------------------
static bool ends_with(const char* str, const char* suffix)
{
    size_t slen  = strlen(str);
    size_t sflen = strlen(suffix);
    if (sflen > slen) return false;
    return strcmp(str + slen - sflen, suffix) == 0;
}

// ---------------------------------------------------------------------------
// After a fully successful decrypt, rename <dir> to <dir>_decrypted.
// If the directory already ends with _decrypted, do nothing.
// ---------------------------------------------------------------------------
static void rename_add_decrypted(const char* dir)
{
    char src[PATH_MAX], dst[PATH_MAX];
    strncpy(src, dir, sizeof(src) - 1);
    src[sizeof(src) - 1] = '\0';
    strip_trailing_sep(src);

    if (ends_with(src, DECRYPTED_SUFFIX)) {
        // Already marked — nothing to do
        return;
    }

    snprintf(dst, sizeof(dst), "%s%s", src, DECRYPTED_SUFFIX);

    if (rename(src, dst) == 0)
        printf("Folder renamed to: %s\n", dst);
    else
        fprintf(stderr, "WARNING: Could not rename folder to '%s'\n", dst);
}

// ---------------------------------------------------------------------------
// After a fully successful encrypt, rename <dir>_decrypted back to <dir>.
// If the directory does not end with _decrypted, do nothing.
// ---------------------------------------------------------------------------
static void rename_remove_decrypted(const char* dir)
{
    char src[PATH_MAX], dst[PATH_MAX];
    strncpy(src, dir, sizeof(src) - 1);
    src[sizeof(src) - 1] = '\0';
    strip_trailing_sep(src);

    if (!ends_with(src, DECRYPTED_SUFFIX)) {
        // No suffix to remove
        return;
    }

    strncpy(dst, src, sizeof(dst) - 1);
    dst[sizeof(dst) - 1] = '\0';
    dst[strlen(dst) - strlen(DECRYPTED_SUFFIX)] = '\0';

    if (rename(src, dst) == 0)
        printf("Folder renamed to: %s\n", dst);
    else
        fprintf(stderr, "WARNING: Could not rename folder to '%s'\n", dst);
}

// ---------------------------------------------------------------------------
// Decrypt one .app → .app.dec using the global AES context (title key).
// ---------------------------------------------------------------------------
#define DECRYPT_BLOCK_SIZE 0x8000

static __attribute__((noinline)) bool decrypt_app_raw(const char* src_path, const char* dst_path,
                                                       uint16_t content_index, uint64_t expected_size)
{
    bool r = false;
    FILE* src = NULL;
    FILE* dst = NULL;
    uint8_t iv[16];
    uint64_t remaining;
    uint8_t* enc = malloc(DECRYPT_BLOCK_SIZE);
    uint8_t* dec = malloc(DECRYPT_BLOCK_SIZE);

    if (enc == NULL || dec == NULL) {
        fprintf(stderr, "ERROR: Out of memory\n");
        goto out;
    }

    src = fopen_utf8(src_path, "rb");
    if (src == NULL) {
        fprintf(stderr, "ERROR: Could not open '%s'\n", src_path);
        goto out;
    }
    dst = fopen_utf8(dst_path, "wb");
    if (dst == NULL) {
        fprintf(stderr, "ERROR: Could not create '%s'\n", dst_path);
        goto out;
    }

    memset(iv, 0, sizeof(iv));
    iv[1] = (uint8_t)content_index;

    remaining = expected_size;
    while (remaining > 0) {
        size_t to_read    = (remaining < DECRYPT_BLOCK_SIZE) ? (size_t)remaining : DECRYPT_BLOCK_SIZE;
        size_t to_decrypt = (to_read + 15) & ~(size_t)15;
        memset(enc, 0, to_decrypt);
        size_t bytes_read = fread(enc, 1, to_read, src);
        if (bytes_read == 0) break;
        aes_crypt_cbc(&ctx, AES_DECRYPT, to_decrypt, iv, enc, dec);
        if (fwrite(dec, 1, bytes_read, dst) != bytes_read) {
            fprintf(stderr, "ERROR: Write failed to '%s'\n", dst_path);
            goto out;
        }
        remaining -= bytes_read;
    }

    r = true;
out:
    if (src != NULL) fclose(src);
    if (dst != NULL) fclose(dst);
    free(enc);
    free(dec);
    return r;
}

#undef DECRYPT_BLOCK_SIZE

// ---------------------------------------------------------------------------
// Re-encrypt .app.dec → temp file for verification. Uses a local AES context
// so the global ctx (keyed for decryption) is not disturbed.
// ---------------------------------------------------------------------------
#define VERIFY_BLOCK_SIZE 0x8000

static __attribute__((noinline)) bool encrypt_app_verify(const char* src_path, const char* dst_path,
                                                          uint16_t content_index, uint64_t data_size,
                                                          const uint8_t* key)
{
    bool r = false;
    FILE* src = NULL;
    FILE* dst = NULL;
    uint8_t iv[16];
    uint64_t remaining;
    aes_context enc_ctx;
    uint8_t* plain  = malloc(VERIFY_BLOCK_SIZE);
    uint8_t* cipher = malloc(VERIFY_BLOCK_SIZE);

    if (plain == NULL || cipher == NULL) {
        fprintf(stderr, "ERROR: Out of memory\n");
        goto out;
    }

    src = fopen_utf8(src_path, "rb");
    if (src == NULL) {
        fprintf(stderr, "ERROR: Could not open '%s'\n", src_path);
        goto out;
    }
    dst = fopen_utf8(dst_path, "wb");
    if (dst == NULL) {
        fprintf(stderr, "ERROR: Could not create '%s'\n", dst_path);
        goto out;
    }

    aes_setkey_enc(&enc_ctx, key, 128);
    memset(iv, 0, sizeof(iv));
    iv[1] = (uint8_t)content_index;

    remaining = data_size;
    while (remaining > 0) {
        size_t to_read = (remaining < VERIFY_BLOCK_SIZE) ? (size_t)remaining : VERIFY_BLOCK_SIZE;
        memset(plain, 0, VERIFY_BLOCK_SIZE);
        size_t bytes_read = fread(plain, 1, to_read, src);
        if (bytes_read == 0) break;
        aes_crypt_cbc(&enc_ctx, AES_ENCRYPT, VERIFY_BLOCK_SIZE, iv, plain, cipher);
        if (fwrite(cipher, 1, VERIFY_BLOCK_SIZE, dst) != VERIFY_BLOCK_SIZE) {
            fprintf(stderr, "ERROR: Write failed to '%s'\n", dst_path);
            goto out;
        }
        remaining -= bytes_read;
    }

    r = true;
out:
    if (src != NULL) fclose(src);
    if (dst != NULL) fclose(dst);
    free(plain);
    free(cipher);
    return r;
}

#undef VERIFY_BLOCK_SIZE

// ---------------------------------------------------------------------------
// do_decrypt — core decrypt logic, extracted so it can be called from both
// the explicit "decrypt" subcommand and the drag-and-drop path.
// nus_dir is the source directory; out_dir is where .app.dec files go
// (may equal nus_dir).
// ---------------------------------------------------------------------------
static int do_decrypt(const char* nus_dir, const char* out_dir)
{
    int r = EXIT_FAILURE;
    char str[PATH_MAX], *tmd_path = NULL, *tik_path = NULL;
    TitleMetaData* tmd = NULL;
    uint8_t* tik = NULL;
    const char* pattern[] = { "%s%c%08x.app", "%s%c%08X.app", "%s%c%08x", "%s%c%08X" };

    size_t len = strlen(nus_dir);
    tmd_path = calloc(len + 16, 1);
    tik_path = calloc(len + 16, 1);
    sprintf(tmd_path, "%s%ctitle.tmd", nus_dir, PATH_SEP);
    sprintf(tik_path, "%s%ctitle.tik", nus_dir, PATH_SEP);

    uint32_t tmd_len = read_file(tmd_path, (uint8_t**)&tmd);
    if (tmd_len == 0) goto out;

    uint32_t tik_len = read_file(tik_path, &tik);
    if (tik_len == 0) goto out;

    if (tmd->Version != 1) {
        fprintf(stderr, "ERROR: Unsupported TMD version: %u\n", tmd->Version);
        goto out;
    }

    printf("Title version : %u\n", getbe16(&tmd->TitleVersion));
    printf("Content count : %u\n", getbe16(&tmd->ContentCount));

    if (strcmp((char*)(&tmd->Issuer), "Root-CA00000003-CP0000000b") == 0)
        aes_setkey_dec(&ctx, WiiUCommonKey, sizeof(WiiUCommonKey) * 8);
    else if (strcmp((char*)(&tmd->Issuer), "Root-CA00000004-CP00000010") == 0)
        aes_setkey_dec(&ctx, WiiUCommonDevKey, sizeof(WiiUCommonDevKey) * 8);
    else {
        fprintf(stderr, "ERROR: Unknown issuer: '%s'\n", (char*)tmd + 0x140);
        goto out;
    }

    memset(title_id, 0, sizeof(title_id));
    memcpy(title_id, &tmd->TitleID, 8);
    memcpy(title_key, tik + 0x1BF, 16);
    aes_crypt_cbc(&ctx, AES_DECRYPT, sizeof(title_key), title_id, title_key, title_key);
    aes_setkey_dec(&ctx, title_key, sizeof(title_key) * 8);

    printf("Output directory: '%s'\n\n", out_dir);
    create_path((char*)out_dir);

    uint32_t ok_count = 0, fail_count = 0;
    uint16_t content_count = getbe16(&tmd->ContentCount);

    for (uint16_t i = 0; i < content_count; i++) {
        uint32_t content_file_id = getbe32(&tmd->Contents[i].ID);
        uint64_t content_size    = getbe64(&tmd->Contents[i].Size);
        uint16_t content_index   = getbe16(&tmd->Contents[i].Index);
        uint16_t content_type    = getbe16(&tmd->Contents[i].Type);
        bool     is_hashed       = (content_type & 0x0002) != 0;

        str[0] = '\0';
        for (uint32_t k = 0; k < array_size(pattern); k++) {
            sprintf(str, pattern[k], nus_dir, PATH_SEP, content_file_id);
            if (is_file(str)) break;
        }
        if (!is_file(str)) {
            fprintf(stderr, "WARNING: Could not find .app for content %08X, skipping\n",
                    content_file_id);
            continue;
        }

        char app_path[PATH_MAX], dec_path[PATH_MAX], md5_path[PATH_MAX], tmp_path[PATH_MAX];
        snprintf(app_path, sizeof(app_path), "%s", str);
        snprintf(dec_path, sizeof(dec_path), "%s%c%08x.app.dec", out_dir, PATH_SEP, content_file_id);
        snprintf(md5_path, sizeof(md5_path), "%s%c%08x.app.md5", out_dir, PATH_SEP, content_file_id);
        snprintf(tmp_path, sizeof(tmp_path), "%s%c%08x.app.tmp", out_dir, PATH_SEP, content_file_id);

        printf("[%3u/%3u] %08X  size: %10" PRIu64 "  index: %u  %s\n",
               i + 1, content_count, content_file_id, content_size,
               content_index, is_hashed ? "[hashed]" : "");

        // Step 1: MD5 the original .app
        uint8_t digest_orig[16];
        FILE* af = fopen_utf8(app_path, "rb");
        if (af == NULL || !md5_of_file(af, digest_orig)) {
            if (af) fclose(af);
            fprintf(stderr, "  ERROR: Could not compute MD5 of '%s'\n", app_path);
            fail_count++;
            continue;
        }
        fclose(af);

        char hex_orig[33];
        md5_to_hex(digest_orig, hex_orig);

        // Write .app.md5 as raw 16 bytes
        FILE* mf = fopen_utf8(md5_path, "wb");
        if (mf == NULL) {
            fprintf(stderr, "  ERROR: Could not write MD5 file '%s'\n", md5_path);
            fail_count++;
            continue;
        }
        fwrite(digest_orig, 1, 16, mf);
        fclose(mf);

        // Step 2: decrypt .app → .app.dec
        if (!decrypt_app_raw(app_path, dec_path, content_index, content_size)) {
            fprintf(stderr, "  ERROR: Decryption failed for content %08X\n", content_file_id);
            remove(dec_path);
            remove(md5_path);
            fail_count++;
            continue;
        }

        // Step 3: re-encrypt .app.dec → .app.tmp for verification
        if (!encrypt_app_verify(dec_path, tmp_path, content_index, content_size, title_key)) {
            fprintf(stderr, "  ERROR: Verification re-encryption failed for content %08X\n",
                    content_file_id);
            remove(dec_path);
            remove(md5_path);
            remove(tmp_path);
            fail_count++;
            continue;
        }

        // Step 4: MD5 the temp file and compare
        uint8_t digest_verify[16];
        FILE* tf = fopen_utf8(tmp_path, "rb");
        if (tf == NULL || !md5_of_file(tf, digest_verify)) {
            if (tf) fclose(tf);
            fprintf(stderr, "  ERROR: Could not compute MD5 of temp file for content %08X\n",
                    content_file_id);
            remove(dec_path);
            remove(md5_path);
            remove(tmp_path);
            fail_count++;
            continue;
        }
        fclose(tf);
        remove(tmp_path);

        if (memcmp(digest_orig, digest_verify, 16) != 0) {
            char hex_verify[33];
            md5_to_hex(digest_verify, hex_verify);
            fprintf(stderr, "  WARNING: Verification FAILED for content %08X\n", content_file_id);
            fprintf(stderr, "    original : %s\n", hex_orig);
            fprintf(stderr, "    verified : %s\n", hex_verify);
            fprintf(stderr, "    Decryption result is unreliable — keeping original .app.\n");
            remove(dec_path);
            remove(md5_path);
            fail_count++;
            continue;
        }

        // Step 5: verified — delete original .app, keep .app.dec + .app.md5
        remove(app_path);
        printf("  OK  MD5: %s\n", hex_orig);
        ok_count++;
    }

    printf("\nDecrypt complete: %u succeeded, %u failed.\n", ok_count, fail_count);

    if (fail_count == 0) {
        rename_add_decrypted(out_dir);
        r = EXIT_SUCCESS;
    }

out:
    free(tmd);
    free(tik);
    free(tmd_path);
    free(tik_path);
    return r;
}

// ---------------------------------------------------------------------------
// do_encrypt — thin wrapper around pack_title that also handles the rename.
// ---------------------------------------------------------------------------
static int do_encrypt(const char* dir)
{
    int result = pack_title(dir);
    if (result == 0)
        rename_remove_decrypted(dir);
    return result;
}

int main_utf8(int argc, char** argv)
{
    if (argc < 2) {
        printf("%s %s - Wii U NUS content tool\n"
            "Copyright (c) 2020-2023 VitaSmith, Copyright (c) 2013-2015 crediar\n"
            "Visit https://github.com/VitaSmith/cdecrypt for official source and downloads.\n\n"
            "Usage:\n"
            "  %s decrypt <nus_dir> [output_dir]\n"
            "      Decrypt all .app files to .app.dec, save .app.md5 sidecars,\n"
            "      verify by re-encrypting, delete original .app, rename folder\n"
            "      to <dir>_decrypted on success.\n\n"
            "  %s encrypt <dir>\n"
            "      Re-encrypt all .app.dec files back to .app, verify against\n"
            "      .app.md5 sidecars, delete .app.dec and .app.md5, remove\n"
            "      _decrypted suffix from folder name on success.\n\n"
            "  %s <dir>\n"
            "      Drag-and-drop: auto-detects decrypt or encrypt based on\n"
            "      whether the folder name ends with _decrypted.\n\n"
            "This program is free software; you can redistribute it and/or modify it under\n"
            "the terms of the GNU General Public License as published by the Free Software\n"
            "Foundation; either version 3 of the License or any later version.\n",
            _appname(argv[0]), APP_VERSION_STR,
            _appname(argv[0]), _appname(argv[0]), _appname(argv[0]));
        return EXIT_SUCCESS;
    }

    // ---- Drag-and-drop: single directory argument, no subcommand --------
    if (argc == 2 && is_directory(argv[1])) {
        char dir[PATH_MAX];
        strncpy(dir, argv[1], sizeof(dir) - 1);
        dir[sizeof(dir) - 1] = '\0';
        strip_trailing_sep(dir);

        if (ends_with(dir, DECRYPTED_SUFFIX)) {
            printf("Auto-detected: ENCRYPT (folder ends with _decrypted)\n\n");
            return do_encrypt(dir);
        } else {
            printf("Auto-detected: DECRYPT (folder does not end with _decrypted)\n\n");
            return do_decrypt(dir, dir);
        }
    }

    // ---- encrypt subcommand ---------------------------------------------
    if (strcmp(argv[1], "encrypt") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s encrypt <dir>\n", _appname(argv[0]));
            return EXIT_FAILURE;
        }
        return do_encrypt(argv[2]);
    }

    // ---- decrypt subcommand ---------------------------------------------
    if (strcmp(argv[1], "decrypt") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s decrypt <nus_dir> [output_dir]\n", _appname(argv[0]));
            return EXIT_FAILURE;
        }
        const char* nus_dir = argv[2];
        const char* out_dir = (argc > 3) ? argv[3] : argv[2];
        return do_decrypt(nus_dir, out_dir);
    }

    fprintf(stderr, "ERROR: Unknown command '%s'\n\n"
            "Usage:\n"
            "  %s decrypt <nus_dir> [output_dir]\n"
            "  %s encrypt <dir>\n"
            "  %s <dir>   (drag-and-drop)\n",
            argv[1], _appname(argv[0]), _appname(argv[0]), _appname(argv[0]));
    return EXIT_FAILURE;
}

CALL_MAIN