/*
  cpack - Re-encrypt Wii U NUS .app.dec files back to .app

  Copyright (C) 2024

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>

#include "cpack.h"
#include "util.h"
#include "utf8.h"
#include "aes.h"
#include "md5.h"

#pragma pack(1)

typedef struct
{
    uint32_t ID;
    uint16_t Index;
    uint16_t Type;
    uint64_t Size;
    uint8_t  SHA2[32];
} PackContent;

typedef struct
{
    uint16_t IndexOffset;
    uint16_t CommandCount;
    uint8_t  SHA2[32];
} PackContentInfo;

typedef struct
{
    uint32_t SignatureType;
    uint8_t  Signature[0x100];
    uint8_t  Padding0[0x3C];
    uint8_t  Issuer[0x40];
    uint8_t  Version;
    uint8_t  CACRLVersion;
    uint8_t  SignerCRLVersion;
    uint8_t  Padding1;
    uint64_t SystemVersion;
    uint64_t TitleID;
    uint32_t TitleType;
    uint16_t GroupID;
    uint8_t  Reserved[62];
    uint32_t AccessRights;
    uint16_t TitleVersion;
    uint16_t ContentCount;
    uint16_t BootIndex;
    uint8_t  Padding3[2];
    uint8_t  SHA2[32];
    PackContentInfo ContentInfos[64];
    PackContent Contents[];
} PackTitleMetaData;

#pragma pack()

static const uint8_t WiiUCommonKey[16] = {
    0xD7, 0xB0, 0x04, 0x02, 0x65, 0x9B, 0xA2, 0xAB,
    0xD2, 0xCB, 0x0D, 0xB2, 0x7F, 0xA2, 0xB6, 0x56
};
static const uint8_t WiiUCommonDevKey[16] = {
    0x2F, 0x5C, 0x1B, 0x29, 0x44, 0xE7, 0xFD, 0x6F,
    0xC3, 0x97, 0x96, 0x4B, 0x05, 0x76, 0x91, 0xFA
};

#define PACK_BLOCK_SIZE 0x8000

// ---------------------------------------------------------------------------
// Re-encrypt one .app.dec back to a .app file.
// Exact inverse of decrypt_app_raw in wuptool.c — same IV, same block size,
// always writes full 0x8000-byte blocks (zero-padding the last one).
// ---------------------------------------------------------------------------
static __attribute__((noinline)) bool encrypt_app_raw(
    const char* src_path, const char* dst_path,
    uint16_t content_index, uint64_t data_size,
    const uint8_t* title_key)
{
    bool r = false;
    FILE* src = NULL;
    FILE* dst = NULL;
    uint8_t iv[16];
    uint64_t remaining;
    aes_context enc_ctx;
    uint8_t* plain  = malloc(PACK_BLOCK_SIZE);
    uint8_t* cipher = malloc(PACK_BLOCK_SIZE);

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

    aes_setkey_enc(&enc_ctx, title_key, 128);
    memset(iv, 0, sizeof(iv));
    iv[1] = (uint8_t)content_index;

    remaining = data_size;
    while (remaining > 0) {
        size_t to_read = (remaining < PACK_BLOCK_SIZE) ? (size_t)remaining : PACK_BLOCK_SIZE;
        memset(plain, 0, PACK_BLOCK_SIZE);
        size_t bytes_read = fread(plain, 1, to_read, src);
        if (bytes_read == 0) break;
        aes_crypt_cbc(&enc_ctx, AES_ENCRYPT, PACK_BLOCK_SIZE, iv, plain, cipher);
        if (fwrite(cipher, 1, PACK_BLOCK_SIZE, dst) != PACK_BLOCK_SIZE) {
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

#undef PACK_BLOCK_SIZE

// ---------------------------------------------------------------------------
// pack_title — re-encrypt all .app.dec files back to .app, verify, clean up.
//
// For each content:
//   1. Re-encrypt <dir>/<id>.app.dec  →  <dir>/<id>.app
//   2. Compute MD5 of the new .app
//   3. Compare against <dir>/<id>.app.md5
//   4. Match   → delete .app.dec and .app.md5  (recovery complete)
//   5. No match → warn, delete the bad .app (leave .app.dec + .app.md5 intact)
// ---------------------------------------------------------------------------
int pack_title(const char* dir)
{
    int r = -1;
    char str[PATH_MAX];
    PackTitleMetaData* tmd = NULL;
    uint8_t* tik = NULL;
    uint8_t title_id[16];
    uint8_t title_key[16];
    aes_context ctx;
    uint32_t ok_count = 0, fail_count = 0;

    const char* dec_patterns[] = {
        "%s%c%08x.app.dec",
        "%s%c%08X.app.dec"
    };

    // ---- Load TMD -------------------------------------------------------
    snprintf(str, sizeof(str), "%s%ctitle.tmd", dir, PATH_SEP);
    uint32_t tmd_len = read_file(str, (uint8_t**)&tmd);
    if (tmd_len == 0) {
        fprintf(stderr, "ERROR: Could not read title.tmd from '%s'\n", dir);
        goto out;
    }
    if (tmd->Version != 1) {
        fprintf(stderr, "ERROR: Unsupported TMD version: %u\n", tmd->Version);
        goto out;
    }

    // ---- Load TIK -------------------------------------------------------
    snprintf(str, sizeof(str), "%s%ctitle.tik", dir, PATH_SEP);
    uint32_t tik_len = read_file(str, &tik);
    if (tik_len == 0) {
        fprintf(stderr, "ERROR: Could not read title.tik from '%s'\n", dir);
        goto out;
    }

    printf("Title ID      : %016" PRIX64 "\n", getbe64(&tmd->TitleID));
    printf("Title version : %u\n", getbe16(&tmd->TitleVersion));
    printf("Content count : %u\n", getbe16(&tmd->ContentCount));

    // ---- Derive title key -----------------------------------------------
    if (strcmp((char*)tmd->Issuer, "Root-CA00000003-CP0000000b") == 0)
        aes_setkey_dec(&ctx, WiiUCommonKey, 128);
    else if (strcmp((char*)tmd->Issuer, "Root-CA00000004-CP00000010") == 0)
        aes_setkey_dec(&ctx, WiiUCommonDevKey, 128);
    else {
        fprintf(stderr, "ERROR: Unknown issuer: '%s'\n", (char*)tmd->Issuer);
        goto out;
    }

    memset(title_id, 0, sizeof(title_id));
    memcpy(title_id, &tmd->TitleID, 8);
    memcpy(title_key, tik + 0x1BF, 16);
    aes_crypt_cbc(&ctx, AES_DECRYPT, 16, title_id, title_key, title_key);

    printf("Title key derived from ticket.\n\n");

    // ---- Re-encrypt and verify each content -----------------------------
    uint16_t content_count = getbe16(&tmd->ContentCount);
    for (uint16_t i = 0; i < content_count; i++) {
        uint32_t content_file_id = getbe32(&tmd->Contents[i].ID);
        uint64_t content_size    = getbe64(&tmd->Contents[i].Size);
        uint16_t content_index   = getbe16(&tmd->Contents[i].Index);

        // Find the .app.dec source
        str[0] = '\0';
        for (uint32_t k = 0; k < 2; k++) {
            snprintf(str, sizeof(str), dec_patterns[k], dir, PATH_SEP, content_file_id);
            if (is_file(str)) break;
        }
        if (!is_file(str)) {
            fprintf(stderr, "WARNING: Could not find .app.dec for content %08X, skipping\n",
                    content_file_id);
            continue;
        }

        char dec_path[PATH_MAX], app_path[PATH_MAX], md5_path[PATH_MAX];
        snprintf(dec_path, sizeof(dec_path), "%s", str);
        snprintf(app_path, sizeof(app_path), "%s%c%08x.app",     dir, PATH_SEP, content_file_id);
        snprintf(md5_path, sizeof(md5_path), "%s%c%08x.app.md5", dir, PATH_SEP, content_file_id);

        printf("[%3u/%3u] %08X  size: %10" PRIu64 "  index: %u\n",
               i + 1, content_count, content_file_id, content_size, content_index);

        // Step 1: re-encrypt .app.dec → .app
        if (!encrypt_app_raw(dec_path, app_path, content_index, content_size, title_key)) {
            fprintf(stderr, "  ERROR: Encryption failed for content %08X\n", content_file_id);
            remove(app_path);
            fail_count++;
            continue;
        }

        // Step 2: compute MD5 of the new .app
        uint8_t digest_new[16];
        FILE* f = fopen_utf8(app_path, "rb");
        if (f == NULL || !md5_of_file(f, digest_new)) {
            if (f) fclose(f);
            fprintf(stderr, "  ERROR: Could not compute MD5 for '%s'\n", app_path);
            remove(app_path);
            fail_count++;
            continue;
        }
        fclose(f);

        // Step 3: read stored .app.md5
        uint8_t digest_stored[16];
        FILE* mf = fopen_utf8(md5_path, "rb");
        if (mf == NULL) {
            fprintf(stderr, "  ERROR: Could not read MD5 file '%s'\n", md5_path);
            remove(app_path);
            fail_count++;
            continue;
        }
        bool md5_read_ok = (fread(digest_stored, 1, 16, mf) == 16);
        fclose(mf);

        if (!md5_read_ok) {
            fprintf(stderr, "  ERROR: Could not read MD5 file '%s'\n", md5_path);
            remove(app_path);
            fail_count++;
            continue;
        }

        // Step 4: compare
        if (memcmp(digest_new, digest_stored, 16) != 0) {
            char hex_new[33], hex_stored[33];
            md5_to_hex(digest_new, hex_new);
            md5_to_hex(digest_stored, hex_stored);
            fprintf(stderr, "  WARNING: MD5 mismatch for content %08X\n", content_file_id);
            fprintf(stderr, "    expected : %s\n", hex_stored);
            fprintf(stderr, "    got      : %s\n", hex_new);
            fprintf(stderr, "    Keeping .app.dec and .app.md5 intact.\n");
            remove(app_path);
            fail_count++;
            continue;
        }

        char hex_new[33];
        md5_to_hex(digest_new, hex_new);
        printf("  OK  MD5: %s\n", hex_new);

        // Step 5: verified — clean up .app.dec and .app.md5
        remove(dec_path);
        remove(md5_path);
        ok_count++;
    }

    printf("\nEncrypt complete: %u succeeded, %u failed.\n", ok_count, fail_count);
    r = (fail_count == 0) ? 0 : -1;

out:
    free(tmd);
    free(tik);
    return r;
}