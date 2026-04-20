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
// Copy a file verbatim — used to carry .tmd, .tik, .cert into output_dir
// ---------------------------------------------------------------------------
static bool pack_copy_file(const char* src_path, const char* dst_path)
{
    bool r = false;
    FILE* src = NULL;
    FILE* dst = NULL;
    uint8_t* buf = malloc(PACK_BLOCK_SIZE);

    if (buf == NULL) {
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
    for (;;) {
        size_t n = fread(buf, 1, PACK_BLOCK_SIZE, src);
        if (n == 0) break;
        if (fwrite(buf, 1, n, dst) != n) {
            fprintf(stderr, "ERROR: Write failed to '%s'\n", dst_path);
            goto out;
        }
    }
    r = true;
out:
    if (src != NULL) fclose(src);
    if (dst != NULL) fclose(dst);
    free(buf);
    return r;
}

// ---------------------------------------------------------------------------
// Re-encrypt one .app.dec file back to a .app file.
//
// This is the exact inverse of decrypt_app_raw in wuptool.c:
//   - Same block size (0x8000)
//   - Same IV scheme: zeroed, content_index in byte [1]
//   - Always write full 0x8000-byte blocks, zero-padding the last one.
//     The original .app files were always block-aligned, so this produces
//     byte-identical output to the original encrypted content.
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

    // Local encryption context — does not touch the global ctx in wuptool.c
    aes_setkey_enc(&enc_ctx, title_key, 128);

    // IV matches what decrypt_app_raw uses: all zeroes, content_index in byte [1]
    memset(iv, 0, sizeof(iv));
    iv[1] = (uint8_t)content_index;

    remaining = data_size;
    while (remaining > 0) {
        size_t to_read = (remaining < PACK_BLOCK_SIZE) ? (size_t)remaining : PACK_BLOCK_SIZE;

        // Zero-fill so the final partial block is padded identically to the
        // original (Nintendo's tooling zero-pads before encrypting too)
        memset(plain, 0, PACK_BLOCK_SIZE);

        size_t bytes_read = fread(plain, 1, to_read, src);
        if (bytes_read == 0)
            break;

        // Always encrypt a full block — .app files are always block-aligned
        // CBC chaining is handled automatically: aes_crypt_cbc updates iv to
        // the last ciphertext block, so the next iteration uses the right IV
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
// pack_title — re-encrypt all .app.dec files back to .app
//
// The title key is derived from the .tik file the same way unpack does:
//   common_key (from TMD issuer) → AES-CBC decrypt tik[0x1BF] with title_id IV
//
// title.tmd, title.tik, and title.cert are copied verbatim — no regeneration.
// ---------------------------------------------------------------------------
int pack_title(const char* input_dir, const char* output_dir)
{
    int r = -1;
    char str[PATH_MAX];
    PackTitleMetaData* tmd = NULL;
    uint8_t* tik = NULL;
    uint8_t title_id[16];
    uint8_t title_key[16];
    aes_context ctx;

    const char* dec_patterns[] = {
        "%s%c%08x.app.dec",
        "%s%c%08X.app.dec"
    };

    // ---- Load TMD -------------------------------------------------------
    snprintf(str, sizeof(str), "%s%ctitle.tmd", input_dir, PATH_SEP);
    uint32_t tmd_len = read_file(str, (uint8_t**)&tmd);
    if (tmd_len == 0) {
        fprintf(stderr, "ERROR: Could not read title.tmd from '%s'\n", input_dir);
        goto out;
    }

    if (tmd->Version != 1) {
        fprintf(stderr, "ERROR: Unsupported TMD version: %u\n", tmd->Version);
        goto out;
    }

    // ---- Load TIK -------------------------------------------------------
    snprintf(str, sizeof(str), "%s%ctitle.tik", input_dir, PATH_SEP);
    uint32_t tik_len = read_file(str, &tik);
    if (tik_len == 0) {
        fprintf(stderr, "ERROR: Could not read title.tik from '%s'\n", input_dir);
        goto out;
    }

    printf("Title ID      : %016" PRIX64 "\n", getbe64(&tmd->TitleID));
    printf("Title version : %u\n",  getbe16(&tmd->TitleVersion));
    printf("Content count : %u\n",  getbe16(&tmd->ContentCount));

    // ---- Derive title key (mirrors unpack exactly) ----------------------
    // Step 1: select common key from issuer field
    if (strcmp((char*)tmd->Issuer, "Root-CA00000003-CP0000000b") == 0) {
        aes_setkey_dec(&ctx, WiiUCommonKey, 128);
    } else if (strcmp((char*)tmd->Issuer, "Root-CA00000004-CP00000010") == 0) {
        aes_setkey_dec(&ctx, WiiUCommonDevKey, 128);
    } else {
        fprintf(stderr, "ERROR: Unknown issuer: '%s'\n", (char*)tmd->Issuer);
        goto out;
    }

    // Step 2: title_id (big-endian, zero-padded to 16 bytes) is the IV
    memset(title_id, 0, sizeof(title_id));
    memcpy(title_id, &tmd->TitleID, 8);

    // Step 3: decrypt the encrypted title key stored at tik[0x1BF]
    memcpy(title_key, tik + 0x1BF, 16);
    aes_crypt_cbc(&ctx, AES_DECRYPT, 16, title_id, title_key, title_key);

    printf("Title key derived from ticket.\n");

    // ---- Prepare output directory ----------------------------------------
    create_path((char*)output_dir);

    // ---- Copy metadata files verbatim -----------------------------------
    // title.tmd
    snprintf(str, sizeof(str), "%s%ctitle.tmd", input_dir, PATH_SEP);
    char dst_meta[PATH_MAX];
    snprintf(dst_meta, sizeof(dst_meta), "%s%ctitle.tmd", output_dir, PATH_SEP);
    if (!pack_copy_file(str, dst_meta))
        goto out;

    // title.tik
    snprintf(str, sizeof(str), "%s%ctitle.tik", input_dir, PATH_SEP);
    snprintf(dst_meta, sizeof(dst_meta), "%s%ctitle.tik", output_dir, PATH_SEP);
    if (!pack_copy_file(str, dst_meta))
        goto out;

    // title.cert (optional — present in most NUS packages)
    snprintf(str, sizeof(str), "%s%ctitle.cert", input_dir, PATH_SEP);
    if (is_file(str)) {
        snprintf(dst_meta, sizeof(dst_meta), "%s%ctitle.cert", output_dir, PATH_SEP);
        if (!pack_copy_file(str, dst_meta))
            goto out;
    }

    // ---- Re-encrypt each content ----------------------------------------
    uint16_t content_count = getbe16(&tmd->ContentCount);
    for (uint16_t i = 0; i < content_count; i++) {
        uint32_t content_file_id = getbe32(&tmd->Contents[i].ID);
        uint64_t content_size    = getbe64(&tmd->Contents[i].Size);
        uint16_t content_index   = getbe16(&tmd->Contents[i].Index);

        // Find the .app.dec source (handle upper/lowercase)
        str[0] = '\0';
        for (uint32_t k = 0; k < 2; k++) {
            snprintf(str, sizeof(str), dec_patterns[k], input_dir, PATH_SEP, content_file_id);
            if (is_file(str))
                break;
        }
        if (!is_file(str)) {
            fprintf(stderr, "WARNING: Could not find .app.dec for content %08X, skipping\n",
                    content_file_id);
            continue;
        }

        // Destination: <output_dir>/<id>.app
        char dst_path[PATH_MAX];
        snprintf(dst_path, sizeof(dst_path), "%s%c%08X.app",
                 output_dir, PATH_SEP, content_file_id);

        printf("[%3u/%3u] %08X  size: %10" PRIu64 "  index: %u  -> %s\n",
               i + 1, content_count, content_file_id, content_size,
               content_index, dst_path);

        if (!encrypt_app_raw(str, dst_path, content_index, content_size, title_key)) {
            fprintf(stderr, "ERROR: Failed to encrypt content %08X\n", content_file_id);
            goto out;
        }
    }

    printf("Done. %u content file(s) encrypted.\n", content_count);
    r = 0;

out:
    free(tmd);
    free(tik);
    return r;
}