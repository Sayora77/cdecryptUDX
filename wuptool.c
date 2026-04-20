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
#include "cpack.h"

// We use part of the root cert name used by TMD/TIK to identify them
#define TMD_MAGIC       0x4350303030303030ULL   // 'CP000000'
#define TIK_MAGIC       0x5853303030303030ULL   // 'XS000000'
#define T_MAGIC_OFFSET  0x0150

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
        if (bytes_read == 0)
            break;

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

int main_utf8(int argc, char** argv)
{
    int r = EXIT_FAILURE;
    char str[PATH_MAX], *tmd_path = NULL, *tik_path = NULL;
    TitleMetaData* tmd = NULL;
    uint8_t* tik = NULL;
    const char* pattern[] = { "%s%c%08x.app", "%s%c%08X.app", "%s%c%08x", "%s%c%08X" };

    if (argc < 2) {
        printf("%s %s - Wii U NUS content tool\n"
            "Copyright (c) 2020-2023 VitaSmith, Copyright (c) 2013-2015 crediar\n"
            "Visit https://github.com/VitaSmith/cdecrypt for official source and downloads.\n\n"
            "Usage:\n"
            "  %s unpack <nus_dir> [output_dir]\n"
            "      Decrypt all .app files and write them as .app.dec files.\n"
            "      output_dir defaults to nus_dir if not specified.\n\n"
            "  %s pack <input_dir> <output_dir>\n"
            "      Re-encrypt .app.dec files back to .app files using the\n"
            "      title key derived from title.tik in input_dir.\n\n"
            "This program is free software; you can redistribute it and/or modify it under\n"
            "the terms of the GNU General Public License as published by the Free Software\n"
            "Foundation; either version 3 of the License or any later version.\n",
            _appname(argv[0]), APP_VERSION_STR, _appname(argv[0]), _appname(argv[0]));
        return EXIT_SUCCESS;
    }

    // ---- pack subcommand -------------------------------------------------
    if (strcmp(argv[1], "pack") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Usage: %s pack <input_dir> <output_dir>\n", _appname(argv[0]));
            return EXIT_FAILURE;
        }
        return pack_title(argv[2], argv[3]);
    }

    // ---- unpack subcommand -----------------------------------------------
    if (strcmp(argv[1], "unpack") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s unpack <nus_dir> [output_dir]\n", _appname(argv[0]));
            return EXIT_FAILURE;
        }
        // Shift argv so the unpack logic below sees argv[1] as the NUS directory
        for (int i = 1; i < argc - 1; i++)
            argv[i] = argv[i + 1];
        argc--;
    } else {
        fprintf(stderr, "ERROR: Unknown command '%s'\n\n"
                "Usage:\n"
                "  %s unpack <nus_dir> [output_dir]\n"
                "  %s pack   <input_dir> <output_dir>\n",
                argv[1], _appname(argv[0]), _appname(argv[0]));
        return EXIT_FAILURE;
    }

    // ---- unpack logic ----------------------------------------------------

    if (!is_directory(argv[1])) {
        uint8_t* buf = NULL;
        uint32_t size = read_file_max(argv[1], &buf, T_MAGIC_OFFSET + sizeof(uint64_t));
        if (size == 0)
            goto out;
        uint64_t magic = getbe64(&buf[T_MAGIC_OFFSET]);
        free(buf);

        if (magic == TMD_MAGIC) {
            tmd_path = strdup(argv[1]);
            tik_path = strdup(argv[1]);
            tik_path[strlen(tik_path) - 2] = 'i';
            tik_path[strlen(tik_path) - 1] = 'k';
        } else if (magic == TIK_MAGIC) {
            tik_path = strdup(argv[1]);
            tmd_path = strdup(argv[1]);
            tmd_path[strlen(tmd_path) - 2] = 'm';
            tmd_path[strlen(tmd_path) - 1] = 'd';
        } else {
            fprintf(stderr, "ERROR: Unrecognized file type (not a TMD or TIK)\n");
            goto out;
        }

        // Trim filename so argv[1] becomes the containing directory
        argv[1][get_trailing_slash(argv[1])] = 0;
        if (argv[1][0] == 0) {
            argv[1][0] = '.';
            argv[1][1] = 0;
        }
    }

    if ((tmd_path == NULL) || (tik_path == NULL)) {
        size_t len = strlen(argv[1]);
        free(tmd_path);
        free(tik_path);
        tmd_path = calloc(len + 16, 1);
        tik_path = calloc(len + 16, 1);
        sprintf(tmd_path, "%s%ctitle.tmd", argv[1], PATH_SEP);
        sprintf(tik_path, "%s%ctitle.tik", argv[1], PATH_SEP);
    }

    uint32_t tmd_len = read_file(tmd_path, (uint8_t**)&tmd);
    if (tmd_len == 0)
        goto out;

    uint32_t tik_len = read_file(tik_path, &tik);
    if (tik_len == 0)
        goto out;

    if (tmd->Version != 1) {
        fprintf(stderr, "ERROR: Unsupported TMD version: %u\n", tmd->Version);
        goto out;
    }

    printf("Title version : %u\n", getbe16(&tmd->TitleVersion));
    printf("Content count : %u\n", getbe16(&tmd->ContentCount));

    if (strcmp((char*)(&tmd->Issuer), "Root-CA00000003-CP0000000b") == 0) {
        aes_setkey_dec(&ctx, WiiUCommonKey, sizeof(WiiUCommonKey) * 8);
    } else if (strcmp((char*)(&tmd->Issuer), "Root-CA00000004-CP00000010") == 0) {
        aes_setkey_dec(&ctx, WiiUCommonDevKey, sizeof(WiiUCommonDevKey) * 8);
    } else {
        fprintf(stderr, "ERROR: Unknown issuer: '%s'\n", (char*)tmd + 0x140);
        goto out;
    }

    // Decrypt the title key from the ticket using the title ID as the IV
    memset(title_id, 0, sizeof(title_id));
    memcpy(title_id, &tmd->TitleID, 8);
    memcpy(title_key, tik + 0x1BF, 16);
    aes_crypt_cbc(&ctx, AES_DECRYPT, sizeof(title_key), title_id, title_key, title_key);

    // Switch the AES context to the decrypted title key for content decryption
    aes_setkey_dec(&ctx, title_key, sizeof(title_key) * 8);

    const char* src_dir = argv[1];
    const char* dst_dir = (argc > 2) ? argv[2] : argv[1];
    printf("Output directory: '%s'\n", dst_dir);
    create_path((char*)dst_dir);

    uint16_t content_count = getbe16(&tmd->ContentCount);
    for (uint16_t i = 0; i < content_count; i++) {
        uint32_t content_file_id = getbe32(&tmd->Contents[i].ID);
        uint64_t content_size    = getbe64(&tmd->Contents[i].Size);
        uint16_t content_index   = getbe16(&tmd->Contents[i].Index);
        uint16_t content_type    = getbe16(&tmd->Contents[i].Type);
        bool     is_hashed       = (content_type & 0x0002) != 0;

        str[0] = '\0';
        for (uint32_t k = 0; k < array_size(pattern); k++) {
            sprintf(str, pattern[k], src_dir, PATH_SEP, content_file_id);
            if (is_file(str))
                break;
        }
        if (!is_file(str)) {
            fprintf(stderr, "WARNING: Could not find .app file for content %08X, skipping\n",
                    content_file_id);
            continue;
        }

        char dst_path[PATH_MAX];
        snprintf(dst_path, sizeof(dst_path), "%s%c%08X.app.dec", dst_dir, PATH_SEP, content_file_id);

        printf("[%3u/%3u] %08X  size: %10" PRIu64 "  index: %u  %s%s\n",
               i + 1, content_count, content_file_id, content_size,
               content_index, is_hashed ? "[hashed] " : "", dst_path);

        if (!decrypt_app_raw(str, dst_path, content_index, content_size)) {
            fprintf(stderr, "ERROR: Failed to decrypt content %08X\n", content_file_id);
            goto out;
        }
    }

    printf("Done. %u content file(s) decrypted.\n", content_count);
    r = EXIT_SUCCESS;

out:
    free(tmd);
    free(tik);
    free(tmd_path);
    free(tik_path);
    return r;
}

CALL_MAIN