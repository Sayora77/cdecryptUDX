/*
  cpack - Pack Wii U NUS content files (encryption support)

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
#include <dirent.h>
#include <sys/stat.h>

#include "cpack.h"
#include "util.h"
#include "utf8.h"
#include "aes.h"
#include "sha1.h"

// Path separator as string
#define PATH_SEP_STR  "/"

// Wii U Common Key
static const uint8_t WiiUCommonKey[16] = {
    0xD7, 0xB0, 0x04, 0x02, 0x65, 0x9B, 0xA2, 0xAB,
    0xD2, 0xCB, 0x0D, 0xB2, 0x7F, 0xA2, 0xB6, 0x56
};

// ============================================================================
// Hash Tree Operations
// ============================================================================

hash_tree* hash_tree_create(uint32_t block_count) {
    hash_tree* ht = calloc(1, sizeof(hash_tree));
    if (!ht) return NULL;
    
    ht->block_count = block_count;
    
    // H0: one hash per block
    ht->h0 = calloc(block_count * HASH_SIZE, 1);
    if (!ht->h0) goto error;
    
    // H1: one hash per 16 H0 hashes
    uint32_t h1_count = (block_count + 15) / 16;
    ht->h1 = calloc(h1_count * HASH_SIZE, 1);
    if (!ht->h1) goto error;
    
    // H2: one hash per 16 H1 hashes
    uint32_t h2_count = (h1_count + 15) / 16;
    ht->h2 = calloc(h2_count * HASH_SIZE, 1);
    if (!ht->h2) goto error;
    
    // H3: one hash per 16 H2 hashes
    uint32_t h3_count = (h2_count + 15) / 16;
    ht->h3 = calloc(h3_count * HASH_SIZE, 1);
    if (!ht->h3) goto error;
    
    return ht;
    
error:
    hash_tree_free(ht);
    return NULL;
}

void hash_tree_free(hash_tree* ht) {
    if (!ht) return;
    free(ht->h0);
    free(ht->h1);
    free(ht->h2);
    free(ht->h3);
    free(ht);
}

int hash_tree_calculate(hash_tree* ht, const uint8_t* data, uint32_t data_size) {
    if (!ht || !data) return -1;
    
    uint8_t block_buffer[HASH_BLOCK_SIZE];
    uint8_t hash_buffer[16 * HASH_SIZE];
    
    // Calculate H0 hashes (one per 0xFC00 data block)
    for (uint32_t i = 0; i < ht->block_count; i++) {
        uint32_t offset = i * HASH_BLOCK_SIZE;
        
        if (offset >= data_size) {
            // Zero pad
            memset(block_buffer, 0, HASH_BLOCK_SIZE);
        } else {
            uint32_t remaining = data_size - offset;
            if (remaining < HASH_BLOCK_SIZE) {
                memcpy(block_buffer, data + offset, remaining);
                memset(block_buffer + remaining, 0, HASH_BLOCK_SIZE - remaining);
            } else {
                memcpy(block_buffer, data + offset, HASH_BLOCK_SIZE);
            }
        }
        
        sha1(block_buffer, HASH_BLOCK_SIZE, ht->h0 + i * HASH_SIZE);
    }
    
    // Calculate H1 hashes (hash of 16 H0 hashes)
    uint32_t h1_count = (ht->block_count + 15) / 16;
    for (uint32_t i = 0; i < h1_count; i++) {
        memset(hash_buffer, 0, sizeof(hash_buffer));
        for (uint32_t j = 0; j < 16; j++) {
            uint32_t idx = i * 16 + j;
            if (idx < ht->block_count) {
                memcpy(hash_buffer + j * HASH_SIZE, ht->h0 + idx * HASH_SIZE, HASH_SIZE);
            }
        }
        sha1(hash_buffer, 16 * HASH_SIZE, ht->h1 + i * HASH_SIZE);
    }
    
    // Calculate H2 hashes (hash of 16 H1 hashes)
    uint32_t h2_count = (h1_count + 15) / 16;
    for (uint32_t i = 0; i < h2_count; i++) {
        memset(hash_buffer, 0, sizeof(hash_buffer));
        for (uint32_t j = 0; j < 16; j++) {
            uint32_t idx = i * 16 + j;
            if (idx < h1_count) {
                memcpy(hash_buffer + j * HASH_SIZE, ht->h1 + idx * HASH_SIZE, HASH_SIZE);
            }
        }
        sha1(hash_buffer, 16 * HASH_SIZE, ht->h2 + i * HASH_SIZE);
    }
    
    // Calculate H3 hashes (hash of 16 H2 hashes)
    uint32_t h3_count = (h2_count + 15) / 16;
    for (uint32_t i = 0; i < h3_count; i++) {
        memset(hash_buffer, 0, sizeof(hash_buffer));
        for (uint32_t j = 0; j < 16; j++) {
            uint32_t idx = i * 16 + j;
            if (idx < h2_count) {
                memcpy(hash_buffer + j * HASH_SIZE, ht->h2 + idx * HASH_SIZE, HASH_SIZE);
            }
        }
        sha1(hash_buffer, 16 * HASH_SIZE, ht->h3 + i * HASH_SIZE);
    }
    
    return 0;
}

int hash_tree_get_hashes_for_block(hash_tree* ht, uint32_t block, uint8_t* out_hashes) {
    if (!ht || !out_hashes || block >= ht->block_count) return -1;
    
    uint8_t* ptr = out_hashes;
    
    // 16 H0 hashes (starting from block aligned to 16)
    uint32_t h0_start = (block / 16) * 16;
    for (uint32_t i = 0; i < 16; i++) {
        uint32_t idx = h0_start + i;
        if (idx < ht->block_count) {
            memcpy(ptr, ht->h0 + idx * HASH_SIZE, HASH_SIZE);
        } else {
            memset(ptr, 0, HASH_SIZE);
        }
        ptr += HASH_SIZE;
    }
    
    // 16 H1 hashes
    uint32_t h1_start = (block / 256) * 16;
    uint32_t h1_count = (ht->block_count + 255) / 256;
    h1_count = (h1_count + 15) / 16 * 16;
    for (uint32_t i = 0; i < 16; i++) {
        uint32_t idx = h1_start + i;
        if (idx < (ht->block_count + 255) / 256) {
            memcpy(ptr, ht->h1 + idx * HASH_SIZE, HASH_SIZE);
        } else {
            memset(ptr, 0, HASH_SIZE);
        }
        ptr += HASH_SIZE;
    }
    
    // 16 H2 hashes
    uint32_t h2_start = (block / 4096) * 16;
    for (uint32_t i = 0; i < 16; i++) {
        uint32_t idx = h2_start + i;
        uint32_t h2_count = (ht->block_count + 4095) / 4096;
        if (idx < h2_count) {
            memcpy(ptr, ht->h2 + idx * HASH_SIZE, HASH_SIZE);
        } else {
            memset(ptr, 0, HASH_SIZE);
        }
        ptr += HASH_SIZE;
    }
    
    return 0;
}

// ============================================================================
// Content Encryption
// ============================================================================

static int encrypt_aes_cbc(const uint8_t* input, uint8_t* output, uint32_t len,
                           const uint8_t* key, uint8_t* iv) {
    aes_context ctx;
    aes_setkey_enc(&ctx, key, 128);
    aes_crypt_cbc(&ctx, AES_ENCRYPT, len, iv, input, output);
    return 0;
}

int encrypt_content_hashed(const char* input_dir, const char* output_dir,
                           pack_title_info* info, pack_content_info* content,
                           const uint8_t* title_key) {
    char input_path[1024];
    char output_path[1024];
    FILE* out_file = NULL;
    uint8_t* data_buffer = NULL;
    uint8_t* encrypted_buffer = NULL;
    int ret = -1;
    
    // Calculate total data size from files assigned to this content
    // Use updated offsets and sizes from scanning
    uint32_t total_size = 0;
    for (uint32_t i = 0; i < info->entry_count; i++) {
        if (info->entries[i].content_id == content->id && !info->entries[i].is_dir) {
            uint32_t end = info->entries[i].file_offset + info->entries[i].file_size;
            if (end > total_size) total_size = end;
        }
    }
    
    if (total_size == 0) {
        // Empty content - still need one block
        total_size = HASH_BLOCK_SIZE;
    }
    
    // Calculate block count from actual data size
    // Each encrypted block has 0xFC00 bytes of data
    uint32_t block_count = (total_size + HASH_BLOCK_SIZE - 1) / HASH_BLOCK_SIZE;
    if (block_count == 0) block_count = 1;
    
    // Allocate data buffer (padded to block boundary)
    uint32_t padded_size = block_count * HASH_BLOCK_SIZE;
    data_buffer = calloc(padded_size, 1);
    if (!data_buffer) goto cleanup;
    
    // Read all files into buffer at their offsets
    for (uint32_t i = 0; i < info->entry_count; i++) {
        pack_fst_entry* entry = &info->entries[i];
        if (entry->content_id != content->id || entry->is_dir) continue;
        
        snprintf(input_path, sizeof(input_path), "%s%s%s", 
                 input_dir, PATH_SEP_STR, entry->path);
        
        FILE* in_file = fopen_utf8(input_path, "rb");
        if (!in_file) {
            fprintf(stderr, "ERROR: Cannot open file: %s\n", input_path);
            goto cleanup;
        }
        
        if (fread(data_buffer + entry->file_offset, 1, entry->file_size, in_file) != entry->file_size) {
            fprintf(stderr, "ERROR: Cannot read file: %s\n", input_path);
            fclose(in_file);
            goto cleanup;
        }
        fclose(in_file);
    }
    
    // Create hash tree
    hash_tree* ht = hash_tree_create(block_count);
    if (!ht) goto cleanup;
    
    if (hash_tree_calculate(ht, data_buffer, padded_size) != 0) {
        hash_tree_free(ht);
        goto cleanup;
    }
    
    // Copy H3 hash to content info (for TMD)
    memcpy(content->hash, ht->h3, HASH_SIZE);
    
    // Update content size to actual encrypted size
    content->size = block_count * HASH_BLOCK_TOTAL;
    
    // Open output file
    snprintf(output_path, sizeof(output_path), "%s%s%s.app",
             output_dir, PATH_SEP_STR, content->filename);
    out_file = fopen_utf8(output_path, "wb");
    if (!out_file) {
        fprintf(stderr, "ERROR: Cannot create output file: %s\n", output_path);
        hash_tree_free(ht);
        goto cleanup;
    }
    
    // Encrypt each block
    encrypted_buffer = malloc(HASH_BLOCK_TOTAL);
    if (!encrypted_buffer) {
        hash_tree_free(ht);
        goto cleanup;
    }
    
    uint8_t iv[16];
    uint8_t hash_data[HASHES_SIZE];
    
    for (uint32_t block = 0; block < block_count; block++) {
        // Get hashes for this block
        if (hash_tree_get_hashes_for_block(ht, block, hash_data) != 0) {
            hash_tree_free(ht);
            goto cleanup;
        }
        
        // XOR content ID into hash
        hash_data[1] ^= (uint8_t)content->id;
        
        // Encrypt hashes
        memset(iv, 0, 16);
        *(uint16_t*)iv = bswap_uint16(content->id);
        encrypt_aes_cbc(hash_data, encrypted_buffer, HASHES_SIZE, title_key, iv);
        
        // Restore hash (for IV calculation)
        hash_data[1] ^= (uint8_t)content->id;
        
        // Write encrypted hashes
        fwrite(encrypted_buffer, 1, HASHES_SIZE, out_file);
        
        // Calculate IV from H0 hash
        uint32_t h0_idx = (block % 16) * HASH_SIZE;
        memcpy(iv, hash_data + h0_idx, 16);
        
        // Encrypt data block
        encrypt_aes_cbc(data_buffer + block * HASH_BLOCK_SIZE, 
                       encrypted_buffer, HASH_BLOCK_SIZE, title_key, iv);
        
        // Write encrypted data
        fwrite(encrypted_buffer, 1, HASH_BLOCK_SIZE, out_file);
    }
    
    content->size = block_count * HASH_BLOCK_TOTAL;
    ret = 0;
    
    hash_tree_free(ht);
    
cleanup:
    free(data_buffer);
    free(encrypted_buffer);
    if (out_file) fclose(out_file);
    return ret;
}

int encrypt_content_simple(const char* input_dir, const char* output_dir,
                           pack_title_info* info, pack_content_info* content,
                           const uint8_t* title_key) {
    char input_path[1024];
    char output_path[1024];
    FILE* out_file = NULL;
    uint8_t* data_buffer = NULL;
    uint8_t* encrypted_buffer = NULL;
    int ret = -1;
    
    // Calculate total data size from files assigned to this content
    uint32_t total_size = 0;
    for (uint32_t i = 0; i < info->entry_count; i++) {
        if (info->entries[i].content_id == content->id && !info->entries[i].is_dir) {
            uint32_t end = info->entries[i].file_offset + info->entries[i].file_size;
            if (end > total_size) total_size = end;
        }
    }
    
    if (total_size == 0) {
        // Empty content - still need padding
        total_size = 0x8000;
    }
    
    // Pad to 0x8000 boundary
    uint32_t padded_size = (total_size + 0x7FFF) & ~0x7FFF;
    if (padded_size == 0) padded_size = 0x8000;
    
    // Allocate data buffer
    data_buffer = calloc(padded_size, 1);
    if (!data_buffer) goto cleanup;
    
    // Read all files into buffer at their offsets
    for (uint32_t i = 0; i < info->entry_count; i++) {
        pack_fst_entry* entry = &info->entries[i];
        if (entry->content_id != content->id || entry->is_dir) continue;
        
        snprintf(input_path, sizeof(input_path), "%s%s%s", 
                 input_dir, PATH_SEP_STR, entry->path);
        
        FILE* in_file = fopen_utf8(input_path, "rb");
        if (!in_file) {
            fprintf(stderr, "ERROR: Cannot open file: %s\n", input_path);
            goto cleanup;
        }
        
        if (fread(data_buffer + entry->file_offset, 1, entry->file_size, in_file) != entry->file_size) {
            fprintf(stderr, "ERROR: Cannot read file: %s\n", input_path);
            fclose(in_file);
            goto cleanup;
        }
        fclose(in_file);
    }
    
    // Calculate hash for TMD (SHA1 of padded content)
    sha1(data_buffer, padded_size, content->hash);
    
    // Open output file
    snprintf(output_path, sizeof(output_path), "%s%s%s.app",
             output_dir, PATH_SEP_STR, content->filename);
    out_file = fopen_utf8(output_path, "wb");
    if (!out_file) {
        fprintf(stderr, "ERROR: Cannot create output file: %s\n", output_path);
        goto cleanup;
    }
    
    // Encrypt with CBC
    uint8_t iv[16] = {0};
    *(uint16_t*)iv = bswap_uint16(content->id);
    
    encrypted_buffer = malloc(padded_size);
    if (!encrypted_buffer) goto cleanup;
    
    encrypt_aes_cbc(data_buffer, encrypted_buffer, padded_size, title_key, iv);
    fwrite(encrypted_buffer, 1, padded_size, out_file);
    
    content->size = padded_size;
    ret = 0;
    
cleanup:
    free(data_buffer);
    free(encrypted_buffer);
    if (out_file) fclose(out_file);
    return ret;
}

// ============================================================================
// FST Building
// ============================================================================

uint8_t* build_fst_data(pack_title_info* info, uint32_t* out_size) {
    // FST structure from NUSPacker:
    // 1. FST Header (0x20 bytes)
    // 2. Content Headers (content_count * 0x20 bytes)
    // 3. File Entries (entry_count * 0x10 bytes)
    // 4. String Table
    
    // Calculate string table size
    uint32_t string_offset = 0;
    for (uint32_t i = 0; i < info->entry_count; i++) {
        info->entries[i].name_offset = string_offset;
        string_offset += strlen(info->entries[i].name) + 1;
    }
    info->string_table_size = string_offset;
    
    // Calculate sizes
    uint32_t header_size = 0x20;                          // FST header
    uint32_t content_headers_size = info->content_count * 0x20;  // Content headers
    uint32_t entry_size = info->entry_count * 0x10;       // File entries
    
    uint32_t total_size = header_size + content_headers_size + entry_size + string_offset;
    
    // Align to 0x8000
    uint32_t aligned_size = (total_size + 0x7FFF) & ~0x7FFF;
    
    uint8_t* fst = calloc(aligned_size, 1);
    if (!fst) return NULL;
    
    // 1. Write FST header
    fst[0] = 'F'; fst[1] = 'S'; fst[2] = 'T'; fst[3] = 0;
    setbe32(fst + 4, info->entry_count);           // Entry count
    setbe32(fst + 8, info->content_count);         // Content count
    // Remaining 0x14 bytes are padding
    
    // 2. Write Content Headers (at offset 0x20)
    uint8_t* content_ptr = fst + 0x20;
    for (uint32_t i = 0; i < info->content_count; i++) {
        pack_content_info* c = &info->contents[i];
        
        // Each content header is 0x20 bytes
        // Format from Content.getFSTContentHeaderAsData():
        // - offset: 4 bytes (calculated, but we'll use 0 for simplicity)
        // - size: 4 bytes
        // - parentTitleID: 8 bytes
        // - groupID: 4 bytes (at offset 0x10)
        // - unkwn: 1 byte (at offset 0x14): 0 for FST, 2 for hashed, 1 for non-hashed
        // - padding: 7 bytes
        
        setbe32(content_ptr + 0, 0);  // offset placeholder
        setbe32(content_ptr + 4, c->size / 0x8000);  // size in 32KB units
        
        // parentTitleID - use title_id for base game
        uint64_t parent_title_id = info->title_id;
        // For updates (0005000E) and DLC (0005000C), use base game title_id
        if ((info->title_id >> 32) == 0x0005000EULL || (info->title_id >> 32) == 0x0005000CULL) {
            parent_title_id = (info->title_id & 0xFFFFFFFF) | 0x00050000ULL;
        }
        setbe64(content_ptr + 8, parent_title_id);
        
        setbe32(content_ptr + 0x10, info->group_id);
        
        // unkwn: 0 for FST content (index 0), 2 for hashed, 1 for non-hashed
        if (c->index == 0) {
            content_ptr[0x14] = 0;  // FST content
        } else if (c->hashed) {
            content_ptr[0x14] = 2;  // Hashed content
        } else {
            content_ptr[0x14] = 1;  // Non-hashed content
        }
        
        content_ptr += 0x20;
    }
    
    // 3. Write File Entries (at offset 0x20 + content_headers_size)
    uint8_t* entry_ptr = fst + 0x20 + content_headers_size;
    
    for (uint32_t i = 0; i < info->entry_count; i++) {
        pack_fst_entry* e = &info->entries[i];
        
        if (e->is_dir) {
            // Directory entry
            // type: 1 byte (bit 0 = 1 for dir)
            // nameOffset: 3 bytes
            entry_ptr[0] = e->is_root ? 1 : (e->is_dir ? 1 : 0);
            entry_ptr[1] = (e->name_offset >> 16) & 0xFF;
            entry_ptr[2] = (e->name_offset >> 8) & 0xFF;
            entry_ptr[3] = e->name_offset & 0xFF;
            
            setbe32(entry_ptr + 4, e->parent_idx);      // Parent offset
            setbe32(entry_ptr + 8, e->next_idx);        // Next offset
            setbe16(entry_ptr + 12, 0);                 // Flags
            setbe16(entry_ptr + 14, 0);                 // Content ID
        } else {
            // File entry
            // type: 1 byte (0 for file)
            // nameOffset: 3 bytes
            entry_ptr[0] = 0;
            entry_ptr[1] = (e->name_offset >> 16) & 0xFF;
            entry_ptr[2] = (e->name_offset >> 8) & 0xFF;
            entry_ptr[3] = e->name_offset & 0xFF;
            
            // fileoffset is stored as offset >> 5
            setbe32(entry_ptr + 4, e->file_offset >> 5);
            setbe32(entry_ptr + 8, e->file_size);
            setbe16(entry_ptr + 12, e->flags);
            setbe16(entry_ptr + 14, e->content_id);
        }
        
        entry_ptr += 0x10;
    }
    
    // 4. Write String Table
    uint8_t* string_ptr = fst + 0x20 + content_headers_size + entry_size;
    for (uint32_t i = 0; i < info->entry_count; i++) {
        strcpy((char*)string_ptr, info->entries[i].name);
        string_ptr += strlen(info->entries[i].name) + 1;
    }
    
    *out_size = aligned_size;
    return fst;
}

// ============================================================================
// JSON Metadata Parsing (simple parser without external dependencies)
// ============================================================================

static char* read_file_content(const char* path) {
    FILE* f = fopen_utf8(path, "rb");
    if (!f) return NULL;
    
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    char* content = malloc(size + 1);
    if (!content) {
        fclose(f);
        return NULL;
    }
    
    if (fread(content, 1, size, f) != (size_t)size) {
        free(content);
        fclose(f);
        return NULL;
    }
    content[size] = '\0';
    fclose(f);
    
    return content;
}

static char* json_get_string(const char* json, const char* key) {
    char search[256];
    snprintf(search, sizeof(search), "\"%s\"", key);
    
    const char* pos = strstr(json, search);
    if (!pos) return NULL;
    
    pos = strchr(pos + strlen(search), ':');
    if (!pos) return NULL;
    
    while (*pos && (*pos == ':' || *pos == ' ' || *pos == '\t')) pos++;
    if (*pos != '"') return NULL;
    pos++;
    
    const char* end = strchr(pos, '"');
    if (!end) return NULL;
    
    size_t len = end - pos;
    char* result = malloc(len + 1);
    if (!result) return NULL;
    
    memcpy(result, pos, len);
    result[len] = '\0';
    return result;
}

static uint64_t json_get_uint64_hex(const char* json, const char* key) {
    char* str = json_get_string(json, key);
    if (!str) return 0;
    
    char* end;
    uint64_t val = strtoull(str, &end, 16);  // Parse as hex
    free(str);
    return val;
}

static uint16_t json_get_uint16_hex(const char* json, const char* key) {
    return (uint16_t)json_get_uint64_hex(json, key);
}

static uint32_t json_get_uint32_hex(const char* json, const char* key) {
    return (uint32_t)json_get_uint64_hex(json, key);
}

static uint64_t json_get_uint64(const char* json, const char* key) {
    char* str = json_get_string(json, key);
    if (!str) {
        // Try to get as number (without quotes)
        char search[256];
        snprintf(search, sizeof(search), "\"%s\"", key);
        
        const char* pos = strstr(json, search);
        if (!pos) return 0;
        
        pos = strchr(pos + strlen(search), ':');
        if (!pos) return 0;
        
        while (*pos && (*pos == ':' || *pos == ' ' || *pos == '\t')) pos++;
        
        // Parse number
        char* end;
        return strtoull(pos, &end, 0);
    }
    
    char* end;
    uint64_t val = strtoull(str, &end, 0);
    free(str);
    return val;
}

static uint32_t json_get_uint32(const char* json, const char* key) {
    return (uint32_t)json_get_uint64(json, key);
}

static uint16_t json_get_uint16(const char* json, const char* key) {
    return (uint16_t)json_get_uint64(json, key);
}

static bool json_get_bool(const char* json, const char* key) {
    char search[256];
    snprintf(search, sizeof(search), "\"%s\"", key);
    
    const char* pos = strstr(json, search);
    if (!pos) return false;
    
    pos = strchr(pos + strlen(search), ':');
    if (!pos) return false;
    
    while (*pos && (*pos == ':' || *pos == ' ' || *pos == '\t')) pos++;
    
    return (strncmp(pos, "true", 4) == 0);
}

static const char* find_array(const char* json, const char* key) {
    char search[256];
    snprintf(search, sizeof(search), "\"%s\"", key);
    
    const char* pos = strstr(json, search);
    if (!pos) return NULL;
    
    pos = strchr(pos + strlen(search), '[');
    return pos;
}

int parse_metadata_json(const char* path, pack_title_info* info) {
    char* json = read_file_content(path);
    if (!json) {
        fprintf(stderr, "ERROR: Cannot read metadata file: %s\n", path);
        return -1;
    }
    
    memset(info, 0, sizeof(pack_title_info));
    
    // Find the "title" object
    const char* title_obj = strstr(json, "\"title\"");
    if (title_obj) {
        title_obj = strchr(title_obj, '{');
        if (title_obj) {
            const char* title_end = strchr(title_obj, '}');
            if (title_end) {
                size_t title_len = title_end - title_obj + 1;
                char* title = malloc(title_len + 1);
                memcpy(title, title_obj, title_len);
                title[title_len] = '\0';
                
                info->title_id = json_get_uint64_hex(title, "title_id");  // Parse as hex
                info->version = json_get_uint32(title, "title_version");
                info->group_id = json_get_uint16(title, "group_id");
                
                // Determine title type from title_id pattern
                // title_id upper 32 bits: 00050000 = base, 0005000E = update, 0005000C = DLC
                if ((info->title_id >> 32) == 0x0005000EULL) {
                    info->title_type = 0x0E; // Update
                } else if ((info->title_id >> 32) == 0x0005000CULL) {
                    info->title_type = 0x0C; // DLC
                } else {
                    info->title_type = 0x00; // Base game
                }
                
                free(title);
            }
        }
    }
    
    // Parse contents array
    const char* contents_start = find_array(json, "contents");
    if (contents_start) {
        // Count contents
        const char* pos = contents_start + 1;
        int count = 0;
        while (*pos && *pos != ']') {
            const char* obj = strchr(pos, '{');
            if (!obj || obj > strchr(pos, ']')) break;
            count++;
            pos = strchr(obj, '}');
            if (!pos) break;
            pos++;
            while (*pos && (*pos == ' ' || *pos == '\t' || *pos == '\n' || *pos == ',')) pos++;
        }
        
        info->content_count = count;
        info->contents = calloc(count, sizeof(pack_content_info));
        
        // Parse each content
        pos = contents_start + 1;
        int idx = 0;
        while (*pos && *pos != ']' && idx < count) {
            const char* obj_start = strchr(pos, '{');
            const char* obj_end = strchr(obj_start, '}');
            if (!obj_start || !obj_end) break;
            
            // Extract object as string
            size_t obj_len = obj_end - obj_start + 1;
            char* obj = malloc(obj_len + 1);
            memcpy(obj, obj_start, obj_len);
            obj[obj_len] = '\0';
            
            info->contents[idx].id = json_get_uint32_hex(obj, "id");  // Parse as hex
            info->contents[idx].index = json_get_uint16(obj, "index");
            info->contents[idx].type = json_get_uint16_hex(obj, "type");  // Parse as hex
            info->contents[idx].size = json_get_uint32(obj, "size");
            info->contents[idx].hashed = json_get_bool(obj, "hashed");
            
            // Parse hash
            char* hash_str = json_get_string(obj, "hash");
            if (hash_str) {
                for (int i = 0; i < 20 && hash_str[i*2] && hash_str[i*2+1]; i++) {
                    char byte[3] = {hash_str[i*2], hash_str[i*2+1], 0};
                    info->contents[idx].hash[i] = (uint8_t)strtol(byte, NULL, 16);
                }
                free(hash_str);
            }
            
            snprintf(info->contents[idx].filename, sizeof(info->contents[idx].filename),
                     "%08X", info->contents[idx].id);
            
            free(obj);
            idx++;
            pos = obj_end + 1;
            while (*pos && (*pos == ' ' || *pos == '\t' || *pos == '\n' || *pos == ',')) pos++;
        }
    }
    
    // Parse files array
    const char* files_start = find_array(json, "files");
    if (files_start) {
        // Count files
        const char* pos = files_start + 1;
        int count = 0;
        while (*pos && *pos != ']') {
            const char* obj = strchr(pos, '{');
            if (!obj || obj > strchr(pos, ']')) break;
            count++;
            pos = strchr(obj, '}');
            if (!pos) break;
            pos++;
            while (*pos && (*pos == ' ' || *pos == '\t' || *pos == '\n' || *pos == ',')) pos++;
        }
        
        info->entry_count = count + 1; // +1 for root
        info->entries = calloc(count + 1, sizeof(pack_fst_entry));
        
        // Set root entry
        info->entries[0].is_dir = true;
        info->entries[0].is_root = true;
        info->entries[0].name = strdup("");
        info->entries[0].parent_idx = 0;
        info->entries[0].next_idx = count + 1;
        
        // Parse each file
        pos = files_start + 1;
        int idx = 1; // Start from 1 (root is 0)
        while (*pos && *pos != ']' && idx <= count) {
            const char* obj_start = strchr(pos, '{');
            const char* obj_end = strchr(obj_start, '}');
            if (!obj_start || !obj_end) break;
            
            size_t obj_len = obj_end - obj_start + 1;
            char* obj = malloc(obj_len + 1);
            memcpy(obj, obj_start, obj_len);
            obj[obj_len] = '\0';
            
            char* path = json_get_string(obj, "path");
            if (path) {
                info->entries[idx].path = path;
                // Extract filename from path
                char* name = strrchr(path, '/');
                if (name) name++;
                else name = path;
                info->entries[idx].name = strdup(name);
            }
            
            info->entries[idx].content_id = json_get_uint16(obj, "content_id");
            info->entries[idx].file_offset = json_get_uint32(obj, "offset");
            info->entries[idx].file_size = json_get_uint32(obj, "size");
            info->entries[idx].flags = json_get_uint16(obj, "flags");
            info->entries[idx].is_dir = json_get_bool(obj, "is_dir");
            info->entries[idx].entry_offset = idx;
            
            free(obj);
            idx++;
            pos = obj_end + 1;
            while (*pos && (*pos == ' ' || *pos == '\t' || *pos == '\n' || *pos == ',')) pos++;
        }
    }
    
    
    free(json);
    return 0;
}

// ============================================================================
// TMD/Ticket/Cert Generation
// ============================================================================

int generate_tmd(const pack_title_info* info, const char* output_path) {
    FILE* f = fopen_utf8(output_path, "wb");
    if (!f) return -1;
    
    // TMD structure from NUSPacker:
    // - Static part: 0x204 bytes (signature + header + SHA2)
    // - ContentInfos: 64 * 0x24 = 0x900 bytes
    // - Contents: N * 0x30 bytes
    uint32_t tmd_size = 0x204 + 0x900 + info->content_count * 0x30;
    uint8_t* tmd = calloc(tmd_size, 1);
    if (!tmd) { fclose(f); return -1; }
    
    uint32_t offset = 0;
    
    // === Signature (0x104 bytes) ===
    setbe32(tmd + offset, 0x00010004);  // signatureType
    offset += 0x104;  // 4 + 0x100 (signature) + 0x3C (padding) = 0x140
    // But we need to account for the padding properly
    offset = 0x140;  // Reset to start of body
    
    // === TMD Body ===
    // issuer (0x40 bytes)
    memcpy(tmd + offset, "Root-CA00000003-CP0000000b", 27);
    offset += 0x40;
    
    // version (1 byte)
    tmd[offset++] = 0x01;
    // CACRLVersion (1 byte)
    tmd[offset++] = 0x00;
    // signerCRLVersion (1 byte)
    tmd[offset++] = 0x00;
    // padding1 (1 byte)
    tmd[offset++] = 0x00;
    
    // systemVersion (8 bytes)
    setbe64(tmd + offset, 0x000500101000400AULL);
    offset += 8;
    
    // titleID (8 bytes)
    setbe64(tmd + offset, info->title_id);
    offset += 8;
    
    // titleType (4 bytes)
    setbe32(tmd + offset, 0x000100);
    offset += 4;
    
    // groupID (2 bytes)
    setbe16(tmd + offset, info->group_id);
    offset += 2;
    
    // appType (4 bytes)
    setbe32(tmd + offset, 0x80000000);
    offset += 4;
    
    // random1 (4 bytes)
    offset += 4;
    // random2 (4 bytes)
    offset += 4;
    // reserved (50 bytes)
    offset += 50;
    // accessRights (4 bytes)
    offset += 4;
    
    // titleVersion (2 bytes)
    setbe16(tmd + offset, info->version);
    offset += 2;
    
    // contentCount (2 bytes)
    setbe16(tmd + offset, info->content_count);
    offset += 2;
    
    // bootIndex (2 bytes)
    setbe16(tmd + offset, 0);
    offset += 2;
    
    // padding3 (2 bytes)
    offset += 2;
    
    // SHA2 (0x20 bytes) - hash of ContentInfos
    offset += 0x20;
    
    // Now offset should be 0x204
    
    // === ContentInfos (64 * 0x24 = 0x900 bytes) ===
    // First ContentInfo: indexOffset=0, commandCount=content_count
    setbe16(tmd + offset, 0);  // indexOffset
    setbe16(tmd + offset + 2, info->content_count);  // commandCount
    // SHA2Hash would be hash of Contents data (skip for now)
    offset += 0x900;  // All 64 ContentInfos
    
    // === Contents (N * 0x30 bytes) ===
    for (uint32_t i = 0; i < info->content_count; i++) {
        // ID (4 bytes)
        setbe32(tmd + offset, info->contents[i].id);
        // index (2 bytes)
        setbe16(tmd + offset + 4, info->contents[i].index);
        // type (2 bytes)
        setbe16(tmd + offset + 6, info->contents[i].type);
        // encryptedFileSize (8 bytes)
        setbe64(tmd + offset + 8, info->contents[i].size);
        // hash (0x20 bytes)
        memcpy(tmd + offset + 16, info->contents[i].hash, 20);
        offset += 0x30;
    }
    
    fwrite(tmd, 1, tmd_size, f);
    free(tmd);
    fclose(f);
    return 0;
}
int generate_ticket(const pack_title_info* info, const char* output_path) {
    FILE* f = fopen_utf8(output_path, "wb");
    if (!f) return -1;
    
    // Ticket structure from NUSPacker: 0x350 bytes
    // Following the exact structure from Ticket.java:
    // - 4 bytes: signature type (00010004)
    // - 0x100 bytes: random signature data
    // - 0x3C bytes: padding
    // - 32 bytes: issuer + padding (hex: 526F6F742D434130303030303030332D58533030303030303063000000000000)
    // - 0x5C bytes: padding  
    // - 3 bytes: "010000"
    // - 16 bytes: encrypted title key
    // - 3 bytes: "000005"
    // - 6 bytes: random data
    // - 4 bytes: padding
    // - 8 bytes: title ID
    // - ... more
    
    uint8_t ticket[0x350] = {0};
    uint8_t* p = ticket;
    
    // Signature type
    setbe32(p, 0x00010004);
    p += 4;
    
    // Random signature data (0x100 bytes) - use zeros for simplicity
    p += 0x100;
    
    // Padding (0x3C bytes) - already zeros
    p += 0x3C;
    
    // Issuer (32 bytes): "Root-CA00000003-XS0000000c" + 5 zero bytes
    memcpy(p, "Root-CA00000003-XS0000000c", 27);
    // Remaining 5 bytes already zeros
    p += 32;
    
    // Padding (0x5C bytes) - already zeros
    p += 0x5C;
    
    // "010000" (3 bytes)
    p[0] = 0x01; p[1] = 0x00; p[2] = 0x00;
    p += 3;
    
    // Encrypted title key (16 bytes) at offset 0x1BF
    if (info->has_encrypted_key) {
        memcpy(p, info->encrypted_key, 16);
    } else {
        memset(p, 0x37, 16);
    }
    p += 16;
    
    // "000005" (3 bytes)
    p[0] = 0x00; p[1] = 0x00; p[2] = 0x05;
    p += 3;
    
    // Random data (6 bytes) - use zeros
    p += 6;
    
    // Padding (4 bytes) - already zeros
    p += 4;
    
    // Title ID (8 bytes)
    setbe64(p, info->title_id);
    p += 8;
    
    // Remaining data from Java code
    memcpy(p, "\x00\x00\x00\x11\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05", 16);
    p += 16;
    
    // Padding (0xB0 bytes)
    p += 0xB0;
    
    // Footer from Java code
    memcpy(p, "\x00\x01\x00\x14\x00\x00\x00\xAC\x00\x00\x00\x14\x00\x01\x00\x14"
              "\x00\x00\x00\x00\x00\x00\x00\x28\x00\x00\x00\x01\x00\x00\x00\x84"
              "\x00\x00\x00\x84\x00\x03\x00\x00\x00\x00\x00\x00\xFF\xFF\xFF\x01", 48);
    
    fwrite(ticket, 1, sizeof(ticket), f);
    fclose(f);
    return 0;
}

int generate_cert(const char* output_path) {
    // Certificate is a signed structure
    // For simplicity, just create an empty cert file
    // Real implementation would need proper certificate chain
    
    FILE* f = fopen_utf8(output_path, "wb");
    if (!f) return -1;
    
    // Minimal cert placeholder
    uint8_t cert[0x400] = {0};
    fwrite(cert, 1, sizeof(cert), f);
    fclose(f);
    return 0;
}

// ============================================================================
// Main Pack Function
// ============================================================================

int pack_title(const char* input_dir, const char* output_dir, const char* title_key_hex, const char* common_key_hex) {
    pack_title_info info;
    char meta_path[1024];
    int ret = -1;
    
    // Check for metadata file
    snprintf(meta_path, sizeof(meta_path), "%s%s.title_meta.json", 
             input_dir, PATH_SEP_STR);
    
    if (!is_file(meta_path)) {
        fprintf(stderr, "ERROR: No metadata file found: %s\n", meta_path);
        fprintf(stderr, "Run cdecrypt first to extract and generate metadata.\n");
        return -1;
    }
    
    printf("Parsing metadata...\n");
    if (parse_metadata_json(meta_path, &info) != 0) {
        return -1;
    }
    
    printf("Title ID: %016" PRIX64 "\n", info.title_id);
    printf("Contents: %u\n", info.content_count);
    printf("Files: %u\n", info.entry_count);
    
    // Scan actual file sizes and recalculate offsets
    // This allows users to modify files and have sizes automatically adjusted
    printf("Scanning actual file sizes...\n");
    char input_path[1024];
    for (uint32_t i = 0; i < info.content_count; i++) {
        uint64_t cur_offset = 0;
        
        for (uint32_t j = 0; j < info.entry_count; j++) {
            pack_fst_entry* entry = &info.entries[j];
            
            if (entry->content_id != info.contents[i].id || entry->is_dir) continue;
            
            // Get actual file size
            snprintf(input_path, sizeof(input_path), "%s%s%s", 
                     input_dir, PATH_SEP_STR, entry->path);
            
            FILE* f = fopen_utf8(input_path, "rb");
            if (f) {
                fseek(f, 0, SEEK_END);
                uint32_t actual_size = (uint32_t)ftell(f);
                fclose(f);
                
                if (actual_size != entry->file_size) {
                    printf("  %s: size changed %u -> %u bytes\n", 
                           entry->path, entry->file_size, actual_size);
                    entry->file_size = actual_size;
                }
            }
            
            // Recalculate offset (aligned to 0x20 as per NUSPacker)
            entry->file_offset = (uint32_t)cur_offset;
            cur_offset += (entry->file_size + 0x1F) & ~0x1F;  // Align to 0x20
        }
        
        // Update content size
        if (cur_offset > 0) {
            info.contents[i].size = (uint32_t)cur_offset;
        }
    }
    
    // Scan for new files not in metadata
    printf("Scanning for new files...\n");
    
    // First, recursively scan directory for all files
    // Disable format-truncation warning as we use sufficiently large buffers
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
    char scan_path[4096];
    
    // Use a simple stack-based directory traversal
    typedef struct {
        char path[4096];
    } dir_stack_entry;
    
    dir_stack_entry* dir_stack = malloc(100 * sizeof(dir_stack_entry));
    int stack_top = 0;
    strcpy(dir_stack[stack_top++].path, ".");
    
    while (stack_top > 0) {
        char current_rel[4096];
        strcpy(current_rel, dir_stack[--stack_top].path);
        
        snprintf(scan_path, sizeof(scan_path), "%s%s%s", input_dir, PATH_SEP_STR, current_rel);
        
        DIR* dir = opendir(scan_path);
        if (!dir) continue;
        
        struct dirent* entry;
        while ((entry = readdir(dir)) != NULL) {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
            if (strcmp(entry->d_name, ".title_meta.json") == 0) continue;
            
            char entry_rel_path[4096];
            if (strcmp(current_rel, ".") == 0) {
                snprintf(entry_rel_path, sizeof(entry_rel_path), "%s", entry->d_name);
            } else {
                snprintf(entry_rel_path, sizeof(entry_rel_path), "%s%s%s", 
                         current_rel, PATH_SEP_STR, entry->d_name);
            }
            
            char entry_full_path[4096];
            snprintf(entry_full_path, sizeof(entry_full_path), "%s%s%s", 
                     input_dir, PATH_SEP_STR, entry_rel_path);
            
            struct stat st;
            if (stat(entry_full_path, &st) != 0) continue;
            
            if (S_ISDIR(st.st_mode)) {
                // Add to stack for recursion
                if (stack_top < 100) {
                    strcpy(dir_stack[stack_top++].path, entry_rel_path);
                }
            } else if (S_ISREG(st.st_mode)) {
                // Check if file is already in entries
                bool found = false;
                for (uint32_t i = 0; i < info.entry_count; i++) {
                    if (info.entries[i].path && strcmp(info.entries[i].path, entry_rel_path) == 0) {
                        found = true;
                        break;
                    }
                }
                
                if (!found) {
                    // New file found
                    printf("  New file: %s (%ld bytes)\n", entry_rel_path, st.st_size);
                    
                    // Find content for this file based on extension first, then directory
                    uint16_t content_id = 0xFFFF;
                    
                    // Get file extension
                    char* ext = strrchr(entry->d_name, '.');
                    if (ext) ext++;  // Skip the dot
                    
                    // First, try to find a file with same extension in same or similar directory
                    for (uint32_t i = 0; i < info.entry_count; i++) {
                        if (info.entries[i].is_dir || !info.entries[i].path) continue;
                        
                        char* entry_ext = strrchr(info.entries[i].name, '.');
                        if (entry_ext) entry_ext++;
                        
                        // Match by extension first (e.g., .jpg files go together)
                        if (ext && entry_ext && strcasecmp(ext, entry_ext) == 0) {
                            content_id = info.entries[i].content_id;
                            printf("    -> Matched by extension .%s\n", ext);
                            break;
                        }
                    }
                    
                    // If no extension match, try directory match
                    if (content_id == 0xFFFF) {
                        char* last_slash = strrchr(entry_rel_path, '/');
                        char dir_path[256] = "";
                        
                        if (last_slash) {
                            strncpy(dir_path, entry_rel_path, last_slash - entry_rel_path);
                            dir_path[last_slash - entry_rel_path] = '\0';
                        }
                        
                        // Find a file in the same directory
                        for (uint32_t i = 0; i < info.entry_count; i++) {
                            if (info.entries[i].is_dir || !info.entries[i].path) continue;
                            char* entry_last_slash = strrchr(info.entries[i].path, '/');
                            if (entry_last_slash) {
                                char entry_dir[256];
                                strncpy(entry_dir, info.entries[i].path, entry_last_slash - info.entries[i].path);
                                entry_dir[entry_last_slash - info.entries[i].path] = '\0';
                                if (strcmp(entry_dir, dir_path) == 0) {
                                    content_id = info.entries[i].content_id;
                                    printf("    -> Matched by directory %s\n", dir_path);
                                    break;
                                }
                            } else if (dir_path[0] == '\0') {
                                // Root directory
                                content_id = info.entries[i].content_id;
                                break;
                            }
                        }
                    }
                    
                    if (content_id != 0xFFFF) {
                        // Add new entry
                        uint32_t new_idx = info.entry_count;
                        info.entries = realloc(info.entries, (new_idx + 1) * sizeof(pack_fst_entry));
                        memset(&info.entries[new_idx], 0, sizeof(pack_fst_entry));
                        info.entries[new_idx].path = strdup(entry_rel_path);
                        info.entries[new_idx].name = strdup(entry->d_name);
                        info.entries[new_idx].file_size = (uint32_t)st.st_size;
                        info.entries[new_idx].content_id = content_id;
                        info.entries[new_idx].is_dir = false;
                        info.entries[new_idx].file_offset = 0;
                        
                        // Copy flags from sibling files in same content
                        for (uint32_t i = 0; i < new_idx; i++) {
                            if (info.entries[i].content_id == content_id) {
                                info.entries[new_idx].flags = info.entries[i].flags;
                                break;
                            }
                        }
                        
                        info.entry_count++;
                        printf("    -> Assigned to content %04X\n", content_id);
                    } else {
                        printf("    -> Warning: Could not determine content for this file, skipping\n");
                    }
                }
            }
        }
        closedir(dir);
    }
    free(dir_stack);
    
    // Recalculate offsets after adding new files
    printf("Recalculating offsets...\n");
    for (uint32_t i = 0; i < info.content_count; i++) {
        uint64_t cur_offset = 0;
        
        for (uint32_t j = 0; j < info.entry_count; j++) {
            pack_fst_entry* entry = &info.entries[j];
            
            if (entry->content_id != info.contents[i].id || entry->is_dir) continue;
            
            entry->file_offset = (uint32_t)cur_offset;
            cur_offset += (entry->file_size + 0x1F) & ~0x1F;
        }
        
        if (cur_offset > 0) {
            info.contents[i].size = (uint32_t)cur_offset;
        }
    }
    
    // Update root entry's next_idx to reflect total entry count
    info.entries[0].next_idx = info.entry_count;
    
    // Title key is required for encryption
    uint8_t title_key[16];
    if (title_key_hex) {
        // Parse hex string (32 characters = 16 bytes)
        if (strlen(title_key_hex) != 32) {
            fprintf(stderr, "ERROR: Title key must be 32 hex characters\n");
            return -1;
        }
        for (int i = 0; i < 16; i++) {
            char byte[3] = {title_key_hex[i*2], title_key_hex[i*2+1], 0};
            title_key[i] = (uint8_t)strtol(byte, NULL, 16);
        }
        printf("Using provided title key: %s\n", title_key_hex);
    } else {
        fprintf(stderr, "ERROR: Title key is required for packing. Use -k <title_key>\n");
        return -1;
    }
    
    // Common key is used to encrypt title key in ticket
    uint8_t common_key[16];
    if (common_key_hex) {
        if (strlen(common_key_hex) != 32) {
            fprintf(stderr, "ERROR: Common key must be 32 hex characters\n");
            return -1;
        }
        for (int i = 0; i < 16; i++) {
            char byte[3] = {common_key_hex[i*2], common_key_hex[i*2+1], 0};
            common_key[i] = (uint8_t)strtol(byte, NULL, 16);
        }
    } else {
        // Use default Wii U common key
        memcpy(common_key, WiiUCommonKey, 16);
    }
    
    // Store encrypted title key for ticket generation
    // Encrypt title_key with common_key using title_id as IV
    aes_context ctx;
    uint8_t iv[16] = {0};
    setbe64(iv, info.title_id);  // Big-endian title ID as IV
    aes_setkey_enc(&ctx, common_key, 128);
    aes_crypt_cbc(&ctx, AES_ENCRYPT, 16, iv, title_key, info.encrypted_key);
    info.has_encrypted_key = true;
    
    // Create output directory
    char output_dir_copy[PATH_MAX];
    strncpy(output_dir_copy, output_dir, sizeof(output_dir_copy) - 1);
    output_dir_copy[sizeof(output_dir_copy) - 1] = '\0';
    create_path(output_dir_copy);
    
    // Process each content (skip content 0 which is FST)
    for (uint32_t i = 0; i < info.content_count; i++) {
        pack_content_info* content = &info.contents[i];
        
        // Skip content 0 (FST) - it will be generated later
        if (content->index == 0) {
            printf("Skipping content %08X (FST - will be generated)\n", content->id);
            continue;
        }
        
        printf("\nPacking content %08X (type %04X)...\n", 
               content->id, content->type);
        
        if (content->hashed) {
            if (encrypt_content_hashed(input_dir, output_dir, &info, content, title_key) != 0) {
                fprintf(stderr, "ERROR: Failed to encrypt content %08X\n", content->id);
                goto cleanup;
            }
        } else {
            if (encrypt_content_simple(input_dir, output_dir, &info, content, title_key) != 0) {
                fprintf(stderr, "ERROR: Failed to encrypt content %08X\n", content->id);
                goto cleanup;
            }
        }
        
        printf("Content %08X: %u bytes\n", content->id, content->size);
    }
    
    // Generate FST (content 0)
    printf("\nGenerating FST...\n");
    uint32_t fst_size;
    uint8_t* fst_data = build_fst_data(&info, &fst_size);
    if (!fst_data) {
        fprintf(stderr, "ERROR: Failed to build FST\n");
        goto cleanup;
    }
    
    // Encrypt and write FST (as content 0)
    char fst_path[1024];
    snprintf(fst_path, sizeof(fst_path), "%s%s00000000.app", output_dir, PATH_SEP_STR);
    FILE* fst_file = fopen_utf8(fst_path, "wb");
    if (fst_file) {
        // Pad FST to 0x8000
        uint32_t padded_fst_size = (fst_size + 0x7FFF) & ~0x7FFF;
        uint8_t* padded_fst = calloc(padded_fst_size, 1);
        memcpy(padded_fst, fst_data, fst_size);
        
        // Encrypt with title key
        uint8_t iv2[16] = {0};
        uint8_t* encrypted_fst = malloc(padded_fst_size);
        aes_setkey_enc(&ctx, title_key, 128);
        aes_crypt_cbc(&ctx, AES_ENCRYPT, padded_fst_size, iv2, padded_fst, encrypted_fst);
        
        fwrite(encrypted_fst, 1, padded_fst_size, fst_file);
        fclose(fst_file);
        free(padded_fst);
        free(encrypted_fst);
    }
    free(fst_data);
    
    // Generate TMD, Ticket, Cert
    printf("Generating TMD...\n");
    char tmd_path[1024];
    snprintf(tmd_path, sizeof(tmd_path), "%s%stitle.tmd", output_dir, PATH_SEP_STR);
    generate_tmd(&info, tmd_path);
    
    printf("Generating Ticket...\n");
    char tik_path[1024];
    snprintf(tik_path, sizeof(tik_path), "%s%stitle.tik", output_dir, PATH_SEP_STR);
    generate_ticket(&info, tik_path);
    
    printf("Generating Cert...\n");
    char cert_path[1024];
    snprintf(cert_path, sizeof(cert_path), "%s%stitle.cert", output_dir, PATH_SEP_STR);
    generate_cert(cert_path);
    
    printf("\nPacking complete!\n");
    ret = 0;
    
cleanup:
    // Free allocated memory
    for (uint32_t i = 0; i < info.content_count; i++) {
        // Contents are in array, no individual free needed
    }
    free(info.contents);
    
    for (uint32_t i = 0; i < info.entry_count; i++) {
        free(info.entries[i].path);
        free(info.entries[i].name);
        free(info.entries[i].children);
    }
    free(info.entries);
    
    return ret;
}

