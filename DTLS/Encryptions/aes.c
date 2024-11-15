#include "../../Utils/utils.h"
#include "encryption.h"
#include <arpa/inet.h>
#include <glib.h>
#include <math.h>
#include <openssl/bn.h>
#include <openssl/types.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#define AES_BLOCK_SIZE 16
uint8_t s_box[16][16] = {
    {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
     0xfe, 0xd7, 0xab, 0x76},
    {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf,
     0x9c, 0xa4, 0x72, 0xc0},
    {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1,
     0x71, 0xd8, 0x31, 0x15},
    {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
     0xeb, 0x27, 0xb2, 0x75},
    {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3,
     0x29, 0xe3, 0x2f, 0x84},
    {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39,
     0x4a, 0x4c, 0x58, 0xcf},
    {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
     0x50, 0x3c, 0x9f, 0xa8},
    {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21,
     0x10, 0xff, 0xf3, 0xd2},
    {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d,
     0x64, 0x5d, 0x19, 0x73},
    {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
     0xde, 0x5e, 0x0b, 0xdb},
    {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62,
     0x91, 0x95, 0xe4, 0x79},
    {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea,
     0x65, 0x7a, 0xae, 0x08},
    {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
     0x4b, 0xbd, 0x8b, 0x8a},
    {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9,
     0x86, 0xc1, 0x1d, 0x9e},
    {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9,
     0xce, 0x55, 0x28, 0xdf},
    {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
     0xb0, 0x54, 0xbb, 0x16},
};
uint8_t inv_s_box[16][16] = {

    {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e,
     0x81, 0xf3, 0xd7, 0xfb},
    {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44,
     0xc4, 0xde, 0xe9, 0xcb},
    {0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b,
     0x42, 0xfa, 0xc3, 0x4e},
    {0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49,
     0x6d, 0x8b, 0xd1, 0x25},
    {0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc,
     0x5d, 0x65, 0xb6, 0x92},
    {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57,
     0xa7, 0x8d, 0x9d, 0x84},
    {0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05,
     0xb8, 0xb3, 0x45, 0x06},
    {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03,
     0x01, 0x13, 0x8a, 0x6b},
    {0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce,
     0xf0, 0xb4, 0xe6, 0x73},
    {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8,
     0x1c, 0x75, 0xdf, 0x6e},
    {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e,
     0xaa, 0x18, 0xbe, 0x1b},
    {0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe,
     0x78, 0xcd, 0x5a, 0xf4},
    {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59,
     0x27, 0x80, 0xec, 0x5f},
    {0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f,
     0x93, 0xc9, 0x9c, 0xef},
    {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c,
     0x83, 0x53, 0x99, 0x61},
    {0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63,
     0x55, 0x21, 0x0c, 0x7d}};

uint32_t round_constants[] = {0x00000001, 0x00000002, 0x00000004, 0x00000008,
                              0x00000010, 0x00000020, 0x00000040, 0x00000080,
                              0x0000001b, 0x00000036};

uint8_t aes_galois_fild[4][4] = {{0x02, 0x03, 0x01, 0x01},
                                 {0x01, 0x02, 0x03, 0x01},
                                 {0x01, 0x01, 0x02, 0x03},
                                 {0x03, 0x01, 0x01, 0x02}};

uint8_t inv_aes_galois_fild[4][4] = {{0x0E, 0x0B, 0x0D, 0x09},
                                     {0x09, 0x0E, 0x0B, 0x0D},
                                     {0x0D, 0x09, 0x0E, 0x0B},
                                     {0x0B, 0x0D, 0x09, 0x0E}};

uint32_t g_function(uint32_t word, uint16_t round_num);
bool aes_expand_key(struct AesEnryptionCtx *ctx) {
  uint16_t aes_key_len = ctx->key_size;
  guchar *key = ctx->initial_key;

  //
  // for (int i = 0; i < num_row; i++) {
  //   memcpy(ctx->initial_key[i], key, num_row);
  //   key += num_row;
  // }
  //
  // uint32_t round0_key[num_row];
  // for (int i = 0; i < num_row; i++) {
  //   for (int j = 0; j < num_row; j++) {
  //     round0_key[i] += ctx->initial_key[i][j];
  //   }
  // }

  // key expansion

  uint16_t expand_key_len = (aes_key_len * ctx->no_rounds) + aes_key_len;

  uint32_t expanded_keys[expand_key_len];

  memcpy(expanded_keys, key, aes_key_len);

  uint8_t num_row = ctx->row_size;

  g_debug("aes key len %d expand key up to %d \n", aes_key_len, expand_key_len);

  for (int i = num_row; i <= expand_key_len; i++) {
    uint16_t round_num = (((int)floor(i / 4)) - 1);

    if ((i % num_row) == 0) {
      expanded_keys[i] = expanded_keys[i - num_row] ^
                         g_function(expanded_keys[i - 1], round_num % 10);
      continue;
    }
    expanded_keys[i] = expanded_keys[i - num_row] ^ expanded_keys[i - 1];
  }

  for (int i = 0; i <= ctx->no_rounds; i++) { // one extran key
    uint8_t(*round_key)[4] = malloc(aes_key_len);
    memcpy(round_key, &(expanded_keys[i * 4]), aes_key_len);
    transpose_matrix(round_key);
    print_aes_matrix(round_key, 4);
    ctx->roundkeys[i] = round_key;
  }

  return true;
}

void transpose_matrix(uint8_t (*round_key)[4]) {
  uint8_t temp;
  for (int i = 0; i < 4; i++) {
    for (int j = i + 1; j < 4; j++) {
      temp = round_key[i][j];
      round_key[i][j] = round_key[j][i];
      round_key[j][i] = temp;
    }
  }
}
uint32_t g_func_sub_byte(uint32_t word) {
  uint8_t first_byte;
  uint32_t mask = 0xFFFFFFFF;

  for (int i = 0; i <= 3; i++) {
    uint8_t byte = ((word & mask) >> (i * 8));

    uint8_t upper4bit = (byte & 0xF0) >> 4;
    uint8_t lower4bit = (byte & 0x0F);

    uint32_t replace_byte =
        (((uint32_t)(s_box[upper4bit][lower4bit])) << (i * 8));

    word = replace_byte | (word & (~((uint32_t)0xFF << (i * 8))));
    // some crazy bit wise shit that I will
    // not remember
  }
  return word;
}

uint32_t g_function(uint32_t word, uint16_t round_num) {
  uint32_t first_byte = (word & 0x000000FF) << (3 * 8);
  // g_debug("\n word %x first bypte %x \n", word, first_byte);
  word = word >> 8;
  word = (word & 0x00FFFFFF) | first_byte;

  // g_debug("rotated %x ", word);

  word = g_func_sub_byte(word);

  // g_debug("subutityed %x %d ", word, round_num);

  return word ^ round_constants[round_num];
}

void sub_bytes(uint8_t (*block)[4]) {
  g_debug("before sub byte\n");
  print_aes_matrix(block, 4);

  for (int i = 0; i < 4; i++) {
    for (int j = 0; j < 4; j++) {

      uint16_t byte = block[i][j];
      uint8_t upper4bit = (byte & 0xF0) >> 4;
      uint8_t lower4bit = (byte & 0x0F);

      block[i][j] = s_box[upper4bit][lower4bit];
    }
  }
  g_debug("after sub byte\n");
  print_aes_matrix(block, 4);
}

void inv_sub_bytes(uint8_t (*block)[4]) {
  g_debug("before sub byte\n");
  print_aes_matrix(block, 4);

  for (int i = 0; i < 4; i++) {
    for (int j = 0; j < 4; j++) {

      uint16_t byte = block[i][j];
      uint8_t upper4bit = (byte & 0xF0) >> 4;
      uint8_t lower4bit = (byte & 0x0F);

      block[i][j] = inv_s_box[upper4bit][lower4bit];
    }
  }
  g_debug("after sub byte\n");
  print_aes_matrix(block, 4);
}

uint8_t gf_mult(uint8_t a, uint8_t b) {
  uint8_t p = 0;
  uint8_t hi_bit_set;
  for (int i = 0; i < 8; i++) {
    if (b & 1) {
      p ^= a;
    }
    hi_bit_set = a & 0x80;
    a <<= 1;
    if (hi_bit_set) {
      a ^= 0x1b; // modulo by irreducible polynomial 0x11b
    }
    b >>= 1;
  }
  return p;
}
void shift_rows(uint8_t (*block)[4]) {

  g_debug("before shift row\n");
  print_aes_matrix(block, 4);
  for (int i = 1; i < 4; i++) {
    uint32_t block32 = (*(uint32_t(*)[4])block)[i];

    uint32_t right_shifted = (block32) << (32 - (i * 8));
    uint32_t left_shifted = (block32) >> ((i * 8));

    (*(uint32_t(*)[4])block)[i] = right_shifted | left_shifted;
  }

  g_debug("after shift row\n");
  print_aes_matrix(block, 4);
}
void inv_shift_rows(uint8_t (*block)[4]) {

  g_debug("before shift row\n");
  print_aes_matrix(block, 4);
  for (int i = 1; i < 4; i++) {
    uint32_t block32 = (*(uint32_t(*)[4])block)[i];

    uint32_t right_shifted = (block32) >> (32 - (i * 8));
    uint32_t left_shifted = (block32) << ((i * 8));

    (*(uint32_t(*)[4])block)[i] = right_shifted | left_shifted;
  }

  g_debug("after shift row\n");
  print_aes_matrix(block, 4);
}
void mix_columns(uint8_t (*matrix)[4], uint8_t (*galois_fild)[4]) {
  g_debug("befroe mix columns\n");
  uint8_t matrix_sum[4][4] = {0};

  print_aes_matrix(matrix, 4);

  print_aes_matrix(aes_galois_fild, 4);

  for (int k = 0; k < 4; k++) {
    for (int i = 0; i < 4; i++) {
      for (int j = 0; j < 4; j++) {
        uint8_t mul = gf_mult(galois_fild[k][j], matrix[j][i]);
        matrix_sum[k][i] = matrix_sum[k][i] ^ mul;
        // g_debug(" %d %d  %d  %d    \[ %d \] \[ %d \] = %x   \[ %d \] "
        //        "\[ %x \] = %x  sum = %x   %d %d\n",
        //        k, j, j, i, k, j, aes_galois_fild[k][j], j, i, matrix[j][i],
        //        matrix_sum[k][i], k, i);
      }
    }
  }
  for (int i = 0; i < 4; i++) {
    for (int j = 0; j < 4; j++) {
      matrix[i][j] = matrix_sum[i][j];
    }
  }

  g_debug("after mix columns\n");
  print_aes_matrix(matrix, 4);
}
void add_round_key(uint8_t (*roundkey)[4], uint8_t (*block)[4]) {

  g_debug("add round key before: \n");

  g_debug("round key:\n");
  print_aes_matrix(roundkey, 4);

  g_debug("block :\n");
  print_aes_matrix(block, 4);

  for (int i = 0; i < 4; i++) {
    for (int j = 0; j < 4; j++) {
      block[i][j] = block[i][j] ^ roundkey[i][j];
    }
  }

  g_debug("after round key :\n");
  print_aes_matrix(block, 4);
}

void add_vector(uint8_t (*block)[4], uint8_t (*iv)[4]) {
  add_round_key(iv, block);
}
void add_aes_padding(uint8_t *block, uint16_t data_len, uint8_t padding_size,
                     enum mode mode) {
  block = block + data_len;

  for (int i = 0; i < padding_size; i++) {
    if (mode == CBC)
      block[i] = padding_size - 1;
    else if (mode == CM) {
      printf("why herel");
      block[i] = 0;
    }
  }
}

void aes_enc_opp(struct AesEnryptionCtx *ctx, uint8_t (*block)[4]) {

  add_round_key(ctx->roundkeys[0], block);

  for (int i = 1; i <= ctx->no_rounds; i++) {
    g_debug("round num :%d", i);
    sub_bytes(block);
    shift_rows(block);

    if (ctx->no_rounds != i)
      mix_columns(block, aes_galois_fild);

    add_round_key(ctx->roundkeys[i], block);
  }
}

uint32_t encrypt_aes(struct AesEnryptionCtx *ctx, uint8_t *block_data,
                     uint16_t block_encrypt_offset, uint32_t total_packet_len) {

  g_debug("string encryption prooces\n");

  uint16_t block_len = total_packet_len - block_encrypt_offset;
  uint8_t padding_size = AES_BLOCK_SIZE - (block_len % AES_BLOCK_SIZE);

  if (ctx->mode == CM && padding_size == AES_BLOCK_SIZE) {
    padding_size = 0;
  }

  uint16_t to_encypt_len = block_len + padding_size;

  uint8_t(*block)[4] = (block_data) + block_encrypt_offset;
  uint32_t data_encrytion_itration = (to_encypt_len) / AES_BLOCK_SIZE;

  add_aes_padding((uint8_t *)block, block_len, padding_size, ctx->mode);

  memcpy(ctx->recordIV, ctx->IV, AES_BLOCK_SIZE);

  transpose_matrix(ctx->IV);

  uint8_t counter[16];
  for (int j = 0; j < data_encrytion_itration; j++) {

    g_debug("block\n");
    print_hex(block, 16);
    g_debug("IV\n");
    print_hex(ctx->IV, 16);
    transpose_matrix(block);

    if (ctx->mode == CBC) {
      add_vector(block, ctx->IV);
      aes_enc_opp(ctx, block);
      ctx->IV = block;
    }

    if (ctx->mode == CM) {
      memcpy(counter, ctx->IV, AES_BLOCK_SIZE);
      aes_enc_opp(ctx, counter);
      add_vector(block, counter);
      increment_counter(ctx->IV);
    }

    block = block + 4;
  }

  block = (block_data) + block_encrypt_offset;

  for (int i = 0; i < data_encrytion_itration; i++) {
    transpose_matrix(block);
    block = block + 4;
  }

  if (ctx->mode == CBC)
    get_random_string((gchar **)&ctx->IV, AES_BLOCK_SIZE, 1);

  return total_packet_len + padding_size;
}
void aes_dec_opp(struct AesEnryptionCtx *ctx, uint8_t (*block)[4]) {

  add_round_key(ctx->roundkeys[ctx->no_rounds], block);

  for (int i = ctx->no_rounds - 1; i >= 0; i--) {
    g_debug("round num :%d", i);
    inv_shift_rows(block);
    inv_sub_bytes(block);

    add_round_key(ctx->roundkeys[i], block);

    if (i != 0)
      mix_columns(block, inv_aes_galois_fild);
  }
}
uint32_t decrypt_aes(struct AesEnryptionCtx *ctx, uint8_t *block_data,
                     uint16_t block_decryption_offset, uint32_t data_len) {

  uint8_t(*block)[4] = block_data + block_decryption_offset;

  if (data_len % 16 != 0)
    g_error("block len should be in multiple of 16 data len is %d", data_len);
  uint32_t data_dencrytion_itration = (data_len) / AES_BLOCK_SIZE;

  transpose_matrix(ctx->IV);

  uint8_t counter[16];
  if (ctx->mode == CBC) {
    block = block + ((data_dencrytion_itration - 1) * 4);
    transpose_matrix(block); // startiing from last block to avoid mem copy
    for (int i = 0; i < data_dencrytion_itration; i++) {
      transpose_matrix(block - 4);
      aes_dec_opp(ctx, block);
      add_vector(block, block - 4); // passing previous block as iv
      block = block - 4;
    }
  }

  if (ctx->mode == CM)
    for (int i = 0; i < data_dencrytion_itration; i++) {
      transpose_matrix(block);
      memcpy(counter, ctx->IV, AES_BLOCK_SIZE);
      aes_enc_opp(ctx, counter);
      add_vector(block, counter);
      increment_counter(ctx->IV);
      block = block + 4;
    }

  block = (block_data) + block_decryption_offset;

  for (int i = 0; i < data_dencrytion_itration; i++) {
    transpose_matrix(block);
    block = block + 4;
  }

  return data_len;
}

struct AesEnryptionCtx *init_aes(struct AesEnryptionCtx **encryption_ctx,
                                 guchar *write_key, uint16_t write_key_size,
                                 guchar *write_mac_key, uint16_t mac_key_size,
                                 guchar *write_IV, enum mode mode) {

  struct AesEnryptionCtx *aes_encryption_ctx =
      calloc(1, sizeof(struct AesEnryptionCtx));
  aes_encryption_ctx->key_size = write_key_size;

  if (aes_encryption_ctx->key_size == AES_BLOCK_SIZE) {
    aes_encryption_ctx->no_rounds = 10;
  } else {
    printf("key size not equels %d", aes_encryption_ctx->key_size);
    return false;
  }

  aes_encryption_ctx->mode = mode;
  aes_encryption_ctx->initial_key = write_key;

  aes_encryption_ctx->IV = g_memdup(write_IV, 16);

  aes_encryption_ctx->mac_key = write_mac_key;

  aes_encryption_ctx->row_size =
      (uint8_t)((float)aes_encryption_ctx->key_size / 4.0);

  aes_encryption_ctx->mac_key_size = mac_key_size;
  aes_encryption_ctx->iv_size = AES_BLOCK_SIZE;
  aes_encryption_ctx->key_size = write_key_size;
  aes_encryption_ctx->recordIV = calloc(1, AES_BLOCK_SIZE);

  aes_expand_key(aes_encryption_ctx);
  *encryption_ctx = aes_encryption_ctx;

  return aes_encryption_ctx;
}
