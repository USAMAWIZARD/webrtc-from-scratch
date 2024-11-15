#include <glib.h>
#include <gmp.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/types.h>
#include <stdbool.h>
#include <stdint.h>

#pragma once
#ifndef _ENRYPTIONH_
#define _ENRYPTIONH_

// 128 10
// 256 12
// 256 14

enum cipher_suite;
struct RTCDtlsTransport;
struct encryption_keys;
struct cipher_suite_info;

enum cipher_suite {
  TLS_RSA_WITH_AES_128_CBC_SHA = 0x2f00,
  SRTP_AES128_CM_HMAC_SHA1_80 = 0x0100
};

enum mode { CBC, CM };
enum symitric_encrypt_algo { AES };

struct AesEnryptionCtx {
  uint8_t *initial_key;
  uint8_t *mac_key;
  uint16_t mac_key_size;
  uint16_t iv_size;
  uint16_t key_size;
  uint8_t row_size;
  enum mode mode;

  uint8_t no_rounds;

  uint8_t input_text[4][4];
  uint8_t (*recordIV)[4];
  uint8_t (*IV)[4];
  uint8_t *prevoius_cipher;
  uint8_t (*roundkeys[14])[4];
};

struct dtls_ctx {
  struct DtlsEncryptionCtx *client;
  struct DtlsEncryptionCtx *server;
  uint32_t (*encrypt_func)(void *encryption_ctx, uint8_t *block_data,
                           uint16_t block_encrypt_offset,
                           uint32_t total_packet_len);
  uint32_t (*decrypt_func)(void *encryption_ctx, uint8_t *block_data,
                           uint16_t block_encrypt_offset,
                           uint32_t total_packet_len);
};

struct srtp_ctx {
  struct SrtpEncryptionCtx *client;
  struct SrtpEncryptionCtx *server;
  uint32_t (*encrypt_func)(void *encryption_ctx, uint8_t *block_data,
                           uint16_t block_encrypt_offset,
                           uint32_t total_packet_len);
  uint32_t (*decrypt_func)(void *encryption_ctx, uint8_t *block_data,
                           uint16_t block_encrypt_offset,
                           uint32_t total_packet_len);
};

struct cipher_suite_info {
  uint16_t selected_cipher_suite;
  enum symitric_encrypt_algo symitric_algo;
  enum mode mode;
  GChecksumType hmac_algo;
  gsize hmac_key_len;
  gsize hmac_len;
  gsize key_size;
  gsize iv_size;
  gsize salt_key_len;
  gsize tag_size;
};

struct encryption_keys {
  BIGNUM *master_secret;
  guchar *my_private_key;
  guchar *client_write_mac_key;
  guchar *server_write_mac_key;
  guchar *client_write_key;
  guchar *server_write_key;
  guchar *client_write_IV;
  guchar *server_write_IV;
  guchar *client_write_SRTP_salt;
  guchar *server_write_SRTP_salt;
  struct cipher_suite_info *cipher_suite_info;
};

#define MASTER_SECRET_LEN 48.0

uint16_t encrypt_rsa(guchar **encrypted_data, EVP_PKEY *pub_key, guchar *data,
                     uint16_t data_len, GChecksumType hash);

BIGNUM *calcualte_master_secret(BIGNUM *premaster_secret);

BIGNUM *get_dtls_rand_appended(BIGNUM *r1, BIGNUM *r2);

guchar *PRF(BIGNUM *secret, guchar *label, BIGNUM *seed,
            GChecksumType checksum_type, uint16_t num_bytes);

BIGNUM *generate_master_key(guchar *premaster_key, BIGNUM *seed);
gchar *generate_encryption_key_block(BIGNUM *master_secret, BIGNUM *seed,
                                     guint16 selected_cipher_suite);
bool parse_encryption_key_block(struct RTCDtlsTransport *transport,
                                gchar *key_block);

bool init_symitric_encryption(struct RTCDtlsTransport *transport);

struct AesEnryptionCtx *init_aes(struct AesEnryptionCtx **encryption_ctx,
                                 guchar *write_key, uint16_t write_key_size,
                                 guchar *write_mac_key, uint16_t mac_key_size,
                                 guchar *write_IV, enum mode mode);
bool aes_expand_key(struct AesEnryptionCtx *ctx);

void sub_bytes(uint8_t (*block)[4]);

void shift_rows(uint8_t (*block)[4]);

void mix_columns(uint8_t (*matrix)[4], uint8_t (*galois_fild)[4]);

uint32_t encrypt_aes(struct AesEnryptionCtx *ctx, uint8_t *block_data,
                     uint16_t block_encrypt_offset, uint32_t data_len);

uint32_t decrypt_aes(struct AesEnryptionCtx *ctx, uint8_t *block_data,
                     uint16_t block_decryption_offset, uint32_t data_len);

void transpose_matrix(uint8_t (*round_key)[4]);

bool init_dtls_ctx(struct dtls_ctx *dtls_ctx,
                   struct encryption_keys *encryption_keys,
                   struct cipher_suite_info *cipher_info);

bool set_cipher_suite_info(struct cipher_suite_info **pp_cipher_suite_info,
                           uint16_t selected_cipher_suite);
uint32_t decrypt_dtls(struct RTCDtlsTransport *dtls_transport, guchar **block,
                      uint32_t length);
uint32_t encrypt_dtls(struct RTCDtlsTransport *dtls_transport, guchar *block,
                      uint32_t length);
#endif // !_ENRYPTIONH_
