#include "../DTLS/Encryptions/encryption.h"
#include "../RTP/rtp.h"
#include "../SRTP/srtp.h"
#include "../Utils/utils.h"
#include <assert.h>
#include <glib.h>
#include <netinet/in.h>
#include <openssl/bn.h>
#include <openssl/types.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
struct Rtp;

void aes_test() {

  // to encrypt
  // 14 00 00 0c 00 05 00 00 00 00 00 0c d7 7f a4 a3 2a d1 d6 bc 76 2e 0a fb
  // ------------IV
  // c8 7c bb fd 9e 77 77 05 2c 74 25 5e 4a 74 92 51
  // -------------initial key
  // 0c cb 1d 0c 65 cb 44 48 3e 45 74 b8 fb 95 3d 63
  //
  // encrypted
  // 1d 36 dd bb 3d e6 42 3f 64 f4 f3 ba 81 54 f6 b6 9a 27 b7 c8 28 41 71 b7 9e
  // b2 36 17 4f 6b 0a 88

  printf("testing AES encryption\n");
  printf("test AES Mode :CBC \n");
  guchar *key, *iv;
  uint16_t key_size =
      hexstr_to_char_2(&key, "aaf5f65767682a3c62ca89863926f24d");
  uint16_t iv_size = hexstr_to_char_2(&iv, "cc681eaa679a4d70bd2e6a1099eb6a6d");
  struct encryption_keys encryption_key;
  struct cipher_suite_info *cipher_info =
      malloc(sizeof(struct cipher_suite_info));
  cipher_info->symitric_algo = AES;
  cipher_info->mode = CBC;

  encryption_key.client_write_key = key;
  encryption_key.client_write_IV = iv;
  encryption_key.client_write_mac_key = iv;

  cipher_info->key_size = key_size;
  cipher_info->iv_size = iv_size;
  cipher_info->hmac_key_len = 14;

  encryption_key.server_write_IV = key;
  encryption_key.server_write_key = iv;
  encryption_key.server_write_mac_key = iv;

  union symmetric_encrypt symmetric_encrypt;
  init_client_server_encryption_ctx(&symmetric_encrypt, &encryption_key,
                                    cipher_info);

  struct aes_ctx *ctx = symmetric_encrypt.aes;
  uint8_t *block_hex = "1400000c000500000000000c4366e450f4d5828d2e5341a6";
  uint8_t *block;

  uint32_t len = hexstr_to_char_2(&block, block_hex);
  block = realloc(block, len + 300);

  len = encrypt_aes(ctx->client, block, 0, len);

  uint8_t *encrypted_bloc = block;
  printf("after encryption \n");

  print_hex(encrypted_bloc, len);

  guchar *bin_test_encrypted;
  hexstr_to_char_2(
      &bin_test_encrypted,
      "07a240b00d520ea32d22e8ace7c55f9085f7709ccb816b308b6be928201d669f");

  assert(memcmp(encrypted_bloc, bin_test_encrypted, len) == 0);
  printf("encryption with AES CBC TEST successfull \n");

  /////
  printf("Test AES Mode : CM");
  len = hexstr_to_char_2(&ctx->client->IV, "3511c3d9d5fc86619febd91467380000");
  block_hex = "1400000c000500000000000c4366e450f4d5828d2e5341a6";
  ctx->client->mode = CM;

  len = hexstr_to_char_2(&block, block_hex);

  len = encrypt_aes(ctx->client, block, 0, len);

  encrypted_bloc = block;
  printf("after encryption %d\n", len);

  print_hex(encrypted_bloc, len);

  hexstr_to_char_2(&bin_test_encrypted, "B7E1D5643D675A6319D0829BB9B399D6");

  assert(memcmp(encrypted_bloc, bin_test_encrypted, len) == 0);
  printf("encryption with AES CM TEST successfull ");
}

void prf_test() {

  printf("starting prf test \n");
  BIGNUM *secret = BN_new();

  BIGNUM *client_hello = BN_new();
  BIGNUM *server_hello = BN_new();

  BN_hex2bn(&secret, "FEFD7D4F93402EAC6C6D875E9A8EE8B8CC9CDCBC03D2E661CC75214B7"
                     "9F1C938A20215621987912ED841E68B770D3427");
  BN_hex2bn(&client_hello,
            "34323532313133382d313163362d343132612d386531382d3835346361616134");
  BN_hex2bn(&server_hello,
            "6ba317d2c22dbc6310c03f82d657002658823f15d9923eb7aae0dd5f7acca2d8");

  guchar *master_secret =
      PRF(secret, "master secret",
          get_dtls_rand_appended(client_hello, server_hello), G_CHECKSUM_SHA256,
          48);

  guchar *expected;
  hexstr_to_char_2(&expected,
                   "29273fd9c595b788a2c3abfb8e172ba0c4430859083820bb50fd77c4a"
                   "b0cd290f10219ac5627d788d3c1af2885b03262b11a");
  assert(memcmp(master_secret, expected, 48) == 0);
  printf("prf test success full\n");
  //  29273fd9c595b788a2c3abfb8e172ba0c4430859083820bb50fd77c4ab0cd290
}

void key_generate_keystream(guchar *counter) {}
void test_srtp_iv() {
  printf("testing srtp iv generateiton \n");

  guchar iv[16];
  uint64_t ssrc = 0xdeadbeef;
  gchar *salt_key = "9e94cabcc69ccae5b2f7da076b1b";
  guchar *salt_key_bin;
  uint32_t key_len = hexstr_to_char_2(&salt_key_bin, salt_key);

  uint64_t packet_index = 17767;
  compute_srtp_iv(iv, salt_key_bin, key_len, &ssrc, (guchar *)&packet_index);

  print_hex(iv, 16);

  guchar *expected;
  hexstr_to_char_2(&expected, "9e94cabc1831740ab2f7da072e7c0000");
  memcmp(iv, expected, 16);

  printf("iv derivation test successful");
}

void test_srtp_key_derivation() {

  guchar *master_key;
  hexstr_to_char_2(&master_key, "E1F97A0D3E018BE0D64FA32C06DE4139");

  guchar *master_salt;
  hexstr_to_char_2(&master_salt, "0EC675AD498AFEEBB6960B3AABE6");

  struct SrtpEncryptionCtx *srtp_encryption_ctx =
      malloc(sizeof(struct SrtpEncryptionCtx));
  srtp_encryption_ctx->roc = 0;
  srtp_encryption_ctx->kdr = 0;
  srtp_encryption_ctx->master_salt_key = master_salt;
  srtp_encryption_ctx->master_write_key = master_key;

  struct cipher_suite_info *cipher_info =
      malloc(sizeof(struct cipher_suite_info));

  cipher_info->key_size = 16;
  cipher_info->salt_key_len = 14;
  cipher_info->hmac_key_len = 20;
  cipher_info->hmac_len = 16;

  srtp_key_derivation(srtp_encryption_ctx, cipher_info);

  guchar *expected;
  hexstr_to_char_2(&expected, "C61E7A93744F39EE10734AFE3FF7A087");
  assert(memcmp(srtp_encryption_ctx->k_e, expected, cipher_info->key_size) ==
         0);
  free(expected);

  hexstr_to_char_2(&expected, "30CBBC08863D8C85D49DB34A9AE17AC6");
  print_hex(srtp_encryption_ctx->k_s, 16);
  assert(memcmp(srtp_encryption_ctx->k_s, expected,
                cipher_info->salt_key_len) == 0);
  free(expected);

  hexstr_to_char_2(
      &expected,
      "CEBE321F6FF7716B6FD4AB49AF256A156D38BAA48F0A0ACF3C34E2359E6CDBCE");

  print_hex(srtp_encryption_ctx->k_a, cipher_info->hmac_key_len);
  assert(memcmp(srtp_encryption_ctx->k_a, expected,
                cipher_info->hmac_key_len) == 0);
  printf("derived k_a\n");
  print_hex(srtp_encryption_ctx->k_a,
            srtp_encryption_ctx->cipher_suite_info->hmac_key_len);
  free(expected);

  printf("srtp key generation successfull\n");
}
void test_srtp_encryption() {

  struct SrtpEncryptionCtx *srtp_encryption_ctx =
      malloc(sizeof(struct SrtpEncryptionCtx));
  struct cipher_suite_info *cipher_info =
      malloc(sizeof(struct cipher_suite_info));
  srtp_encryption_ctx->cipher_suite_info = cipher_info;

  cipher_info->hmac_len = 10;
  srtp_encryption_ctx->roc = 0;

  guchar *iv;
  uint32_t ssrc = 0x00000000;
  uint16_t seq_no = 0x00000000;

  cipher_info->salt_key_len = 14;
  hexstr_to_char_2(&srtp_encryption_ctx->k_s,
                   "F0F1F2F3F4F5F6F7F8F9FAFBFCFD0000");

  cipher_info->key_size = 16;
  hexstr_to_char_2(&srtp_encryption_ctx->k_e,
                   "2B7E151628AED2A6ABF7158809CF4F3C");

  cipher_info->hmac_len = 16;
  cipher_info->hmac_key_len = 16;
  hexstr_to_char_2(&srtp_encryption_ctx->k_a,
                   "CEBE321F6FF7716B6FD4AB49AF256A15");

  init_aes(&srtp_encryption_ctx->aes, srtp_encryption_ctx->k_e,
           cipher_info->key_size, NULL, 0, NULL, CM);

  uint32_t len = 32;
  struct Rtp *rtp = malloc(sizeof(struct Rtp) + len);

  memset(rtp->payload, 0x0, len);
  print_hex(rtp->payload, len);

  rtp->ssrc = ssrc;
  rtp->seq_no = seq_no;

  encrypt_srtp(srtp_encryption_ctx, rtp, &len);

  guchar *expected;
  hexstr_to_char_2(&expected, "E03EAD0935C95E80E166B16DD92B4EB4"
                              "D23513162B02D0F72A43A2FE4A5F97AB"
                              "41E95B3BB0A2E8DD477901E4FCA894C0");
  print_hex(rtp->payload, len);
  assert(memcmp(expected, rtp->payload, 32) == 0);
  printf("srtp encryption successful \n");
}
void test_srtp_mac() {}

void test_srtp() {

  struct srtp_ctx *srtp;

  struct encryption_keys *encryption_keys =
      calloc(1, sizeof(struct encryption_keys));

  struct cipher_suite_info *cipher_info;
  set_cipher_suite_info(&cipher_info, SRTP_AES128_CM_HMAC_SHA1_80);
  encryption_keys->cipher_suite_info = cipher_info;

  encryption_keys->client_write_key = malloc(cipher_info->key_size);
  encryption_keys->client_write_SRTP_salt = malloc(cipher_info->salt_key_len);

  guchar *key_block;
  hexstr_to_char_2(&key_block,
                   "E1F97A0D3E018BE0D64FA32C06DE4139" // master encrytion key
                   "0EC675AD498AFEEBB6960B3AABE6");   // master salt

  copy_key_block(key_block, &encryption_keys->client_write_key,
                 cipher_info->key_size,
                 &encryption_keys->client_write_SRTP_salt,
                 cipher_info->salt_key_len, NULL);

  init_srtp(&srtp, encryption_keys);

  struct Rtp *rtp_packet = malloc(sizeof(struct Rtp) + 400);
  hexstr_to_char_2(&rtp_packet, "a1664567507ed7abdeadbeef01000000");

  guchar *rtp_payload;
  uint32_t rtp_payload_size = hexstr_to_char_2(
      &rtp_payload,
      "6742c01fd9005005bb016a020202800001f480007530078c1924000000000006000000");
  memcpy(rtp_packet->payload, rtp_payload, rtp_payload_size);

  printf("to encrypt rtp packet\n");
  printf("header\n");
  print_hex(rtp_packet, sizeof(struct Rtp));
  printf("payload\n");
  print_hex(rtp_packet->payload, rtp_payload_size);

  encrypt_srtp(srtp->client, rtp_packet, &rtp_payload_size);

  printf("srtp encrypted payload\n");
  print_hex(rtp_packet->payload, rtp_payload_size);
}
int main() {

  // test_srtp_mac();
  // test_srtp_encryption();
  // test_srtp_key_derivation();
  // test_srtp_iv();
  // test_srtp();
  //  aes_test();
  // prf_test();
}
// 24 d5 a4 de 5f 55 84 b2 77 f7 ae 50 c2 8e 69 4c