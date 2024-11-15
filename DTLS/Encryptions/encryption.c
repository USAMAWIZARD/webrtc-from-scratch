
#include "./encryption.h"
#include "../../DTLS/dtls.h"
#include "../../SRTP/srtp.h"
#include "../../Utils/utils.h"
#include <glib.h>
#include <math.h>
#include <openssl/bn.h>
#include <openssl/types.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
guchar *PRF(BIGNUM *secret, guchar *label, BIGNUM *seed,
            GChecksumType checksum_type, uint16_t num_bytes) {

  uint16_t total_itration_required =
      ceil((float)num_bytes / g_checksum_type_get_length(checksum_type));

  uint16_t secret_size = BN_num_bytes(secret);
  guchar secret_str[secret_size];
  guchar seed_str[BN_num_bytes(seed)];
  BN_bn2bin(secret, secret_str);
  BN_bn2bin(seed, seed_str);

  uint8_t label_len = strlen(label);
  gsize label_seed_len = label_len + BN_num_bytes(seed);

  guchar label_seed[label_seed_len];
  memcpy(label_seed, label, label_len);
  memcpy(label_seed + label_len, seed_str, label_seed_len);

  gsize checksum_len = g_checksum_type_get_length(checksum_type);
  guchar a_concat_seed[checksum_len + label_seed_len];
  gsize a_concat_seed_len = checksum_len + label_seed_len;
  memcpy(a_concat_seed + checksum_len, label_seed, label_seed_len);

  guchar *ALL_hmac = malloc(checksum_len * total_itration_required);
  for (int i = 1; i <= total_itration_required; i++) {

    guchar *A_seed = a_concat_seed + checksum_len;
    uint16_t A_seed_len = label_seed_len;
    for (int j = 0; j <= i - 1; j++) {

      GHmac *a_hmac = g_hmac_new(checksum_type, secret_str, secret_size);
      g_hmac_update(a_hmac, A_seed, A_seed_len);
      g_hmac_get_digest(a_hmac, a_concat_seed, &checksum_len);

      A_seed = a_concat_seed;
      A_seed_len = checksum_len;

      g_hmac_unref(a_hmac);
    }

    GHmac *hmac = g_hmac_new(G_CHECKSUM_SHA256, secret_str, secret_size);
    g_hmac_update(hmac, a_concat_seed, a_concat_seed_len);
    g_hmac_get_digest(hmac, ALL_hmac + ((i - 1) * checksum_len), &checksum_len);
    g_hmac_unref(hmac);
  }

  return ALL_hmac;
}

struct encryption_keys *
get_srtp_enryption_keys(struct RTCDtlsTransport *transport, guchar *key_block) {

  uint16_t selected_cipher_suite =
      transport->srtp_cipher_suite->selected_cipher_suite;
  struct encryption_keys *encryption_keys = transport->encryption_keys;
  struct cipher_suite_info *cipher_info = transport->srtp_cipher_suite;
  encryption_keys->cipher_suite_info = cipher_info;

  g_assert(encryption_keys != NULL && cipher_info != NULL);

  encryption_keys->client_write_key = malloc(cipher_info->key_size);
  encryption_keys->server_write_key = malloc(cipher_info->key_size);

  encryption_keys->client_write_SRTP_salt = malloc(cipher_info->salt_key_len);
  encryption_keys->server_write_SRTP_salt = malloc(cipher_info->salt_key_len);

  encryption_keys->client_write_IV = malloc(cipher_info->iv_size);
  encryption_keys->server_write_IV = malloc(cipher_info->iv_size);

  copy_key_block(
      key_block, &encryption_keys->client_write_key, cipher_info->key_size,
      &encryption_keys->server_write_key, cipher_info->key_size,
      &encryption_keys->client_write_SRTP_salt, cipher_info->salt_key_len,
      &encryption_keys->server_write_SRTP_salt, cipher_info->salt_key_len,
      NULL);

  printf("------DTLS EXPORTER ------\n");
  printf("Master Srtp Client write key: \n");
  print_hex(encryption_keys->client_write_key, cipher_info->key_size);

  printf("Master Srtp Client write salt key \n");
  print_hex(encryption_keys->client_write_SRTP_salt, cipher_info->salt_key_len);

  return encryption_keys;
}
struct encryption_keys *
get_dtls_encryption_keys(struct RTCDtlsTransport *transport,
                         guchar *key_block) {
  uint16_t selected_cipher_suite = transport->selected_cipher_suite;
  struct encryption_keys *encryption_keys = transport->encryption_keys;
  struct cipher_suite_info *cipher_info = transport->dtls_cipher_suite;
  encryption_keys->cipher_suite_info = cipher_info;

  encryption_keys->client_write_mac_key = malloc(cipher_info->hmac_len);
  encryption_keys->server_write_mac_key = malloc(cipher_info->hmac_len);

  encryption_keys->client_write_key = malloc(cipher_info->key_size);
  encryption_keys->server_write_key = malloc(cipher_info->key_size);

  encryption_keys->client_write_IV = malloc(cipher_info->iv_size);
  encryption_keys->server_write_IV = malloc(cipher_info->iv_size);

  copy_key_block(key_block, &encryption_keys->client_write_mac_key,
                 cipher_info->hmac_len, &encryption_keys->server_write_mac_key,
                 cipher_info->hmac_len, &encryption_keys->client_write_key,
                 cipher_info->key_size, &encryption_keys->server_write_key,
                 cipher_info->key_size, &encryption_keys->client_write_IV,
                 cipher_info->iv_size, &encryption_keys->server_write_IV,
                 cipher_info->iv_size, NULL);

  return encryption_keys;
}

bool init_dtls(struct dtls_ctx **encryption_ctx,
               struct encryption_keys *encryption_keys,
               struct cipher_suite_info *cipher_info) {

  struct dtls_ctx *dtls_encrytion_ctx = malloc(sizeof(struct dtls_ctx));
  dtls_encrytion_ctx->client = calloc(1, sizeof(struct DtlsEncryptionCtx));
  dtls_encrytion_ctx->server = calloc(1, sizeof(struct DtlsEncryptionCtx));

  switch (cipher_info->symitric_algo) {
  case AES:

    if (encryption_keys->client_write_key) {
      init_aes((struct AesEnryptionCtx **)&dtls_encrytion_ctx->client
                   ->encryption_ctx,
               encryption_keys->client_write_key, cipher_info->key_size,
               encryption_keys->client_write_mac_key, cipher_info->hmac_len,
               encryption_keys->client_write_IV, cipher_info->mode);
    }

    if (encryption_keys->server_write_key) {
      init_aes((struct AesEnryptionCtx **)&dtls_encrytion_ctx->server
                   ->encryption_ctx,
               encryption_keys->server_write_key, cipher_info->key_size,
               encryption_keys->server_write_mac_key, cipher_info->hmac_len,
               encryption_keys->server_write_IV, cipher_info->mode);
    }
    dtls_encrytion_ctx->encrypt_func = &encrypt_aes;
    dtls_encrytion_ctx->decrypt_func = &decrypt_aes;

    *encryption_ctx = dtls_encrytion_ctx;
    break;
  }
  return true;
}

bool init_symitric_encryption(struct RTCDtlsTransport *transport) {
  BIGNUM *master_secret = transport->encryption_keys->master_secret;

  guchar *key_block =
      PRF(master_secret, "key expansion",
          get_dtls_rand_appended(transport->peer_random, transport->my_random),
          G_CHECKSUM_SHA256, 128);

  struct encryption_keys *encryption_keys =
      get_dtls_encryption_keys(transport, key_block);
  free(key_block);

  init_dtls(&transport->dtls_ctx, encryption_keys,
            transport->dtls_cipher_suite);

  // check if srtp is required SRTP

  key_block =
      PRF(master_secret, "EXTRACTOR-dtls_srtp",
          get_dtls_rand_appended(transport->my_random, transport->peer_random),
          G_CHECKSUM_SHA256, 128);

  encryption_keys = get_srtp_enryption_keys(transport, key_block);
  init_srtp(&transport->srtp_ctx, encryption_keys);

  free(key_block);

  return true;
}
bool set_cipher_suite_info(struct cipher_suite_info **pp_cipher_suite_info,
                           uint16_t selected_cipher_suite) {
  struct cipher_suite_info *cipher_info =
      calloc(1, sizeof(struct cipher_suite_info));

  cipher_info->selected_cipher_suite = selected_cipher_suite;

  switch (cipher_info->selected_cipher_suite) {
  case TLS_RSA_WITH_AES_128_CBC_SHA:
    cipher_info->hmac_algo = G_CHECKSUM_SHA1;
    cipher_info->hmac_len = g_checksum_type_get_length(cipher_info->hmac_algo);
    cipher_info->hmac_key_len = 20;
    cipher_info->key_size = 16;
    cipher_info->iv_size = 16;
    cipher_info->symitric_algo = AES;
    cipher_info->mode = CBC;
    *pp_cipher_suite_info = cipher_info;

    break;
  case SRTP_AES128_CM_HMAC_SHA1_80:
    cipher_info->hmac_algo = G_CHECKSUM_SHA1;
    cipher_info->hmac_len = 10;
    cipher_info->hmac_key_len = 20;
    cipher_info->key_size = 16;
    cipher_info->salt_key_len = 14;
    cipher_info->iv_size = 16;
    cipher_info->symitric_algo = AES;
    cipher_info->mode = CM;

    *pp_cipher_suite_info = cipher_info;

    break;
  default:
    printf("cipher sute not supported %x \n", selected_cipher_suite);
    exit(0);
  }
  return true;
}
