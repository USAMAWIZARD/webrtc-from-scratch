#include "./srtp.h"
#include "../DTLS/Encryptions/encryption.h"
#include "../RTP/rtp.h"
#include "../Utils/utils.h"
#include <arpa/inet.h>
#include <glib.h>
#include <openssl/bn.h>
#include <openssl/types.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct srtp_ext parse_srtp_ext(guchar *value, uint16_t len) {
  struct srtp_ext ext;
  memcpy(&ext, value, sizeof(struct srtp_ext));
  ext.profile_len = ntohs(ext.profile_len);
  ext.encryption_profile = ntohs(ext.encryption_profile);
  printf("%x\n", ext.encryption_profile);

  return ext;
}
void compute_srtp_iv(guchar *all_xored_iv, guchar *salting_key,
                     uint32_t salting_key_len, guchar *ssrc,
                     guchar *packet_index) {
  // IV = (k_s * 2 ^ 16) XOR(SSRC * 2 ^ 64) XOR(i * 2 ^ 16)

  memset(all_xored_iv + 14, 0, 2);
  int pos = 16 - 2 - salting_key_len; // 16 shifted
  memcpy(all_xored_iv - pos, salting_key, salting_key_len);

  pos = 16 - 8 - 4; // 64 shifted
  for (int i = 3; i >= 0; i--) {
    all_xored_iv[pos] = all_xored_iv[pos] ^ ssrc[i];
    pos++;
  }

  pos = 16 - 2 - 6; // 16 shifted
  for (int i = 5; i >= 0; i--) {
    all_xored_iv[pos] = all_xored_iv[pos] ^ packet_index[i];
    pos++;
  }
}

void calculate_x_and_to_encrypt(struct SrtpEncryptionCtx *srtp_encrption_ctx,
                                guchar *x, guchar *toencrypt, uint8_t lable) {
  // uint64_t key_id = 0;
  memset(x, 0, 16);
  memset(toencrypt, 0, 16);

  // uint64_t r = 0;
  // if (srtp_encrption_ctx->kdr)
  //   r = srtp_encrption_ctx->index / srtp_encrption_ctx->kdr;
  //
  // memcpy(((guchar *)&key_id), (guchar *)&r, 48 / 8);

  memcpy(x, srtp_encrption_ctx->master_salt_key,
         srtp_encrption_ctx->cipher_suite_info->salt_key_len);

  x[7] ^= lable;

  // for (int i = 0; i <= 6; i++)
  //   x[i + 8] =
  //       ((guchar *)&key_id)[i] ^ srtp_encrption_ctx->master_salt_key[i + 8];
}

struct AesEnryptionCtx *srtp_prf(struct SrtpEncryptionCtx *srtp_encrption_ctx,
                                 uint8_t lable, guchar **pp_data,
                                 uint32_t data_len) {

  struct AesEnryptionCtx *aes;
  guchar x[16];
  guchar toencrypt[16] = {0};
  guchar iv[16];

  *pp_data = malloc(data_len + 16);
  guchar *i_data = *pp_data;
  int32_t i = data_len;
  if (data_len > 40)
    exit(0);

  calculate_x_and_to_encrypt(srtp_encrption_ctx, x, toencrypt, lable);
  memcpy(iv, x, 16);

  init_aes(&aes, srtp_encrption_ctx->master_write_key,
           srtp_encrption_ctx->cipher_suite_info->key_size, x,
           srtp_encrption_ctx->cipher_suite_info->hmac_key_len, iv, CM);

  while (i > 0) {
    calculate_x_and_to_encrypt(srtp_encrption_ctx, x, toencrypt, lable);
    encrypt_aes(aes, toencrypt, 0, 16);
    memcpy(i_data, toencrypt, 16);
    i -= 16;
    i_data += 16;
    transpose_matrix(aes->IV);
  }

  return aes;
}

void srtp_key_derivation(struct SrtpEncryptionCtx *srtp_encrption_ctx,
                         struct cipher_suite_info *cipher_suite_info) {
  srtp_encrption_ctx->cipher_suite_info = cipher_suite_info;

  srtp_prf(srtp_encrption_ctx, lable_k_e, &srtp_encrption_ctx->k_e,
           cipher_suite_info->key_size);

  srtp_prf(srtp_encrption_ctx, lable_k_a, &srtp_encrption_ctx->k_a,
           srtp_encrption_ctx->cipher_suite_info->hmac_key_len);

  srtp_prf(srtp_encrption_ctx, lable_k_s, &srtp_encrption_ctx->k_s,
           cipher_suite_info->salt_key_len);

  printf("----- SRTP KEY DERIVATION ------ \n");

  printf("authentication key\n");
  print_hex(srtp_encrption_ctx->k_a,
            srtp_encrption_ctx->cipher_suite_info->hmac_key_len);
  printf("salt key\n");
  print_hex(srtp_encrption_ctx->k_s,
            srtp_encrption_ctx->cipher_suite_info->salt_key_len);
  printf("encryption key\n");
  print_hex(srtp_encrption_ctx->k_e,
            srtp_encrption_ctx->cipher_suite_info->key_size);

  struct AesEnryptionCtx *aes;
  init_aes(&aes, srtp_encrption_ctx->k_e, cipher_suite_info->key_size, NULL, 0,
           NULL, CM);

  srtp_encrption_ctx->aes = aes;
}

void init_srtp(struct srtp_ctx **pp_srtp_ctx,
               struct encryption_keys *encryption_keys) {

  struct srtp_ctx *srtp_ctx = malloc(sizeof(struct srtp_ctx));
  srtp_ctx->client = calloc(1, sizeof(struct SrtpEncryptionCtx));
  srtp_ctx->server = calloc(1, sizeof(struct SrtpEncryptionCtx));

  if (encryption_keys->client_write_key) {
    srtp_ctx->client->master_salt_key = encryption_keys->client_write_SRTP_salt;
    srtp_ctx->client->master_write_key = encryption_keys->client_write_key;
    srtp_key_derivation(srtp_ctx->client, encryption_keys->cipher_suite_info);
  }

  if (encryption_keys->server_write_key) {
    srtp_ctx->server->master_write_key = encryption_keys->server_write_key;
    srtp_ctx->server->master_salt_key = encryption_keys->server_write_SRTP_salt;
    srtp_key_derivation(srtp_ctx->server, encryption_keys->cipher_suite_info);
  }

  srtp_ctx->encrypt_func = &encrypt_aes;
  srtp_ctx->decrypt_func = &decrypt_aes;

  *pp_srtp_ctx = srtp_ctx;
}

void encrypt_srtp(struct SrtpEncryptionCtx *srtp_context,
                  struct Rtp *rtp_packet, uint32_t *payloadlen) {

  uint64_t index = (0) + ntohs(rtp_packet->seq_no);

  guchar iv[16];
  uint32_t ssrc = ntohl(rtp_packet->ssrc);

  compute_srtp_iv(iv, srtp_context->k_s,
                  srtp_context->cipher_suite_info->salt_key_len,
                  (guchar *)&ssrc, (guchar *)&index);
  g_debug("iv for encyrption\n");
  srtp_context->aes->IV = iv;
  print_hex(iv, 16);
  g_debug("salt key  \n");
  print_hex(srtp_context->k_s, 14);
  g_debug("encypt key  \n");
  print_hex(srtp_context->k_e, 16);

  gsize hmac_len = 20;

  guchar computed_mac[hmac_len];

  g_debug("to ebncrypt\n");
  print_hex(rtp_packet->payload, *payloadlen);

  encrypt_aes(srtp_context->aes, rtp_packet->payload, 0, *payloadlen);

  g_debug("encrypted\n");
  print_hex(rtp_packet->payload, *payloadlen);

  GHmac *srtp_hmac = g_hmac_new(G_CHECKSUM_SHA1, srtp_context->k_a,
                                srtp_context->cipher_suite_info->hmac_key_len);
  g_hmac_update(srtp_hmac, (guchar *)rtp_packet, sizeof(struct Rtp));
  g_hmac_update(srtp_hmac, rtp_packet->payload, *payloadlen);
  g_hmac_update(srtp_hmac, (guchar *)&srtp_context->roc, 4);
  g_hmac_get_digest(srtp_hmac, computed_mac, &hmac_len);

  g_debug("computed mac\n");
  print_hex(computed_mac, 10);

  memcpy(rtp_packet->payload + (*payloadlen), computed_mac,
         srtp_context->cipher_suite_info->hmac_len);

  *payloadlen = srtp_context->cipher_suite_info->hmac_len + (*payloadlen);

  g_hmac_unref(srtp_hmac);
}
