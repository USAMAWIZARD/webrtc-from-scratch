#pragma once
#include "../DTLS/Encryptions/encryption.h"
#include <glib.h>
#include <openssl/bn.h>
#include <openssl/types.h>
#include <stdint.h>

#define lable_k_e 0x00
#define lable_k_a 0x01
#define lable_k_s 0x02

struct Rtp;

struct __attribute__((packed)) srtp_ext {
  uint16_t profile_len;
  uint16_t encryption_profile;
  uint8_t mki_len;
};

struct SrtpEncryptionCtx {
  uint32_t roc;
  uint16_t mki;
  guchar *master_salt_key;
  guchar *master_write_key;
  guchar *k_e;
  guchar *k_s;
  guchar *k_a;
  uint16_t ssrc;
  uint64_t index : 48;
  uint32_t kdr;

  struct cipher_suite_info *cipher_suite_info;
  struct AesEnryptionCtx *aes;
};

struct srtp_ext parse_srtp_ext(guchar *value, uint16_t len);
void compute_srtp_iv(guchar *pp_iv, guchar *salting_key,
                     uint32_t salting_key_len, guchar *ssrc,
                     guchar *packet_index);

void srtp_key_derivation(struct SrtpEncryptionCtx *srtp_encrption_ctx,
                         struct cipher_suite_info *cipher_suite_info);
void init_srtp(struct srtp_ctx **pp_srtp_ctx,
               struct encryption_keys *encryption_keys);

void encrypt_srtp(struct SrtpEncryptionCtx *srtp_context,
                  struct Rtp *rtp_packet, uint32_t *payloadlen);
