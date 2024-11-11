#include "dtls.h"
#include "../Network/network.h"
#include "../RTP/rtp.h"
#include "../SRTP/srtp.h"
#include "../STUN/stun.h"
#include "../Utils/utils.h"
#include "../WebRTC/webrtc.h"
#include "./Encryptions/encryption.h"
#include "json-glib/json-glib.h"
#include <bits/pthreadtypes.h>
#include <bits/types/struct_iovec.h>
#include <ctype.h>
#include <errno.h>
#include <glib.h>
#include <malloc.h>
#include <math.h>
#include <netinet/in.h>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/types.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>

gchar *my_rsa_public_cert =
    "308202f0308201d8a00302010202060191b72d1cc4300d06092a864886f70d01010b050030"
    "39310d300b06035504030c0474657374310b3009060355040613025553311b301906092a86"
    "4886f70d010901160c7465737440746573742e696f301e170d323430393033303931373532"
    "5a170d3235303930333039313735325a3039310d300b06035504030c0474657374310b3009"
    "060355040613025553311b301906092a864886f70d010901160c7465737440746573742e69"
    "6f30820122300d06092a864886f70d01010105000382010f003082010a02820101009da3b9"
    "42f90af45d38462fade4304c738e6503aee887b41d42c203186fb1eb269b0c9b779cd90744"
    "96cb075659cd9bd7acc208438a97717821625fffb7f761266a7589d049398e4dba6eca6969"
    "2055f57e02871ad99f43bcfbb2e58ca6a14b5a53e1ebd1601ddea4200084a8d01494dad18f"
    "90cb01aa00932eeb93adc345d1742586a54755217c9bebee79c9ecfe6a3a14d2a0abb7cc1d"
    "e87341d8cdb451e8a94e6bba08d0e70959f2b8e3b32dce1f951b9df1acf0183240c2452ef6"
    "c80a4cd988f11d3603b4282513b89a72fda79c8a09aaecd6a8f79851f50ace0a33f67172b1"
    "d8e9beb2ec71b40a013894d0edef5fad8fb9185ea4ed636f35ecfe7c25906d020301000130"
    "0d06092a864886f70d01010b0500038201010031885530f32f767e3b04dda840183214c77c"
    "76a73568145d7d7a3a83ff5d95aaff6ddf0ba2957d2adc8b9a9a78099b4a7c66d9fc51656c"
    "0c2b16e4e2abbe7320a86d175012d6a4e36109615b4da6f48f4245b5dfdf1eff886aa17ca4"
    "7f522a3efa8a9dbc12a8a5006f51ef5c10c5d2e0ba9568452638a6e1b8c8125f7578def1b7"
    "7a6932af456e01d5e60030a60a00b60c386e942701b3fe8c56e8a84a22c28e1932d19610ea"
    "03c8c01ec3beb5999a31a33e70bc63cc5046dfce79b4c4bd46fb9878bcbcee3bd4703fda0e"
    "2119c6459b8998e86d241003538aab47224dec83da02ef9a758a2aca197cba009aba784ee7"
    "d2a25457c15107917ee8d97cb56a7660";

gchar *my_rsa_private_key =
    "308204bc020100300d06092a864886f70d0101010500048204a6308204a202010002820101"
    "009da3b942f90af45d38462fade4304c738e6503aee887b41d42c203186fb1eb269b0c9b77"
    "9cd9074496cb075659cd9bd7acc208438a97717821625fffb7f761266a7589d049398e4dba"
    "6eca69692055f57e02871ad99f43bcfbb2e58ca6a14b5a53e1ebd1601ddea4200084a8d014"
    "94dad18f90cb01aa00932eeb93adc345d1742586a54755217c9bebee79c9ecfe6a3a14d2a0"
    "abb7cc1de87341d8cdb451e8a94e6bba08d0e70959f2b8e3b32dce1f951b9df1acf0183240"
    "c2452ef6c80a4cd988f11d3603b4282513b89a72fda79c8a09aaecd6a8f79851f50ace0a33"
    "f67172b1d8e9beb2ec71b40a013894d0edef5fad8fb9185ea4ed636f35ecfe7c25906d0203"
    "010001028201000873b6a3567555bc73ca763efabcf389bf3e3f9aceabe1512fa5a058873b"
    "4107925e4982f9c811cc307b95454b7900873ea383f6e9c4e1ed6b78cf50877d68da3af0af"
    "616eb3a5236f6b5b9ded92dc190157185b025a62dd8c99e9c0874f499a2a64dd69c89f56b3"
    "1d10cf616510081a780c47054e185e81db0d001f866df00e1671088b77b8fe39b5b4a901de"
    "d5d4c89aae3fd3c2aabd2226068c55620fac98b7dcc83332be416c5f070fb56a63461aeb8a"
    "d1637442d2b0bdecd16048d04396052a4841177182312642e02f6198a2e236cbc884fa54f1"
    "8d9363c422af5cfb32c21f702dd236b471e48cb97f571dc8e160d92e901228022afcf9e6b0"
    "50d35dff02818100cfe297e52302d58437c14a867626396401970149c3af836847150dde1f"
    "ceb7c94fc87e5bea6ed9db4aff4518311853b205205d7efc9af71fe33ddfec3c12c773e079"
    "e45c68f3f8472fbb67f86c6b687240985526ddd9147a8403a6ebf23078e08de3e24b55f033"
    "e1092aaa509735f10c00e80eee969c5255887da57d5abf452302818100c220072dbebb8992"
    "52da10e17c6100ed3bc356ac37a911f775fca874ca7514fdd4ed9d0907896d889a7b87ab81"
    "8c198311056f19ced8e5eb7c03ae34dfaf8f554ee17668d2a5be307fd2e8a87522dd14212d"
    "be927aec7f1173492b6ead3bfdcfa49de281a68e033ac9155a6cee51227cc8cbfd45b1715c"
    "0c14de8d741ff4152f0281801cb8333fe6ac578f229cc38cfbf99fe81f081b97733f662a1b"
    "d7dec8972059e7a7ec0cf8e9d452a8a71dc90fe48875d79c39b270feb8f1f727cfbe85c66e"
    "d9bb3a81dc789fcf44b7a0f285149ef5dfc21906728d220d01754393b595d729b7295eb0e2"
    "ec817ce3cded1445df48649d5e89298616941c188bd485773d7032087d0281804301451910"
    "15b155954d79b82af35c9b861e55a35a0efc899aeb1bc63c3f8f8051e7b66570798a1a35a0"
    "5fe2ddf35ab6f7c0156a26108dc3eb6965cf104a8bc1d9594f42bd3ac25c0132ee657f110a"
    "98311f9600ff76f42134d6d3abff158ef506100d27cd328580dbf987ddc3a0b3b3b8a75883"
    "9ecccf05c88a4cef013c81b70281801796d64f3cc9a8f42f02abd7193432fadcd856fc685d"
    "ec12f89101b610ba8bbf9e49f220b73bcb9afdc57beead41dff2409a8a21cdef7b917eea53"
    "12dbce6cdea4e1ac90a6e915a6011c64f33df1b59e39d944d10f4d88c29fc7e7b8a66836f5"
    "2b075c42e80c1c74b2af94c79e3b28a2f98f5929a6fba389dd3c8fb4c90c6c53";

uint16_t cipher_suite_list[CIPHER_SUITE_LEN] = {TLS_RSA_WITH_AES_128_CBC_SHA};

uint16_t srtp_supported_profiles[] = {SRTP_AES128_CM_HMAC_SHA1_80};
uint16_t signature_algorithms[] = {0x0102, 0x0104};
uint16_t supported_signature_algorithms[] = {0x0401};

struct RTCDtlsTransport *create_dtls_transport() {
  struct RTCDtlsTransport *dtls_transport =
      calloc(1, sizeof(struct RTCDtlsTransport));

  dtls_transport->dtls_flights = json_object_new();
  dtls_transport->encryption_keys = malloc(sizeof(struct encryption_keys));

  dtls_transport->state = DTLS_CONNECTION_STATE_NEW;
  dtls_transport->fingerprint =
      "3C:4A:AA:DA:3A:F5:7F:B1:60:B2:1A:BB:59:20:22:DB:FC:44:FB:71:BB:88:"
      "6D:E5:";
  dtls_transport->mode = DTLS_ACTIVE;

  guchar *my_private_cert_bin;
  uint16_t cert_len =
      hexstr_to_char_2(&my_private_cert_bin, my_rsa_private_key);

  guchar *my_public_key_bin;
  uint16_t public_key_len =
      hexstr_to_char_2(&my_public_key_bin, my_rsa_public_cert);

  EVP_PKEY *private_key;
  private_key = d2i_PrivateKey(EVP_PKEY_RSA, NULL,
                               (const guchar **)&my_private_cert_bin, cert_len);
  dtls_transport->my_private_key = private_key;

  X509 *cert;
  const guchar *public_certificate;
  uint32_t certificate_len =
      hexstr_to_char_2((guchar **)&public_certificate, my_rsa_public_cert);
  cert = d2i_X509(NULL, (&public_certificate), certificate_len);
  EVP_PKEY *pub_key = X509_get_pubkey(cert);
  dtls_transport->my_public_key = pub_key;

  RSA *rsa = EVP_PKEY_get1_RSA(pub_key);
  BIGNUM *my_public_exponent = RSA_get0_e(rsa);
  BIGNUM *my_public_modulus = RSA_get0_n(rsa);
  printf("my public exponent %s\n", BN_bn2hex(my_public_exponent));
  printf("my public modulus %s\n", BN_bn2hex(my_public_modulus));

  BIGNUM *r1 = BN_new();
  BN_bin2bn((guchar *)g_uuid_string_random(), 32, r1);
  dtls_transport->my_random = r1;

  dtls_transport->cookie = 1213;

  return dtls_transport;
}

void send_dtls_client_hello(struct RTCPeerConnection *peer, bool with_cookie) {

  struct DtlsClientHello *dtls_client_hello =
      malloc(sizeof(struct DtlsClientHello));

  dtls_client_hello->client_version = htons(DTLS_1_2);
  guchar *myrandom = malloc(32);
  BN_bn2bin(peer->dtls_transport->my_random, myrandom);
  memcpy(dtls_client_hello->random, myrandom, 32);
  free(myrandom);
  dtls_client_hello->cookie_len =
      with_cookie ? peer->dtls_transport->cookie : with_cookie;
  dtls_client_hello->cipher_suite_len = sizeof(cipher_suite_list);
  dtls_client_hello->compression_method_len = 1;
  dtls_client_hello->compression_method = 0;
  dtls_client_hello->session_id = 0;
  dtls_client_hello->extention_len = 0;

  memcpy(dtls_client_hello->cipher_suite, cipher_suite_list,
         dtls_client_hello->cipher_suite_len);
  dtls_client_hello->cipher_suite_len =
      htons(dtls_client_hello->cipher_suite_len);

  // printf("\nlen %x %x\n", cipher_suite_list[0],
  //        (uint16_t)dtls_client_hello->cipher_suite[0]);
  // print_hex(dtls_client_hello->cipher_suite,
  //           dtls_client_hello->cipher_suite_len);

  uint16_t ext_len;
  struct dtls_ext *srtp_extention;
  uint8_t mki_len = 0;

  struct dtls_ext *supported_signature_algorithms;
  ext_len = make_extentention(&supported_signature_algorithms, SIGN_ALGO_EXT,
                              (guchar *)signature_algorithms,
                              sizeof(signature_algorithms), 0, 0);
  add_dtls_extention(&dtls_client_hello, supported_signature_algorithms,
                     ext_len);
  free(supported_signature_algorithms);

  ext_len = make_extentention(&srtp_extention, SRTP_EXT,
                              (guchar *)srtp_supported_profiles,
                              sizeof(srtp_supported_profiles), &mki_len, 1);
  add_dtls_extention(&dtls_client_hello, srtp_extention, ext_len);
  free(srtp_extention);

  // struct dtls_ext *other_extention;
  // ext_len =
  //     make_extentention(&other_extention, EXTEND_MASTER_SEC_EXT, 0, 0, 0, 0);
  // add_dtls_extention(&dtls_client_hello, other_extention, ext_len);
  // free(other_extention);
  //
  // // session ticket extention
  // ext_len = make_extentention(&other_extention, SESS_TICKET_EXT, 0, 0, 0, 0);
  // add_dtls_extention(&dtls_client_hello, other_extention, ext_len);
  // free(other_extention);

  // int a = 0;
  // ext_len = make_extentention(&other_extention, 0xff01, 0, 0, &a, 1);
  // add_dtls_extention(&dtls_client_hello, other_extention, ext_len);
  // free(other_extention);

  dtls_client_hello->extention_len = htons(dtls_client_hello->extention_len);

  send_dtls_packet(peer->dtls_transport, handshake_type_client_hello,
                   (guchar *)dtls_client_hello,
                   sizeof(struct DtlsClientHello) +
                       ntohs(dtls_client_hello->extention_len));

  printf("--------------------- DTLS Client Hello  -------------------->\n");
}
uint8_t get_content_type(uint8_t handshake_type) {

  uint8_t content_type = 22;
  if (handshake_type == handshake_type_change_cipher_spec)
    content_type = 20;

  return content_type;
}
bool get_fragment_itration_info(uint32_t total_len, uint8_t *no_of_itrations,
                                uint16_t *fragment_len) {
  *no_of_itrations = 1;

  if (total_len < 255) {
    *fragment_len = total_len;
    return false;
  }
  *no_of_itrations = ceil((float)total_len / 260);
  *fragment_len = total_len / *no_of_itrations;

  return true;
}

bool send_dtls_packet(struct RTCDtlsTransport *dtls_transport,
                      uint8_t handshake_type, guchar *dtls_payload,
                      uint32_t dtls_payload_len) {
  uint8_t no_of_itrations;
  uint16_t fragment_mtu_len;
  guchar *dtls_payload_fragment = dtls_payload;

  bool is_fragmented = get_fragment_itration_info(
      dtls_payload_len, &no_of_itrations, &fragment_mtu_len);

  uint32_t remaining_data = dtls_payload_len;
  uint16_t fragment_seq_no = dtls_transport->current_flight_no;

  while (no_of_itrations > 0) {
    if (no_of_itrations == 1)
      fragment_mtu_len = remaining_data;

    struct CandidataPair *pair = dtls_transport->pair;
    struct DtlsHeader *dtls_header = malloc(sizeof(struct DtlsHeader));
    dtls_header->type = get_content_type(handshake_type);

    dtls_header->version = handshake_type == handshake_type_client_hello
                               ? htons(DTLS_1_0)
                               : htons(DTLS_1_2);
    dtls_header->epoch = dtls_transport->epoch;
    dtls_header->length = htons(fragment_mtu_len);
    dtls_header->sequence_number = htons(dtls_transport->current_seq_no);
    dtls_header->sequence_number = dtls_header->sequence_number << 32;

    struct HandshakeHeader *handshake = NULL;

    if (!(handshake_type == handshake_type_change_cipher_spec)) {

      dtls_header->length =
          htons(ntohs(dtls_header->length) + sizeof(struct HandshakeHeader));

      handshake = malloc(sizeof(struct HandshakeHeader));
      handshake->type = handshake_type;
      handshake->message_seq = htons(fragment_seq_no);
      handshake->length = htonl(dtls_payload_len) >> 8;
      handshake->fragment_length = htonl(fragment_mtu_len) >> 8;
      handshake->fragment_offset =
          htonl(dtls_payload_fragment - dtls_payload) >> 8;
    }
    store_concated_handshake_msgs(dtls_transport, handshake,
                                  dtls_payload_fragment, fragment_mtu_len,
                                  is_fragmented);

    struct iovec dtls_packet[5];

    uint8_t len =
        make_dtls_packet(dtls_transport, &dtls_packet[0], dtls_header,
                         handshake, dtls_payload_fragment, fragment_mtu_len);

    struct msghdr msghdr = {0};
    msghdr.msg_iov = dtls_packet;
    msghdr.msg_iovlen = len;
    msghdr.msg_name = (struct sockaddr *)pair->p1->src_socket;
    msghdr.msg_namelen = sizeof(struct sockaddr_in);

    int bytes = sendmsg(pair->p0->sock_desc, &msghdr, 0);

    dtls_transport->current_seq_no++;
    dtls_payload_fragment = dtls_payload_fragment + fragment_mtu_len;
    remaining_data -= fragment_mtu_len;
    no_of_itrations--;

    if (bytes < 0) {
      printf("error no : %d\n", errno);
      printf("cannot send DTLS packet %d\n", len);
      exit(0);
    }
  }
  if (get_content_type(handshake_type) == 22)
    dtls_transport->current_flight_no++;

  return true;
}

void dtls_symitric_encrypt(struct RTCDtlsTransport *transport) {
  switch (transport->dtls_cipher_suite->symitric_algo) {
  case AES:
    switch (transport->dtls_cipher_suite->mode) {
    case CBC:

      break;
    case CM:
      printf("Coutnter mode is not supported");
      exit(0);
      break;
    default:
      printf("unsupported symitric algorithm for dtls \n");
      exit(0);
    }
  }
}
uint8_t make_dtls_packet(struct RTCDtlsTransport *transport, struct iovec *iov,
                         struct DtlsHeader *dtls_header,
                         struct HandshakeHeader *handshake,
                         guchar *dtls_payload, uint32_t payload_len) {

  uint8_t iov_len = 0;
  bool encrypt_packet = ntohs(dtls_header->epoch);
  size_t Hheader_payload_len = payload_len;

  if (handshake != NULL)
    Hheader_payload_len += sizeof(struct HandshakeHeader);

  guchar *packet = malloc(Hheader_payload_len + 64 + 400 +
                          16); //  length max hmac size max paddign size
  guchar *ptr = packet;

  iov[iov_len].iov_base = dtls_header;
  iov[iov_len].iov_len = sizeof(struct DtlsHeader);
  iov_len++;

  if (handshake != NULL) {
    memcpy(ptr, handshake, sizeof(struct HandshakeHeader));
    ptr = ptr + sizeof(struct HandshakeHeader);
  }

  memcpy(ptr, dtls_payload, payload_len);
  ptr = ptr + payload_len;

  if (encrypt_packet) {
    struct dtls_ctx *encryption_ctx = transport->dtls_symitric_encrypt.dtls;
    struct AesEnryptionCtx *client_Ectx =
        encryption_ctx->client->encryption_ctx;

    iov[iov_len].iov_base = client_Ectx->recordIV;
    iov[iov_len].iov_len = 16;
    iov_len++;

    // calculate mac of the packet
    gsize hmac_len = transport->dtls_cipher_suite->hmac_len;
    GHmac *hmac = g_hmac_new(transport->dtls_cipher_suite->hmac_algo,
                             client_Ectx->mac_key, client_Ectx->mac_key_size);
    g_hmac_update(hmac, (guchar *)&dtls_header->epoch,
                  8); // copies epoch and seq number
    g_hmac_update(hmac, &dtls_header->type, 1);
    g_hmac_update(hmac, (guchar *)&dtls_header->version, 2);
    g_hmac_update(hmac, (guchar *)&dtls_header->length, 2);
    g_hmac_update(hmac, (guchar *)handshake, sizeof(struct HandshakeHeader));
    g_hmac_update(hmac, dtls_payload, payload_len);
    //

    guchar dtls_packet_mac[hmac_len];
    g_hmac_get_digest(hmac, dtls_packet_mac, &hmac_len);
    memcpy(ptr, dtls_packet_mac, hmac_len);

    printf("to encrypt \n");
    print_hex(packet, Hheader_payload_len + hmac_len);

    uint32_t enrypted_len = encrypt_aes(
        client_Ectx, packet, 0,
        Hheader_payload_len + hmac_len); // set this as a function pointer
    print_hex(packet, enrypted_len);

    dtls_header->length = htons(enrypted_len + 16); // IV len

    Hheader_payload_len = enrypted_len;
  }

  iov[iov_len].iov_base = packet;
  iov[iov_len].iov_len = Hheader_payload_len;
  iov_len++;

  return iov_len;
}

uint16_t add_dtls_extention(struct DtlsClientHello **dtls_hello,
                            struct dtls_ext *extention,
                            uint16_t extention_len) {
  uint16_t old_ext_len = (*dtls_hello)->extention_len;
  uint16_t new_len =
      sizeof(struct DtlsClientHello) + old_ext_len + extention_len;

  *dtls_hello = realloc(*dtls_hello, new_len);
  // printf("old ext lend %d \n", (*dtls_hello)->extention_len);
  memcpy((char *)(*dtls_hello)->extentions + old_ext_len, extention,
         extention_len);

  (*dtls_hello)->extention_len += extention_len;

  return new_len;
}
void start_dtls_negosiation(struct RTCPeerConnection *peer) {
  if (peer == NULL || peer->dtls_transport->pair == NULL) {
    return;
  }
  struct CandidataPair *pair = peer->dtls_transport->pair;
  printf("starting DTLS Negosiation on pair %s %d %s %d \n", pair->p0->address,
         pair->p0->port, pair->p1->address, pair->p1->port);
  send_dtls_client_hello(peer, false);
}

bool check_if_dtls(uint8_t first_byte) {
  return (first_byte > 19 && first_byte < 34);
}

uint16_t make_extentention(struct dtls_ext **ext, uint16_t extention_type,
                           guchar *data, uint16_t data_len, guchar *extradata,
                           uint16_t extra_data_len) {
  struct dtls_ext *extention =
      malloc(sizeof(struct dtls_ext) + data_len + extra_data_len + 2);

  extention->type = htons(extention_type);
  extention->ext_length = 0;

  if (data_len != 0) {
    extention->ext_length = (data_len + 2);
    uint16_t len = htons(data_len);
    memcpy(extention->value, &len, sizeof(uint16_t));
    memcpy(extention->value + sizeof(uint16_t), data, data_len);
  }
  if (extra_data_len != 0) {
    memcpy(extention->value + extention->ext_length, extradata, extra_data_len);
    extention->ext_length += extra_data_len;
  }

  *ext = extention;
  // print_hex(extention, (sizeof(struct dtls_ext) + extention->ext_length));

  extention->ext_length = htons(extention->ext_length);
  return (sizeof(struct dtls_ext) + ntohs(extention->ext_length));
}

void on_dtls_packet(struct NetworkPacket *netowrk_packet,
                    struct RTCPeerConnection *peer) {

  JsonObject *flight = peer->dtls_transport->dtls_flights;
  struct DtlsParsedPacket *dtls_packet = netowrk_packet->payload.dtls_parsed;

  printf("packet type : %d\n", dtls_packet->dtls_header->type);

  while (dtls_packet != NULL) {

    if (dtls_packet->isencrypted) {
      printf("\n -----------------------"
             "encrypted dtls packet----------------------- \n");

      dtls_packet = dtls_packet->next_record;
      // decrept the packet and check if its a finished messaga also verify the
      // hash of the message
      printf("%ld", peer->dtls_transport->srtp_symitric_encrypt.srtp->client
                        ->cipher_suite_info->hmac_len);
      init_rtp_stream(
          peer->transceiver->sender->track->rtp_stream,
          peer->dtls_transport->pair,
          peer->dtls_transport->srtp_symitric_encrypt.srtp
              ->client); // change here set it to selected pair in ice not

      start_rtp_stream(peer->transceiver->sender->track->rtp_stream);

      continue;
    }
    switch (dtls_packet->dtls_header->type) {
    case content_type_change_cipher_spec:
      printf("\n -----------------------"
             "change cipher spec ---------------------------- \n");
      dtls_packet = dtls_packet->next_record;
      continue;
    case content_type_alert:
      printf("allert ----\n");
      continue;
    }

    uint32_t total_fragment_len =
        ntohl((uint32_t)dtls_packet->handshake_header->length) >> 8;
    uint32_t fragment_length =
        ntohl((uint32_t)dtls_packet->handshake_header->fragment_length) >> 8;
    uint32_t fragment_offset =
        ntohl((uint32_t)dtls_packet->handshake_header->fragment_offset) >> 8;
    guchar *handshake_payload = dtls_packet->handshake_payload;

    gchar *handshake_type_str =
        g_strdup_printf("%d", dtls_packet->handshake_type);

    bool was_last_pkt_fragmented = false;
    bool is_this_last_fragment = false;

    store_concated_handshake_msgs(peer->dtls_transport,
                                  dtls_packet->handshake_header,
                                  dtls_packet->handshake_payload,
                                  fragment_length, dtls_packet->isfragmented);

    if (dtls_packet->isfragmented) {
      printf("fragmented \n");
      struct DtlsParsedPacket *last_similar_packet = NULL;

      if (json_object_has_member(flight, handshake_type_str)) {
        last_similar_packet =
            (struct DtlsParsedPacket *)(json_object_get_int_member(
                flight, handshake_type_str));

      } else {
        json_object_set_int_member(flight, handshake_type_str,
                                   (guint64)dtls_packet);
        dtls_packet->all_fragmented_payload = malloc(total_fragment_len);
        memcpy(dtls_packet->all_fragmented_payload,
               dtls_packet->handshake_payload, fragment_length);

        return;
      }
      if (last_similar_packet && last_similar_packet->isfragmented) {

        uint16_t last_packet_seqno =
            last_similar_packet->handshake_header->message_seq;

        uint16_t this_packet_seqno = dtls_packet->handshake_header->message_seq;

        if (last_packet_seqno == this_packet_seqno) {
          memcpy(last_similar_packet->all_fragmented_payload + fragment_offset,
                 dtls_packet->handshake_payload, fragment_length);

          printf("fragment continue type: %s seq %d %d flen %d\n ",
                 handshake_type_str, last_packet_seqno, fragment_offset,
                 fragment_length);
        }
      }

      if (!dtls_packet->islastfragment)
        return;

      handshake_payload = last_similar_packet->all_fragmented_payload;

      g_debug("all fragments aseembedled \n");

    } else {
      g_debug("non fragmented \n");
    }
    switch (dtls_packet->handshake_type) {
    case handshake_type_server_hello:
      printf("---------------------- Server Hello ------------------------\n");
      uint16_t dtls_hello_size = fragment_length;

      struct llTVL *tvl;
      struct DtlsServerHello *server_hello =
          parse_server_hello(handshake_payload, total_fragment_len, &tvl);

      dtls_packet->parsed_handshake_payload.hello = server_hello;

      handle_server_hello(peer->dtls_transport, server_hello, tvl);
      break;

    case handshake_type_certificate:
      if (total_fragment_len < sizeof(uint32_t))
        return;
      printf("certificate \n");

      uint32_t total_certificates_len =
          ntohl(*((uint32_t *)handshake_payload)) >> 8;

      if (total_fragment_len < total_certificates_len)
        return;

      handshake_payload += 3;

      uint32_t certificate_len = ntohl(*((uint32_t *)handshake_payload)) >> 8;

      struct Certificate *certificate =
          malloc(sizeof(struct Certificate) + certificate_len + 1000);
      certificate->certificate_len = certificate_len;

      handshake_payload += 3;

      if (total_fragment_len < 3 + certificate->certificate_len)
        return;

      memcpy(certificate->certificate, handshake_payload,
             certificate->certificate_len);

      dtls_packet->parsed_handshake_payload.certificate = certificate;

      handle_certificate(peer->dtls_transport, certificate,
                         peer->parsed_remote_desc->fingerprint,
                         peer->parsed_remote_desc->fingerprint_type);

      break;
    case handshake_type_server_key_exchange:

      break;
    case handshake_type_certificate_request:
      printf("certificate request \n");
      struct CertificateRequest *certificate_request =
          malloc(sizeof(struct CertificateRequest));

      certificate_request->certificate_types_count =
          *((uint8_t *)handshake_payload);

      handshake_payload += sizeof(uint8_t);

      certificate_request->certificate_types =
          malloc(certificate_request->certificate_types_count);

      memcpy(certificate_request->certificate_types, handshake_payload,
             certificate_request->certificate_types_count);

      handshake_payload += certificate_request->certificate_types_count;

      certificate_request->signature_hash_algo_len =
          ntohs(*((uint16_t *)handshake_payload));
      handshake_payload += sizeof(uint16_t);

      certificate_request->signature_hash_algo =
          (uint16_t *)calloc(1, certificate_request->signature_hash_algo_len);

      memcpy(certificate_request->signature_hash_algo, handshake_payload,
             certificate_request->signature_hash_algo_len);

      uint16_t selected_sign_hash_algo = 0;
      for (int i = 0; i < certificate_request->signature_hash_algo_len / 2;
           i++) {
        if (selected_sign_hash_algo != 0)
          break;
        uint16_t i_sign_hash_algo =
            ntohs(certificate_request->signature_hash_algo[i]);

        for (int j = 0; j < sizeof(supported_signature_algorithms) /
                                sizeof(supported_signature_algorithms[0]);
             j++) {

          uint16_t j_supported_sign_algo = supported_signature_algorithms[j];

          // printf("%x %d %d %x \n", i_sign_hash_algo, i,
          //        certificate_request->signature_hash_algo_len,
          //        j_supported_sign_algo);
          //
          if (i_sign_hash_algo == j_supported_sign_algo) {

            selected_sign_hash_algo = i_sign_hash_algo;
            printf("slected signature algo %x \n", i_sign_hash_algo);
            break;
          }
        }
      }

      peer->dtls_transport->selected_signatuire_hash_algo =
          selected_sign_hash_algo;

      if (selected_sign_hash_algo == 0) {
        printf("no supported dtls singing hash algo \n");
        exit(0);
      }

      break;
    case handshake_type_server_hello_done:
      printf("server hello done \n");

      send_certificate(peer->dtls_transport);
      do_client_key_exchange(peer->dtls_transport);
      do_certificate_verify(peer->dtls_transport);
      do_change_cipher_spec(peer->dtls_transport);
      peer->dtls_transport->current_seq_no = 0;
      do_client_finished(peer->dtls_transport);

      printf("master %s\n ",
             BN_bn2hex(peer->dtls_transport->encryption_keys->master_secret));
      printf("client heloow %s\n ", BN_bn2hex(peer->dtls_transport->my_random));

      break;
    case handshake_type_finished:
      printf("\n -----------------------dtls connection "
             "sucssessfull---------------------------- \n");
    default:
      break;
    }

    dtls_packet = dtls_packet->next_record;
  }
}

void handle_server_hello(struct RTCDtlsTransport *transport,
                         struct DtlsServerHello *hello, struct llTVL *lltvl) {
  transport->current_flight_no = 1;
  transport->epoch = 0;

  transport->selected_cipher_suite = ntohs(hello->cipher_suite);
  set_cipher_suite_info(&transport->dtls_cipher_suite,
                        transport->selected_cipher_suite);

  BIGNUM *r2 = BN_new();
  BN_bin2bn(&hello->random[0], 32, r2);
  transport->peer_random = r2;

  do {
    switch (lltvl->type) {
    case SRTP_EXT:
      struct srtp_ext ext = parse_srtp_ext(lltvl->value, lltvl->len);
      printf("%x\n", ext.encryption_profile);
      set_cipher_suite_info(&transport->srtp_cipher_suite,
                            htons(ext.encryption_profile));
      break;
    case 0:
      break;
    default:
      break;
    }
    lltvl = lltvl->next_tvl;
  } while (lltvl != NULL);
}

gboolean compare_certificate_fingerprint(guchar *certificate,
                                         uint16_t certificate_len,
                                         gchar *expected_fingerprint,
                                         gchar *fingerprint_type) {
  GChecksumType type;
  if (strncmp(fingerprint_type, "sha-256", 7) == 0) {
    type = G_CHECKSUM_SHA256;
  }

  uint16_t checksum_len = g_checksum_type_get_length(type);
  GChecksum *checksum = g_checksum_new(type);
  g_checksum_update(checksum, certificate, certificate_len);
  const gchar *calculated_fingerprint = g_checksum_get_string(checksum);
  printf("calculated fingerpring from peer certificate %s\n",
         calculated_fingerprint);

  while (!(expected_fingerprint == '\0' || checksum_len == 0)) {
    if (expected_fingerprint[0] == ':') {
      expected_fingerprint++;
      continue;
    }
    if (tolower(calculated_fingerprint[0]) != tolower(expected_fingerprint[0]))
      return false;

    calculated_fingerprint++;
    expected_fingerprint++;
    checksum_len--;
  }

  if (checksum_len == 0)
    return true;
  else
    return false;
}

void handle_certificate(struct RTCDtlsTransport *transport,
                        struct Certificate *certificate,
                        gchar *expected_fingerprint, gchar *fingerprint_type) {
  X509 *cert;
  printf("%d\n", certificate->certificate_len);
  const guchar *ptr_certificate = certificate->certificate;
  cert = d2i_X509(NULL, (&ptr_certificate), certificate->certificate_len);

  if (!cert) {
    printf("unable to parse certificate\n");
    exit(0);
    return;
  }

  if (!compare_certificate_fingerprint(
          certificate->certificate, certificate->certificate_len,
          expected_fingerprint, fingerprint_type)) {
    printf("certificate in the SDP does not match the dtls certificate "
           "fingerprint "
           "exiting...\n");
    exit(0);
    return;
  }

  transport->server_certificate = cert;

  EVP_PKEY *pub_key = X509_get_pubkey(cert);

  transport->pub_key = pub_key;
}

void handle_certificate_request(
    struct RTCDtlsTransport *transport,
    struct CertificateRequest *certificate_request) {}

void send_alert() {}
void parse_dtls_alert() {}
struct DtlsServerHello *parse_server_hello(guchar *handshake_payload,
                                           uint32_t length,
                                           struct llTVL **pp_tlv) {
  if (length < sizeof(struct DtlsServerHello))
    return NULL;

  struct DtlsServerHello *server_hello = malloc(sizeof(struct DtlsServerHello));
  guchar *ptr = handshake_payload;

  server_hello->client_version = ntohs(*((uint16_t *)ptr));

  ptr = handshake_payload + sizeof(uint16_t);

  memcpy(server_hello->random, ptr, sizeof(server_hello->random));

  ptr += sizeof(server_hello->random);

  server_hello->session_id_len = *((uint8_t *)ptr);

  ptr += sizeof(uint8_t);

  if (ptr + server_hello->session_id_len - handshake_payload < 0)
    return NULL;

  server_hello->session_id = malloc(server_hello->session_id_len);

  memcpy(server_hello->session_id, ptr, server_hello->session_id_len);

  ptr += server_hello->session_id_len;

  server_hello->cipher_suite = ntohs(*(uint16_t *)ptr);
  ptr += sizeof(uint16_t);

  server_hello->compression_method = *(uint8_t *)ptr;
  ptr += sizeof(uint8_t);

  server_hello->extention_len = ntohs(*(uint16_t *)ptr);

  if ((ptr + server_hello->extention_len - handshake_payload) < 0)
    return NULL;

  server_hello->extentions = malloc(server_hello->extention_len);
  ptr += 2;
  memcpy(server_hello->extentions, ptr, server_hello->extention_len);

  guchar *extentions = (guchar *)server_hello->extentions;

  struct llTVL *tvl = malloc(sizeof(struct llTVL));
  *pp_tlv = tvl;

  for (int i = 0; i < server_hello->extention_len;) {
    uint16_t type = ntohs(*((uint16_t *)extentions));
    extentions = extentions + 2;
    uint16_t len = ntohs(*(uint16_t *)extentions);

    if ((extentions + len - handshake_payload) < 0)
      return NULL;

    extentions = extentions + 2;

    tvl->value = malloc(len);
    tvl->type = type;
    tvl->len = len;
    tvl->next_tvl = calloc(1, sizeof(struct llTVL));
    memcpy(tvl->value, extentions, len);

    tvl = tvl->next_tvl;

    i += (len + 4);
  }

  return server_hello;
}

uint32_t
get_client_certificate(guchar **certificate,
                       struct CertificateRequest *certificate_request) {
  // todo
  // check if we support these Certificae requete
  //
  guchar *my_rsa_public_cert_bin;
  uint32_t cert_509_len =
      hexstr_to_char_2(&my_rsa_public_cert_bin, my_rsa_public_cert);

  uint32_t certificate_len = cert_509_len + sizeof(struct Certificate);
  struct Certificate *client_certificate = malloc(certificate_len);

  memcpy(client_certificate->certificate, my_rsa_public_cert_bin, cert_509_len);

  uint32_t total_certificates_len = certificate_len;
  guchar *all_certificates = malloc(total_certificates_len + 3);

  uint32_t n_total_certificates_len = htonl(total_certificates_len) >> 8;
  client_certificate->certificate_len = htonl(cert_509_len) >> 8;

  memcpy(all_certificates, &n_total_certificates_len, 3);
  memcpy(all_certificates + 3, client_certificate, certificate_len);

  *certificate = all_certificates;

  return total_certificates_len + 3;
}
bool send_certificate(struct RTCDtlsTransport *transport) {
  guchar *certificate;
  uint32_t certificate_len = get_client_certificate(&certificate, NULL);

  send_dtls_packet(transport, handshake_type_certificate, certificate,
                   certificate_len);

  return true;
}
bool do_client_key_exchange(struct RTCDtlsTransport *transport) {
  uint16_t selected_cipher_suite = transport->selected_cipher_suite;
  // add better struct here

  if (selected_cipher_suite == cipher_suite_list[0]) { // rsa key change
    guchar *premaster_key;

    get_random_string(&premaster_key, 48, 1);

    uint16_t version = (uint16_t)htons(DTLS_1_2);
    memcpy(premaster_key, &version, sizeof(uint16_t));

    guchar *encrypted_premaster_key;

    uint16_t encrypted_key_len = encrypt_rsa(
        &encrypted_premaster_key, transport->pub_key, premaster_key, 48, -1);

    BIGNUM *master_secret = generate_master_key(
        premaster_key,
        get_dtls_rand_appended(transport->my_random, transport->peer_random));
    printf("master %s\n ", BN_bn2hex(master_secret));

    transport->encryption_keys->master_secret = master_secret;

    init_symitric_encryption(transport);

    struct ClientKeyExchange *client_key_xchange =
        malloc(sizeof(struct ClientKeyExchange) + encrypted_key_len);

    memcpy(client_key_xchange->encrypted_premaster_key, encrypted_premaster_key,
           encrypted_key_len);

    client_key_xchange->key_len = htons(encrypted_key_len);

    send_dtls_packet(transport, handshake_type_client_key_exchange,
                     (guchar *)client_key_xchange,
                     sizeof(struct ClientKeyExchange) + encrypted_key_len);
  } else {
    printf("only rsa key exchagge suported \n");
    return false;
  }
  return true;
}
bool do_change_cipher_spec(struct RTCDtlsTransport *transport) {

  guchar a = (gchar)1;
  send_dtls_packet(transport, handshake_type_change_cipher_spec, &a, 1);
  return true;
}

void store_concated_handshake_msgs(struct RTCDtlsTransport *transport,
                                   struct HandshakeHeader *handshake_header,
                                   guchar *payload, uint32_t payload_len,
                                   bool isfragmented) {
  struct ALLDtlsMessages *handshake_message =
      malloc(sizeof(struct ALLDtlsMessages));
  handshake_message->next_message = NULL;

  handshake_message->handshake_header = handshake_header;
  handshake_message->payload = payload;
  handshake_message->payload_len = payload_len;
  handshake_message->isfragmented = isfragmented;

  if (transport->all_previous_handshake_msgs == NULL) {
    transport->all_previous_handshake_msgs = handshake_message;
    return;
  }

  struct ALLDtlsMessages *last_message = transport->all_previous_handshake_msgs;
  while (last_message->next_message != NULL)
    last_message = last_message->next_message;

  last_message->next_message = handshake_message;
}

const gchar *compute_all_message_hash(struct RTCDtlsTransport *transport,
                                      bool for_finished_message,
                                      GChecksumType checksum_hash_algo) {

  printf("computing all message hash for verify certificate \n");
  if (!transport->selected_signatuire_hash_algo) {
    printf("no signature algorityhms selected\n");
    return 0;
  }

  struct ALLDtlsMessages *all_handshake_msgs =
      transport->all_previous_handshake_msgs;

  if (!all_handshake_msgs) {
    printf("no handshaekk mesage \n");
    exit(0);
  }

  GChecksum *checksum = g_checksum_new(checksum_hash_algo);

  while (all_handshake_msgs != NULL) {
    if (all_handshake_msgs->handshake_header == NULL)
      goto next_handshake_message;

    if (for_finished_message && all_handshake_msgs->isfragmented) {
      if (all_handshake_msgs->handshake_header->fragment_offset == 0) {

        all_handshake_msgs->handshake_header->fragment_offset = 0;
        all_handshake_msgs->handshake_header->fragment_length =
            all_handshake_msgs->handshake_header->length;
        goto update_handshake_header;
      }
    } else {
    update_handshake_header:

      g_checksum_update(checksum,
                        (guchar *)all_handshake_msgs->handshake_header,
                        sizeof(struct HandshakeHeader));
      g_debug("appeding handshake header of type :%d\n",
              all_handshake_msgs->handshake_header->type);
      print_hex(all_handshake_msgs->handshake_header,
                sizeof(struct HandshakeHeader));
    }

    uint32_t payload_len = all_handshake_msgs->payload_len;
    g_debug("appending paylaod of type %d len %d\n",
            all_handshake_msgs->handshake_header->type, payload_len);

    if (payload_len) {
      g_checksum_update(checksum, (guchar *)all_handshake_msgs->payload,
                        payload_len);
      // print_hex(all_handshake_msgs->payload, payload_len);
    }

  next_handshake_message:
    all_handshake_msgs = all_handshake_msgs->next_message;
  }

  printf("\nend \n");
  return g_checksum_get_string(checksum);
}

bool do_certificate_verify(struct RTCDtlsTransport *transport) {
  // RSA sha256

  if (transport->selected_signatuire_hash_algo ==
      supported_signature_algorithms[0]) {

    gchar *all_msgs_hash =
        (gchar *)compute_all_message_hash(transport, true, G_CHECKSUM_SHA256);

    printf("\nall msg hash %s\n", all_msgs_hash);
    guchar *all_msgs_hash_bin;
    uint32_t hash_len = hexstr_to_char_2(&all_msgs_hash_bin, all_msgs_hash);

    guchar *encrypted_hash;
    uint16_t encrypte_hash_len =
        encrypt_rsa(&encrypted_hash, transport->my_private_key,
                    all_msgs_hash_bin, hash_len, G_CHECKSUM_SHA256);

    uint16_t cert_verify_size =
        sizeof(struct CertificateVerify) + encrypte_hash_len;
    struct CertificateVerify *certificate_verify = malloc(cert_verify_size);

    certificate_verify->signature_algorithms =
        htons(transport->selected_signatuire_hash_algo);

    certificate_verify->signature_len = htons(encrypte_hash_len);
    memcpy(certificate_verify->signature, encrypted_hash, encrypte_hash_len);

    send_dtls_packet(transport, handshake_type_certificate_verify,
                     (guchar *)certificate_verify, cert_verify_size);

    return true;
  } else {
    printf("signature algorithm not supported \n");
  }

  return false;
}
void encrypt_dtls(guchar *block) {}

bool do_client_finished(struct RTCDtlsTransport *transport) {

  transport->epoch = htons(1);

  const gchar *all_message_hash =
      compute_all_message_hash(transport, true, G_CHECKSUM_SHA256);

  BIGNUM *all_message_hash_bn = BN_new();
  BN_hex2bn(&all_message_hash_bn, all_message_hash);

  guchar *verify_data =
      PRF(transport->encryption_keys->master_secret, "client finished",
          all_message_hash_bn, G_CHECKSUM_SHA256, 12);

  printf("prf dtls finish message verify data  \n");
  print_hex(verify_data, 12);
  send_dtls_packet(transport, handshake_type_finished, verify_data, 12);

  return true;
}
