
#pragma once
#include <stdint.h>
#ifndef _NETWORKH_
#define _NETWORKH_

#include "../RTP/rtp.h"
#include "../STUN/stun.h"
#include "../WebRTC/webrtc.h"
#include <arpa/inet.h>
#include <glib.h>
#include <poll.h>
#include <sched.h>
#include <sys/socket.h>

enum packet_protocol { STUN, DTLS, RTP, RTCP };
enum subtype { BINDING_REQUEST, BINDING_RESPONSE };

struct sockaddr_in *get_network_socket(char *ip, int port);
union header {
  struct Stun *stun_header;
  struct DtlsHeader *dtls_header;
  struct Rtp *rtp_header;
};
union payload {
  struct StunPayload *stun_payload;
  struct DtlsParsedPacket *dtls_parsed;
};

struct NetworkPacket {
  char *sender_ip;
  char *receiver_ip;
  uint16_t *sender_port;
  uint16_t *receiver_port;
  union header header;
  union payload payload;
  enum packet_protocol protocol;
  enum subtype subtype;
  int sock_desc;
  size_t sock_len;
  struct sockaddr *sender_sock;
  struct sockaddr *receiver_sock;
  uint16_t total_bytes_recvied;
};
char *get_ip_str(const struct sockaddr *sa, char *s_ip, uint16_t *port,
                 size_t maxlen);
int get_udp_sock_desc();
void *packet_listner_thread(void *peer_v);

bool check_if_stun(struct Stun *stun_header);
struct NetworkPacket *get_parsed_packet(struct RTCDtlsTransport *dtls_transport,
                                        guchar *packet, uint32_t bytes);
int get_candidates_fd_array(struct RTCPeerConnection *peer,
                            struct pollfd **candidate_fd);
uint32_t hton24(uint32_t host24);
#endif // !_NETWORKH_
