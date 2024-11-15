#include "network.h"
#include "../DTLS/dtls.h"
#include "../STUN/stun.h"
#include "../Utils/utils.h"
#include <arpa/inet.h>
#include <assert.h>
#include <bits/pthreadtypes.h>
#include <glib.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#pragma pack(1)
struct sockaddr_in *get_network_socket(char *ip, int port) {

  struct sockaddr_in *socket_address;
  socket_address = malloc(sizeof(struct sockaddr_in));
  socket_address->sin_family = AF_INET; // ipv4 by defalult
  socket_address->sin_port = htons(port);
  socket_address->sin_addr.s_addr =
      ip != NULL ? inet_addr(ip) : htonl(INADDR_ANY);

  return socket_address;
}

int get_udp_sock_desc() {
  int socket_desc = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (socket_desc < 0) {
    printf("Error while creating socket\n");
    return -1;
  }
  return socket_desc;
}

char *get_ip_str(const struct sockaddr *sa, char *s_ip, uint16_t *port,
                 size_t maxlen) {
  switch (sa->sa_family) {
  case AF_INET:
    struct sockaddr_in *sin = (struct sockaddr_in *)sa;
    if (s_ip != NULL) {
      inet_ntop(AF_INET, &sin->sin_addr, s_ip, maxlen);
    }
    if (port != NULL)
      *port = htons(sin->sin_port);
    break;

  case AF_INET6:
    inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)sa)->sin6_addr), s_ip,
              maxlen);
    break;

  default:
    strncpy(s_ip, "Unknown AF", maxlen);
    return NULL;
  }

  return s_ip;
}

// todo: change here to support diffrent bundle policy make thread argument more
// robust
void *packet_listner_thread(void *peer_v) {
  struct RTCPeerConnection *peer = (struct RTCPeerConnection *)peer_v;
  uint16_t sport;
  uint16_t rport;
  char sender_ip[20];
  char recv_ip[20];
  guchar udp_packet[1000];
  socklen_t socklen = sizeof(struct sockaddr_in);

  struct sockaddr *sender_addr = malloc(sizeof(struct sockaddr));
  struct sockaddr *receiver_addr = malloc(sizeof(struct sockaddr));

  if (peer->transceiver == NULL &&
      peer->transceiver->local_ice_candidate == NULL) {
    printf("something went wrong  null");
    exit(0);
    return 0;
  }
  struct pollfd *candidates_fds;
  int candidate_list_size = get_candidates_fd_array(peer, &candidates_fds);

  send_stun_bind(NULL, STUN_REQUEST_CLASS,
                 peer->transceiver->local_ice_candidate, NULL);

  while (poll(candidates_fds, candidate_list_size, -1) != -1) {
    for (int poll_index = 0; poll_index < candidate_list_size; poll_index++) {

      if (!((candidates_fds + poll_index)->revents & POLL_IN)) {
        continue;
      }

      int sock_desc = (candidates_fds + poll_index)->fd;
      uint32_t bytes =
          recvfrom(sock_desc, udp_packet, 1000, 0, sender_addr, &socklen);

      if (bytes == -1)
        printf("error something went wrong when reciving stun response %d",
               errno);

      struct NetworkPacket *packet =
          get_parsed_packet(peer->dtls_transport, udp_packet, bytes);

      if (!packet) {
        printf("packet detected a NULL\n");
        continue;
      }
      getsockname(sock_desc, receiver_addr, &socklen);
      packet->receiver_sock = receiver_addr;

      get_ip_str(sender_addr, sender_ip, &sport, socklen);
      get_ip_str((struct sockaddr *)receiver_addr, recv_ip, &rport, socklen);

      packet->sender_ip = sender_ip;
      packet->receiver_ip = recv_ip;
      packet->sender_port = &sport;
      packet->receiver_port = &rport;
      packet->sock_desc = sock_desc;
      packet->sock_len = socklen;

      packet->sender_sock = sender_addr;
      packet->receiver_sock = receiver_addr;
      packet->total_bytes_recvied = bytes;

      if (packet->protocol == STUN) {
        printf("recived stun packet \n");
        on_stun_packet(packet, peer);
      } else if (packet->protocol == DTLS) {

        // printf("%d aa\n", packet->total_bytes_recvied);
        // print_hex(packet, packet->total_bytes_recvied);
        on_dtls_packet(packet, peer);
      } else if (packet->protocol == RTP) {
        // parse RTP packet
      } else if (packet->protocol == RTCP) {
        // parse RTCP packet
      }
    }
  }
  return 0;
}
struct NetworkPacket *get_parsed_packet(struct RTCDtlsTransport *dtls_transport,
                                        guchar *packet, uint32_t bytes) {

  // check if its a STUN
  struct NetworkPacket *network_packet = malloc(sizeof(struct NetworkPacket));
  struct Stun *stun = (struct Stun *)malloc(sizeof(struct Stun));
  memcpy(stun, packet, sizeof(struct Stun));
  network_packet->total_bytes_recvied = bytes;

  if (check_if_stun(stun)) {
    network_packet->protocol = STUN;
    network_packet->header.stun_header = stun;
    // class request 00 indication 01 success response 10 error 11
    // method binding 01  response 10
    int class = stun->msg_type & 0x110;
    int method = stun->msg_type & 0x3EEF;

    if (class == STUN_RESPONSE_CLASS && method == STUN_BINDING_METHOD) {
      printf("recived stun binding response \n");
      network_packet->subtype = BINDING_RESPONSE;

      struct StunPayload *stun_respose_payload =
          malloc(sizeof(struct StunPayload));
      int stun_header_size = sizeof(struct Stun);

      memcpy(stun_respose_payload,
             packet + stun_header_size + sizeof(struct TVL),
             sizeof(struct StunPayload));

      network_packet->payload.stun_payload = stun_respose_payload;

      uint32_t magic = STUN_MAGIC_COOKIE;

      uint16_t mapped_port =
          (ntohs(stun_respose_payload->x_port) ^
           ((uint16_t)(ntohs(stun->magic_cookie)))); // port and ip is sotred
                                                     // xored with the cookie
      uint32_t mapped_ip = ntohl(ntohl(stun_respose_payload->x_ip) ^ (magic));

      stun_respose_payload->x_ip = mapped_ip;
    }

    if (class == STUN_REQUEST_CLASS && method == STUN_BINDING_METHOD) {
      printf("\n received stun binding request");
      network_packet->subtype = BINDING_REQUEST;
    }

    // if (class == method ==) {
    // }

    return network_packet;
  }

  uint8_t first_byte = packet[0];

  if (check_if_dtls(first_byte)) {
    printf("dtls packet \n");
    network_packet->protocol = DTLS;

    struct DtlsParsedPacket *dtls_packet =
        calloc(1, sizeof(struct DtlsParsedPacket));
    network_packet->payload.dtls_parsed = dtls_packet;

    uint32_t remaining_bytes = bytes;

    uint16_t dtls_header_size = sizeof(struct DtlsHeader);
    while (remaining_bytes > 0) {

      if (remaining_bytes < dtls_header_size) {
        printf("%d rem\n", remaining_bytes);
        exit(0);
        return NULL;
      }
      struct DtlsHeader *dtls_header = malloc(dtls_header_size);
      dtls_packet->dtls_header = dtls_header;
      memcpy(dtls_header, packet, dtls_header_size);
      dtls_header->length = ntohs(dtls_header->length);
      dtls_header->epoch = htons(dtls_header->epoch);

      remaining_bytes = remaining_bytes - dtls_header_size;
      packet = packet + dtls_header_size;

      if (dtls_header->epoch) {
        if (dtls_transport->dtls_ctx != NULL) {

          dtls_header->length =
              decrypt_dtls(dtls_transport, &packet, dtls_header->length);
          remaining_bytes = dtls_header->length; // fix here

        } else
          g_error("recived encrypted packet but dtls context is null");
      }

      if (dtls_header->type != 22) {

        uint16_t header_paylod_size = dtls_header->length;

        if (remaining_bytes < header_paylod_size) {
          return NULL;
        }
        remaining_bytes = remaining_bytes - header_paylod_size;
        dtls_packet->payload = malloc(header_paylod_size);
        memcpy(dtls_packet->payload, packet, header_paylod_size);
        packet = packet + header_paylod_size;

        goto next_record;
      }

      struct HandshakeHeader *handshake_header =
          malloc(sizeof(struct HandshakeHeader));

      uint16_t handshake_header_size = sizeof(struct HandshakeHeader);
      if (remaining_bytes < handshake_header_size)
        return NULL;

      memcpy(handshake_header, packet, handshake_header_size);
      remaining_bytes = remaining_bytes - handshake_header_size;
      dtls_packet->handshake_header = handshake_header;
      dtls_packet->handshake_type = handshake_header->type;

      uint32_t fragment_len =
          ntohl((uint32_t)handshake_header->fragment_length) >> 8;
      uint32_t length = ntohl((uint32_t)handshake_header->length) >> 8;
      uint32_t fragment_offset =
          ntohl((uint32_t)handshake_header->fragment_offset) >> 8;

      if (fragment_len != length) {
        dtls_packet->isfragmented = true;
        uint16_t total_recvied_len = fragment_offset + fragment_len;
        if (total_recvied_len == length)
          dtls_packet->islastfragment = true;
        else
          dtls_packet->islastfragment = false;
      } else {
        dtls_packet->isfragmented = false;
        dtls_packet->islastfragment = false;
      }

      packet = packet + handshake_header_size;

      if (remaining_bytes != 0 && remaining_bytes >= fragment_len) {

        if (length < fragment_offset + fragment_len) {

          return NULL;
        }

        dtls_packet->handshake_payload = malloc(length);

        memcpy(dtls_packet->handshake_payload, packet, fragment_len);

        packet = packet + fragment_len;
        remaining_bytes = remaining_bytes - fragment_len;
      }
    next_record:

      if (remaining_bytes >= dtls_header_size) {
        dtls_packet->next_record = calloc(1, sizeof(struct DtlsParsedPacket));
        dtls_packet = dtls_packet->next_record;
      }
      if (remaining_bytes == 0) {
        return network_packet;
      }
    }

    return NULL;
  }

  if (false) { // check if rtp or rtcp
  }
  // check if RTP RTCP
  return NULL;
}

int get_candidates_fd_array(struct RTCPeerConnection *peer,
                            struct pollfd **candidate_fd) {
  if (peer == NULL || peer->transceiver == NULL)
    return 0;
  struct pollfd *fd_array = malloc(sizeof(struct pollfd) * 10);
  struct pollfd *i = fd_array;
  int size = 10;

  for (struct RTCRtpTransceivers *transceiver = peer->transceiver;
       transceiver != NULL; transceiver = transceiver->next_trans) {
    for (struct RTCIecCandidates *candidate = transceiver->local_ice_candidate;
         candidate != NULL; candidate = candidate->next_candidate) {
      if ((fd_array + size) == i) {
        fd_array = realloc(fd_array, sizeof(struct pollfd) * size +
                                         sizeof(struct pollfd) * 10);
        size = size + 10;
      }
      struct pollfd *fd = malloc(sizeof(struct pollfd));
      fd->fd = candidate->sock_desc;
      fd->events = POLL_IN;

      *i = *fd;
      i++;
    }
    if (BUNDLE_MAX_BUNDLE) { // compare webrtc config param todo
      break;
    }
  }
  *candidate_fd = fd_array;

  return i - fd_array;
}

uint32_t hton24(uint32_t host24) {
  host24 &= 0xFFFFFF;

  uint8_t byte1 = (host24 >> 16) & 0xFF;
  uint8_t byte2 = (host24 >> 8) & 0xFF;
  uint8_t byte3 = host24 & 0xFF;

  return (byte1 << 16) | (byte2 << 8) | byte3;
}
