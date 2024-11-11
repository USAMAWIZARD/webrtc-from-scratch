#include "ice.h"
#include "../Network/network.h"
#include "../STUN/stun.h"
#include "../Utils/utils.h"
#include "../WebRTC/webrtc.h"
#include "glib.h"
#include <arpa/inet.h>
#include <assert.h>
#include <bits/pthreadtypes.h>
#include <ifaddrs.h>
#include <math.h>
#include <net/if.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
//    candidate-attribute   = "candidate" ":" foundation SP component-id SP
//                            transport SP
//                            priority SP
//                            connection-address SP     ;from RFC 4566
//                            port         ;port from RFC 4566
//                            SP cand-type
//                            [SP rel-addr]
//                            [SP rel-port]
//                            *(SP extension-att-name SP
//                                 extension-att-value)
// candidate:2764676115 1 udp 2122194687 192.168.0.110 37515 typ host generation
// 0 ufrag 0KCc network-id 2 network-cost 10

bool parse_ice_candidate(struct RTCIecCandidates *candidate) {

  if (candidate == NULL) {
    return false;
  }

  candidate->id = rand();

  if (candidate->candidate == NULL ||
      g_strcmp0(candidate->candidate, "") == 0) {
    char *candidate_str;

    candidate_str = g_strdup_printf(
        "candidate:%d %d %s %d %s %d typ %s generation 0 ufrag %s",
        candidate->foundation, candidate->component_id, "udp",
        candidate->priority, candidate->address, candidate->port,
        candidate->type, "H0Tz");
    candidate->candidate = candidate_str;
    return true;
  }

  char *candidate_cpy = strdup(candidate->candidate);
  char *candidate_colon = strtok(candidate_cpy, ":");
  if (candidate_colon == NULL ||
      strncmp(candidate_colon, "candidate:", 10) == 0)
    return false;

  char *foundation = strtok(0, " ");
  if (foundation == NULL)
    return false;
  candidate->foundation = atoi(foundation);

  char *component_id = strtok(0, " ");
  if (component_id == NULL)
    return false;
  candidate->component_id = atoi(component_id);

  char *transport = strtok(0, " ");
  if (transport == NULL)
    return false;
  candidate->transport = transport;

  char *priority = strtok(0, " ");
  if (priority == NULL)
    return false;
  candidate->priority = atoi(priority);

  char *address = strtok(0, " ");
  if (address == NULL)
    return false;
  candidate->address = address;

  char *port = strtok(0, " ");
  if (port == NULL)
    return false;
  candidate->port = atoi(port);

  char *type = strtok(0, " ");
  type = strtok(0, " ");
  if (type == NULL)
    return false;
  candidate->type = type;

  if (strncmp(type, "srflx", 5) == 0) {
    char *raddr = strtok(0, " ");
    raddr = strtok(0, " ");
    if (raddr == NULL)
      return true;
    candidate->raddr = raddr;

    char *rport = strtok(0, " ");
    rport = strtok(0, " ");
    if (rport == NULL)
      return true;
    candidate->rport = atoi(rport);
  }
  candidate->ufrag = NULL;

  char *ufrag = strtok(0, " ");
  while (ufrag != NULL) {
    if (g_strcmp0(ufrag, "ufrag") == 0) {
      ufrag = strtok(0, " ");
      candidate->ufrag = ufrag;
      return true;
    }
    ufrag = strtok(0, " ");
  }
  return true;
}

char *get_candidate_string(int foundation, int component_id, int priority,
                           char *ip, int port, char *candidate_type) {

  char *candidate;
  candidate = g_strdup_printf(
      "candidate:%d %d %s %d %s %d typ %s generation 0 ufrag %s", foundation,
      component_id, "udp", priority, ip, port, candidate_type, "H0Tz");

  return candidate;
}

// not posix complient support ipv4
char *get_running_NIC_IP(struct ifaddrs **network_interface) {

  while (*network_interface != NULL) {
    char *ip = malloc(16);

    ip = get_ip_str((*network_interface)->ifa_addr, ip, NULL,
                    sizeof(struct sockaddr));
    unsigned int nic_status = (*network_interface)->ifa_flags;

    bool is_running = ((nic_status & IFF_RUNNING) == IFF_RUNNING) &&
                      ((nic_status & IFF_LOOPBACK) != IFF_LOOPBACK);
    if ((*network_interface)->ifa_addr->sa_family == AF_INET6 || ip == NULL ||
        !is_running) {

      *network_interface = (*network_interface)->ifa_next;
      continue;
    }

    *network_interface = (*network_interface)->ifa_next;
    return ip;
  }

  return NULL;
}
struct RTCRtpTransceivers *get_transceiver(struct RTCRtpTransceivers *trans,
                                           int mid) {
  for (; trans != NULL && trans->mid != mid; trans = trans->next_trans) {

    printf("---------------------------------------\n");
  }

  return trans;
}
void add_local_icecandidate(struct RTCPeerConnection *peer,
                            struct RTCIecCandidates *candidate) {
  void (*on_ice_candidate_callback)(struct RTCPeerConnection *,
                                    struct RTCIecCandidates *) =
      peer->on_ice_candidate;
  if (candidate == NULL)
    goto nullcandidate;

  struct RTCRtpTransceivers *transceiver = peer->transceiver;

  transceiver = get_transceiver(transceiver, candidate->sdpMid);
  if (transceiver == NULL) {
    return;
  }

  transceiver->local_ice_password = "HXeKrqNxtoH7MLYV/gQXytWJ";
  transceiver->local_ice_ufrag = candidate->ufrag;

  if (transceiver->local_ice_candidate == NULL) {
    transceiver->local_ice_candidate = candidate;
    transceiver->local_ice_candidate->next_candidate = NULL;
  } else {
    struct RTCIecCandidates *last_candidate;
    for (last_candidate = transceiver->local_ice_candidate;
         last_candidate->next_candidate != NULL;
         last_candidate = last_candidate->next_candidate) {
    }
    candidate->next_candidate = NULL;
    last_candidate->next_candidate = candidate;
  }

  printf("---------added local candidate added %s://%s:%d----------\n",
         candidate->transport, candidate->address, candidate->port);
nullcandidate:
  if (on_ice_candidate_callback != NULL)
    on_ice_candidate_callback(peer, candidate);
}
// can have seprate ports to support diffrent bundle policies
// eatch stream should have its own ice candidate
void gather_ice_candidate(struct RTCPeerConnection *peer) {

  peer->ice_connection_state = ICE_GATHRING;
  struct ifaddrs *all_network_interface;

  getifaddrs(&all_network_interface);

  if (all_network_interface < 0) {
    printf("something went wrong when gathring candidates");
    exit(0);
  }

  char *local_ip;
  int priority = 0xFFFF;
  int foundation = 42322;
  int component_id = 1; // rtp 1 rtcp 2 both muxed 1
  int port = 5020;
  char *candidate_type = "host";
  char *candidate;
  char *ufrag = "H0Tz";

  struct RTCIecCandidates *local_ice_candidate;

  // host candidates
  while ((local_ip = get_running_NIC_IP(&all_network_interface)) != NULL) {
    local_ice_candidate = calloc(1, sizeof(struct RTCIecCandidates));

    local_ice_candidate->foundation = foundation;
    local_ice_candidate->port = port;
    local_ice_candidate->address = local_ip;
    local_ice_candidate->type = candidate_type;
    local_ice_candidate->component_id = 1;
    local_ice_candidate->sdpMid = 0;
    local_ice_candidate->candidate = "";
    local_ice_candidate->transport = "udp";
    local_ice_candidate->sock_desc = get_udp_sock_desc();
    local_ice_candidate->src_socket = get_network_socket(local_ip, port);
    local_ice_candidate->ufrag = ufrag;
    local_ice_candidate->password = "HXeKrqNxtoH7MLYV/gQXytWJ";
    local_ice_candidate->priority =
        (int)pow(2, 24) * (get_type_pref(candidate_type)) +
        (int)pow(2, 8) *
            (1) // can add option to give more pref to wired set 1 for now
        + (int)pow(2, 0) * (256 - component_id);

    if (bind(local_ice_candidate->sock_desc,
             (struct sockaddr *)local_ice_candidate->src_socket,
             sizeof(*local_ice_candidate->src_socket)) < 0) {
      perror("binding ip for stun failed");
    }

    if (parse_ice_candidate(local_ice_candidate))
      add_local_icecandidate(peer, local_ice_candidate);
    else
      printf("failed to parse ice candidate");

    // listen_for_handshake(local_ip, port);
    priority--;
  }

  pthread_t *pkt_listener_t;
  pkt_listener_t = malloc(sizeof(pthread_t));
  peer->listener_thread_id = pkt_listener_t;

  pthread_create(pkt_listener_t, NULL, &packet_listner_thread, (void *)peer);

  // Empty candidate to signal ICE gathring completion
  add_local_icecandidate(peer, NULL);

  return;
}
// incomplete
void add_candidate_for_each_transiver(
    struct RTCPeerConnection *peer, struct RTCIecCandidates *local_candidate) {
  for (struct RTCRtpTransceivers *transceiver = peer->transceiver;
       transceiver != NULL; transceiver = transceiver->next_trans) {

    add_local_icecandidate(peer, local_candidate);
  }
}

// void listen_for_ice_handshake(struct RTCRtpTransceivers *transceiver ,struct
// RTCIecCandidates *local_candidate,struct RTCIecCandidates *remote_candidate)
// {
//   listen_for_ice_handshake() {
//     if (stun_request)
//       sendresponse() if (response) {}
//   }
// }
bool check_pair_compatiblity(struct RTCRtpTransceivers *transceiver,
                             struct RTCIecCandidates *local_candidate,
                             struct RTCIecCandidates *remote_candidate) {

  if (transceiver == NULL || local_candidate == NULL ||
      remote_candidate == NULL)
    return false;

  // check if already exist
  for (struct CandidataPair *checklist = transceiver->pair_checklist;
       checklist != NULL; checklist = checklist->next_pair) {
    if ((local_candidate->id ^ remote_candidate->id) == checklist->xored_id) {
      // printf(" already exist candidate pair  \n");
      return false;
    }
  }

  if (strcicmp(local_candidate->transport, remote_candidate->transport) == 0) {
    return true;
  }
  return false;
}
// return true if new pair made
bool make_pair(struct RTCRtpTransceivers *transceiver,
               struct RTCIecCandidates *rcandidate) {
  bool newpairmade = false;

  for (struct RTCIecCandidates *lcandidate = transceiver->local_ice_candidate;
       lcandidate != NULL; lcandidate = lcandidate->next_candidate) {
    // printf("try to pair candidate  %s://%s:%d  %s://%s:%d \n",
    //        lcandidate->transport, lcandidate->address, lcandidate->port,
    //        rcandidate->transport, rcandidate->address, rcandidate->port);
    if (check_pair_compatiblity(transceiver, lcandidate, rcandidate)) {
      struct CandidataPair *candidate_pair =
          calloc(1, sizeof(struct CandidataPair));
      candidate_pair->p0 = lcandidate;
      candidate_pair->p1 = rcandidate;
      candidate_pair->isvalid = false;
      candidate_pair->state = ICE_PAIR_WAITING;
      candidate_pair->xored_id = lcandidate->id ^ rcandidate->id;

      strncpy(candidate_pair->transaction_id, g_uuid_string_random(), 12);

      printf("---------\n new candidate pair made for trans%d %s://%s:%d  "
             "%s://%s:%d ----------\n",
             transceiver->mid, candidate_pair->p0->transport,
             candidate_pair->p0->address, candidate_pair->p0->port,
             candidate_pair->p1->transport, candidate_pair->p1->address,
             candidate_pair->p1->port);

      if (transceiver->pair_checklist == NULL) {
        transceiver->pair_checklist = candidate_pair;
      } else {
        struct CandidataPair *endlist = transceiver->pair_checklist;
        for (; endlist->next_pair != NULL; endlist = endlist->next_pair)
          ;
        endlist->next_pair = candidate_pair;
      }
      newpairmade = true;
    }
  }
  return newpairmade;
}
guint make_candidate_pair(struct args *arg) {
  struct RTCIecCandidates *candidate = arg->candidate;
  struct RTCRtpTransceivers *transceiver = arg->transceiver;
  if (candidate == NULL || transceiver == NULL) {
    return false;
  }
  make_pair(transceiver, candidate);
  return true;
}
// todo make this rfc complient by incorporating proper timer and priority
// mechenism
guint do_ice_handshake(struct RTCPeerConnection *peer) {

  for (struct RTCRtpTransceivers *transceiver = peer->transceiver;
       transceiver != NULL; transceiver = transceiver->next_trans)
    for (struct CandidataPair *pair = transceiver->pair_checklist; pair != NULL;
         pair = pair->next_pair) {
      pair->p1->password = transceiver->remote_ice_password;
      pair->p1->ufrag = transceiver->remote_ice_ufrag;

      send_stun_bind(pair, STUN_REQUEST_CLASS, NULL, NULL);

      printf("\n ice handshake request sent form %s://%s:%d to %s://%s:%d\n",
             pair->p0->transport, pair->p0->address, pair->p0->port,
             pair->p1->transport, pair->p1->address, pair->p1->port);

      if (pair->state == ICE_PAIR_WAITING) {
        pair->state = ICE_PAIR_INPROGRESS;
        return 0;
      }
    }
  return true;
}
void ice_handshake_ended(struct RTCIecCandidates *local_candidate,
                         struct RTCIecCandidates *remote_candidate) {

  printf("\nice handchake ended  for candididate pair %s:%d \n", "asf", 213);
}
int get_type_pref(char *candidate_type) {
  if (g_strcmp0(candidate_type, HOST_CANDIDATE) == 0) {
    return 126;
  }
  if (g_strcmp0(candidate_type, PRFLX_CANDIDATE) == 0) {
    return 93;
  }
  if (g_strcmp0(candidate_type, SRFLX_CANDIDATE) == 0) {
    return 62;
  }
  if (g_strcmp0(candidate_type, RELAY_CANDIDATE) == 0) {
    return 31;
  }
  return 0;
}
