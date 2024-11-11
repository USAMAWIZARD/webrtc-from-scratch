#include "./webrtc.h"
#include "../DTLS/dtls.h"
#include "../ICE/ice.h"
#include "../Network/network.h"
#include "../SDP/sdp.h"
#include "glib-object.h"
#include "glib.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct RTCPeerConnection *NEW_RTCPeerConnection() {
  struct RTCPeerConnection *peer =
      (struct RTCPeerConnection *)calloc(1, sizeof(struct RTCPeerConnection));
  peer->signalling_state = STABLE;
  peer->dtls_transport = create_dtls_transport();
  if (peer == NULL) {
    perror("Failed to allocate memory for RTCPeerConnection");
    return NULL;
  }
  return peer;
}

struct MediaStreamTrack *NEW_MediaTrack(char *kind, char *label,
                                        void *get_data_callback,
                                        void *userdata) {
  struct MediaStreamTrack *track =
      (struct MediaStreamTrack *)malloc(sizeof(struct MediaStreamTrack));
  track->get_data_callback = get_data_callback;
  track->kind = kind;
  track->label = label;
  track->next_track = NULL;
  track->id = "random trackid";
  track->userdata = userdata;
  return track;
}

bool add_track(struct RTCPeerConnection *peer, struct MediaStreamTrack *track) {
  if (peer->media_tracks == NULL) {
    peer->media_tracks = track;
    printf("New Track Added to WebRTC Session id:%s Kind: %s Label: %s\n",
           track->id, track->kind, track->label);
    track->rtp_stream = create_rtp_stream(NULL, track, 0xdeadbeef, 102);

    add_transceivers(peer, peer->media_tracks);
  } else {
    peer->media_tracks->next_track = track;
  }
  return true;
}

struct RTCRtpTransceivers *add_transceivers(struct RTCPeerConnection *peer,
                                            struct MediaStreamTrack *track) {
  struct RTCRtpTransceivers *transceiver = peer->transceiver;
  if (transceiver != NULL)
    for (; transceiver->next_trans != NULL;
         transceiver = transceiver->next_trans)
      ;

  struct RTCRtpTransceivers *new_transceiver =
      calloc(1, sizeof(struct RTCRtpTransceivers));
  new_transceiver->mid = transceiver != NULL ? transceiver->mid + 1 : 0;
  new_transceiver->direction = SEND_RECV;
  new_transceiver->next_trans = NULL;

  struct Transport *sender = calloc(1, sizeof(struct Transport));
  sender->track = track;
  sender->state = TRANSPORT_STATE_NEW;
  new_transceiver->sender = sender;

  if (peer->transceiver == NULL) {
    peer->transceiver = new_transceiver;
  } else {
    transceiver->next_trans = new_transceiver;
  }

  return transceiver;
}

struct RTCSessionDescription *create_offer(struct RTCPeerConnection *peer) {
  struct RTCRtpTransceivers *transceiver = peer->transceiver;
  peer->ice_role = ICE_AGENT_CONTROLLING;

  char *offer_constants = get_sdp_constants();
  printf("%s", offer_constants);
  char *transceiver_sdp = "";
  if (peer->current_remote_desc != NULL) {
    // generate a maching description
    //
  } else {
    if (peer->transceiver != NULL) {
      transceiver_sdp = generate_unmached_desc(peer->transceiver);
    }
  }

  return NULL;
}

struct RTCSessionDescription *
create_answer(struct RTCSessionDescription *peer) {

  return NULL;
}
void set_local_description(struct RTCPeerConnection *peer,
                           struct RTCSessionDescription *sdp) {
  // icreated the offer
  // imporove spegetti
  if (peer == NULL || sdp == NULL)
    return;

  bool is_offer = strncmp(sdp->type, SDP_TYPE_OFFER, 4) == 0;
  bool is_answer = strncmp(sdp->type, SDP_TYPE_ANSWER, 5) == 0;
  if ((is_offer && peer->signalling_state == HAVE_REMOTE_OFFER) ||
      (is_answer && peer->signalling_state == HAVE_REMOTE_ANSWER)) {
    printf("set local desc called in wrong state");
    return;
  }

  if (is_offer) {
    peer->signalling_state = HAVE_LOCAL_OFFER;
  } else if (is_answer) {
    peer->signalling_state = HAVE_LOCAL_ANSWER;
  }
  peer->current_local_desc = sdp;

  gather_ice_candidate(peer);
}
bool set_remote_discription(struct RTCPeerConnection *peer,
                            struct RTCSessionDescription *sdp) {

  if (peer == NULL || peer->transceiver == NULL) {
    printf("set remote description failed not a valid state :\n");
    return false;
  }
  // if its answer then I should be in have  local offer state
  // imporve this spegetti
  //
  if ((strncmp(sdp->type, SDP_TYPE_ANSWER, 6) == 0 &&
       peer->signalling_state == HAVE_LOCAL_OFFER) ||
      (strncmp(sdp->type, SDP_TYPE_OFFER, 4) == 0 &&
       (peer->signalling_state == STABLE ||
        peer->signalling_state == HAVE_LOCAL_OFFER))) {

    parse_sdp_string(peer, sdp);
  } else {
    printf("set remote description  called in wrong state: %d\n",
           peer->signalling_state);
    return false;
  }
  peer->current_remote_desc = sdp;
  g_timeout_add_full(G_PRIORITY_HIGH, 499, (GSourceFunc)do_ice_handshake, peer,
                     (GDestroyNotify)ice_handshake_ended);
  return true;
}
// remote ice
void add_ice_candidate(struct RTCPeerConnection *peer,
                       struct RTCIecCandidates *candidate) {

  if (candidate == NULL) {
    // signal remote ice gathering compleated
    return;
  }

  if (!parse_ice_candidate(candidate)) {
    printf("failed to parse remote ice ");
    return;
  }

  candidate->src_socket =
      get_network_socket(candidate->address, candidate->port);
  struct RTCRtpTransceivers *transceiver =
      get_transceiver(peer->transceiver, candidate->sdpMid);

  printf("\n----------added remote candidate %s://%s:%d-------------\n",
         candidate->transport, candidate->address, candidate->port);
  if (transceiver == NULL)
    return;

  if (transceiver->remote_ice_candidate == NULL) {
    transceiver->remote_ice_candidate = candidate;
  } else {
    struct RTCIecCandidates *lastcandidate = transceiver->remote_ice_candidate;

    for (; lastcandidate->next_candidate != NULL;
         lastcandidate = lastcandidate->next_candidate)
      ;
    lastcandidate->next_candidate = candidate;
  }
  struct args *arg = malloc(sizeof(struct args));
  arg->transceiver = transceiver;
  arg->candidate = candidate;

  g_timeout_add_full(G_PRIORITY_HIGH, 499, (GSourceFunc)make_candidate_pair,
                     arg, (GDestroyNotify)ice_handshake_ended);
}
