#include<stdbool.h>
#include <arpa/inet.h>
#include <stdint.h>


#ifndef _RTPH_
#define _RTPH_
#pragma pack(1)

struct RtpStream{
  void (*media_data_callback)(void * , void(*rtp_sender_thread)(struct RtpStream *, char *, int),struct RtpStream *);
  void *callback_data;
  int port;
  char *ip;
  char *streamState;
  struct sockaddr_in *socket_address;
  int sockdesc;
  struct Rtp * rtp_packet; 
  int socket_len;
  int payload_type;
  int clock_rate;
  uint32_t timestamp;
};
struct RtpSession{
  struct RtpStream *streams[10];
  int totalStreams;
};
struct __attribute__((packed)) Rtp {
#if G_BYTE_ORDER == G_LITTLE_ENDIAN
  unsigned int csrc_count : 4;
  unsigned int ext : 1;
  unsigned int padding : 1;
  unsigned int v : 2;
#elif G_BYTE_ORDER == G_BIG_ENDIAN
  unsigned int v : 2;
  unsigned int padding : 1;
  unsigned int ext : 1;
  unsigned int csrc_count : 4;
#else
#error "Byte order is not recognized it should either be big or little endian"
#endif

#if G_BYTE_ORDER == G_LITTLE_ENDIAN
  unsigned int pt : 7;
  unsigned int marker : 1;
#elif G_BYTE_ORDER == G_BIG_ENDIAN
  unsigned int marker : 1;
  unsigned int pt : 7;
#error "Byte order is not recognized it should either be big or little endian"
#endif
  unsigned int seq_no : 16;
  unsigned int timestamp : 32;
  unsigned int ssrc : 32;
  unsigned int csrc :32;
char *payload[];
};
struct RtpSession* create_rtp_session();
struct RtpStream* create_rtp_stream(char* ip, int port ,struct RtpSession *rtp_session,void *video_data_callback,void *callback_data);
bool start_rtp_session(struct RtpSession *rtpSession); 
bool start_rtp_stream(struct RtpStream *rtpStream);
int get_udp_sock_desc();

#endif
