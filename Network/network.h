
#include <arpa/inet.h>
#include <sys/socket.h>
struct sockaddr_in * get_network_socket(char *ip , int port);
int get_udp_sock_desc();
