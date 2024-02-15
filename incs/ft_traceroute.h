#ifndef FT_TRACEROUTE_H
# define FT_TRACEROUTE_H

# include <unistd.h>
# include <stdio.h>
# include <signal.h>
# include <arpa/inet.h>
# include <sys/types.h>
# include <sys/socket.h>
# include <netinet/ip.h>
# include <netinet/ip_icmp.h>
# include <netdb.h>
# include <sys/time.h>
# include <stdbool.h>
# include <stdlib.h>
# include <float.h>
# include <math.h>
# include <errno.h>
# include <fcntl.h>

# define NB_PROBES 3

typedef struct s_env {

    // names
    char *hostname;
    char *host_dst;
    char *host_src;

    // communication structures
    pid_t pid;
    struct ip *ip;
    struct icmp *icmp;
    struct addrinfo hints;
    struct addrinfo *res;
    char buffer[200];

    struct iovec iov[1];
    struct msghdr msg;
    char buffer_control[200];

    // communication data
    unsigned int port_sequence; // just don't print the dns. bonus -n
    unsigned int interval;
    char *interface;

    unsigned int timeout; // default 1s
    unsigned int first_ttl; // -f premier ttl
    unsigned int max_ttl; // -c count number of packets to send
    bool numeric; // just don't print the dns. bonus -n

    // socket
    int socket_fd;
} t_env;

t_env env;

#endif