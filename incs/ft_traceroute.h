#ifndef FT_PING_H
# define FT_PING_H

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
    unsigned int seq;
    unsigned int interval;

    unsigned int timeout; // default 10s
    unsigned int count; // -c count number of packets to send
    bool verbose; // -v verbose to print errors in packets
    bool numeric; // just don't print the weird sub dns rebound. bonus -n
    bool unix_time; // print unix time. bonus -D
    unsigned int ttl; // 64 by default is it ??. bonus -ttl
    unsigned int deadline; // bonus -w int deadline, seconds after which we quit the program
    struct timeval deadline_timeval;
    unsigned int time_spent_sending_packets; // bonus -w int deadline, seconds after which we quit the program

    // socket
    int socket_fd;

    // calculus data
    unsigned int packets_sent;
    unsigned int packets_recv;
    double min;
    double max;
} t_env;

t_env env;

#endif