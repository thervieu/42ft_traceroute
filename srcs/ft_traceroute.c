#include "../incs/ft_traceroute.h"

void usage_error(void) {
    printf("usage: ./ft_ping [-h, -f, -n -p, -W, -ttl] hostname\n");
    printf("\t./ft_ping -h to print the help\n");
    exit(1);
}

// -f first ttl value, default is 1
// -m max ttl value, default is 30
// -i interface to use, default is first in routing
// -n Do not try to map the IP addresses to host names when diplaying names
// -p UDP destination port to use increments each probe, ICMP sequence number also increments each probe, TCP constant destination port to use
void help_and_exit(void) {
    printf("FT_PING: help:\nusage: ./ft_ping [-h, -v, -c, -D -n, -t, -w] hostname\n");
    printf("\t-h\n\t\tprint this help\n\n");
    printf("\t-v\n\t\tVerbose output. Do not suppress DUP replies when pinging multicast address.\n\n");
    printf("\t-c count\n\t\tStop after sending count ECHO_REQUEST packets. With deadline option, ping waits for count ECHO_REPLY packets, until the timeout expires.\n\n");
    printf("\t-D\n\t\tPrint timestamp (unix time + microseconds as in gettimeofday) before each line.\n\n");
    printf("\t-n\n\t\tNumeric output only. No attempt will be made to lookup symbolic names for host addresses.\n\n");
    printf("\t-t ttl\n\t\tping only. Set the IP Time to Live.\n"); // print response ttl
    printf("\t-w deadline\n\t\tSpecify a timeout, in seconds, before ping exits regardless of how many packets have been sent or received. In this case ping does not stop after ");
    printf("count packet are sent, it waits either for deadline expire. or until count probes are answered or for some error notification from network.\n\n");
    exit(0);
}

void error_exit(char *err) {
    printf("ft_ping: %s\n", err);
    exit(1);
}

size_t ft_strlen(char *s) {
    size_t i = 0;
    while (s[i] != '\0') {
        i++;
    }
    return i;
}

size_t ft_strcmp(char *s1, char *s2) {
    if (ft_strlen(s1) != ft_strlen(s2)) {
        return 1;
    }
    for (size_t i = 0; i < ft_strlen(s1); i ++) {
        if (s1[i] != s2[i])
            return 1;
        if (s1[i] == '\0' || s2[i] == '\0')
            break ;
    }
    return 0;
}

void	*ft_memset(void *b, int c, size_t len)
{
	size_t			i;
	unsigned char	*ptr;

	i = 0;
	ptr = (unsigned char *)b;
	while (i < len)
		ptr[i++] = (unsigned char)c;
	return (b);
}

void print_stats(t_env *env) {
    (void)env;
    printf("print_stats\n");
    exit(0);
}


void signal_handler(int signal) {
    if (signal == SIGINT) {
        print_stats(&env);
    }
    return ;
}


char *get_ip_from_hostname(char *hostname) {
    struct addrinfo hints;
    struct addrinfo *res;
    struct sockaddr_in *sa_in;
    
    ft_memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;

    int status = getaddrinfo(hostname, NULL, &hints, &res);
    if (status < 0) {
        error_exit("getaddrinfo failed");
    }

    sa_in = (struct sockaddr_in *)res->ai_addr;
    char *ip_address = malloc(INET_ADDRSTRLEN*sizeof(char));
    if (ip_address == NULL) {
        freeaddrinfo(res);
        error_exit("malloc failed");
    }

    if (inet_ntop(res->ai_family, &(sa_in->sin_addr),  ip_address, INET_ADDRSTRLEN) == NULL) {
        freeaddrinfo(res);
        free(ip_address);
        error_exit("inet_ntop failed");
    }

    freeaddrinfo(res);
    return ip_address;
}

void create_socket(t_env *env) {
    env->host_src = "0.0.0.0"; // us
    env->host_dst = get_ip_from_hostname(env->hostname);

    ft_memset(&(env->hints), 0, sizeof(env->hints));
    env->hints.ai_family = AF_INET;
    env->hints.ai_socktype = SOCK_RAW;
    env->hints.ai_protocol = IPPROTO_ICMP;

    if (getaddrinfo(env->host_dst, NULL, &(env->hints), &(env->res)) < 0) {
        error_exit("get_addr_info: unknown host");
    }
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        error_exit("socket failed");
    }
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (flags == -1) {
        error_exit("fcntl");
    }
    if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) == -1) {
        error_exit("fcntl");
    }
    int option_value = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &option_value, sizeof(option_value)) < 0) {
        error_exit("setsockopt: error when setting up the socket's options");
    }
    env->socket_fd = sockfd;
}

void init_env(t_env *env) {
    env->pid = getpid();
    env->seq = 0;
    env->interval = 1;
    env->timeout = 10;
    env->time_spent_sending_packets = 0; // valeure 'time' dans les stats affichées

    // bonuses default
    env->count = 0; // 0 for infinite
    env->verbose = false; // ne sert à rien ??
    env->numeric = false;
    env->unix_time = false;
    env->ttl = 64;
    env->deadline = 0; // 0 for infinite
}

void arg_handler(t_env *env, int ac, char **av) {
    char *hostname = NULL;
    for (int i = 1; i < ac; i++) {
        if (hostname == NULL) {
            hostname = av[i];
        } else {
            error_exit("too many arguments");
        }
    }
    env->hostname = hostname;
    return ;
}

short ft_checksum(unsigned short *data, int len) {
    unsigned long checksum = 0;

    while (len > 1) {
        checksum += *data++;
        len -= sizeof(unsigned short);
    }
    if (len)
        checksum += *(unsigned char*)data;

    while (checksum >> 16) {
        checksum = (checksum & 0xFFFF) + (checksum >> 16);
    }
    return (short)~checksum;
}

void print_host(t_env env) {
    printf("PING %s (%s) 56(84) bytes of data.\n", env.hostname, env.host_dst);
}

void setup_send(t_env *env) {
    ft_memset(&(env->buffer), 0, sizeof(env->buffer));

    env->ip->ip_v = 4;            // Set the IP version to IPv4
    env->ip->ip_hl = 5;           // Set the header length to 20 bytes (5 words)
    env->ip->ip_tos = 0;          // Type of Service (set to 0 for default)
    env->ip->ip_len = htons(sizeof(env->buffer));
    env->ip->ip_id = 0; // Unique identification (you can choose a suitable value)
    env->ip->ip_off = 0;          // Fragment offset and flags (set to 0 for no fragmentation)
    env->ip->ip_ttl = env->ttl;         // Time to Live (adjust as needed)
    env->ip->ip_p = env->res->ai_protocol;  // Protocol (e.g., ICMP)
    env->ip->ip_sum = 0;          // Set checksum to 0 for now (calculate it later)
    inet_pton(env->res->ai_family, env->host_src, &(env->ip->ip_src.s_addr));
    inet_pton(env->res->ai_family, env->host_dst, &(env->ip->ip_dst.s_addr));

    env->icmp->icmp_type = ICMP_ECHO;
    env->icmp->icmp_code = 0;
    env->icmp->icmp_id = env->pid;
    env->icmp->icmp_seq = env->seq;

    env->icmp->icmp_cksum = 0;
    env->icmp->icmp_cksum = ft_checksum((unsigned short *) env->icmp, sizeof(env->icmp));
    
    // increment sequence number
    env->seq++;
}

void setup_receive(t_env *env) {
    ft_memset(&(env->buffer), 0, sizeof(env->buffer));
	env->iov[0].iov_base = env->buffer;
	env->iov[0].iov_len = sizeof(env->buffer);
	env->msg.msg_name = env->res->ai_addr;
	env->msg.msg_namelen = env->res->ai_addrlen;
	env->msg.msg_iov = env->iov;
	env->msg.msg_iovlen = 1;
	env->msg.msg_control = &(env->buffer_control);
	env->msg.msg_controllen = sizeof(env->buffer_control);
	env->msg.msg_flags = 0;
}

void receive_packet(int seconds_to_wait, t_env *env) {
    setup_receive(env);
    
	struct timeval tv_current;
	struct timeval tv_next;

	if (gettimeofday(&tv_current, NULL) < 0)
		error_exit("Error gettimeofday\n");
	tv_next = tv_current;
	tv_next.tv_sec += seconds_to_wait; // interval or packet receive timeout (mélangé pck -W pas implémenté)
    while (1) {
        char buffer[200];
        ssize_t packet_size = recvfrom(env->socket_fd, buffer, sizeof(buffer), MSG_DONTWAIT, NULL, NULL);

        if (packet_size < 0) {
            // if no packets received and time elapsed, break
            if (gettimeofday(&tv_current, NULL) < 0)
                error_exit("Error gettimeofday\n");
            if (env->deadline != 0 && (tv_current.tv_sec * 1000000 + tv_current.tv_usec) >= (env->deadline_timeval.tv_sec * 1000000 + env->deadline_timeval.tv_usec)) {
                kill(getpid(), SIGINT); // -w deadline
            }
            if (tv_current.tv_sec * 1000000 + tv_current.tv_usec  < tv_next.tv_sec * 1000000 + tv_next.tv_usec) {
                break; // pas sur de la formule
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }
            error_exit("recvfrom");
        }

        struct iphdr *ip_packet = (struct iphdr *) buffer;
        struct icmp *icmp_packet = (struct icmp *) (buffer + (ip_packet->ihl * 4));

        env->packets_recv++;
        // calculate stats
        if (icmp_packet->icmp_type == ICMP_TIME_EXCEEDED) {
            printf("Time to live exceeded.\n");
        } else {
            // -D, -n, 
            printf("%ld bytes from %s: icmp_seq=%u ttl=%d\n",
                packet_size - sizeof(struct iphdr), inet_ntoa(*(struct in_addr *)&ip_packet->saddr),
                icmp_packet->icmp_seq, ip_packet->ttl);
        }
        while (1) {
            // if received all packets, quit
            if (env->count != 0 && env->packets_recv == env->count) {
                break ;
            }
            // if packet received and time elapsed, break
            if (gettimeofday(&tv_current, NULL) < 0)
                error_exit("Error gettimeofday\n");
            if (env->deadline != 0 && (tv_current.tv_sec * 1000000 + tv_current.tv_usec) >= (env->deadline_timeval.tv_sec * 1000000 + env->deadline_timeval.tv_usec)) {
                kill(getpid(), SIGINT);  // -w deadline
            }
            if (tv_current.tv_sec * 1000000 + tv_current.tv_usec  < tv_next.tv_sec * 1000000 + tv_next.tv_usec) {
                break; // pas sur de la formule
            }
        }
    }
}

void ping_loop(t_env *env) {


    env->packets_sent = 0;
    env->packets_recv = 0;

    while (true) {
        struct timeval beg;
        struct timeval cur;
        setup_send(env);
        if (gettimeofday(&beg, NULL) < 0)
            error_exit("Error gettimeofday\n");
        if (sendto(env->socket_fd, env->buffer, sizeof(env->buffer), 0, env->res->ai_addr, env->res->ai_addrlen) < 0) {
            error_exit("sendto: could not send");
        }
        // time print start
        env->packets_sent++;
        if (env->count != 0 && env->packets_sent == env->count) {
            break ;
        }
        if (gettimeofday(&cur, NULL) < 0)
            error_exit("Error gettimeofday\n");
        receive_packet(env->interval, env); // interval = 1
        env->time_spent_sending_packets += (cur.tv_usec - beg.tv_usec) / 1000;
    }
    receive_packet(env->timeout, env);
    return ;
}

int main(int ac, char **av) {
    if (ac < 2) {
        usage_error();
    }
    signal(SIGINT, signal_handler);

    init_env(&env); // set default values
    arg_handler(&env, ac, av); // get hostname and options

    create_socket(&env); // create socket

    // init ip and icmp structs
    env.ip = (struct ip *)env.buffer;
    env.icmp = (struct icmp *)(env.ip + 1);

    print_host(env);
    ping_loop(&env);

    return 0;
}
