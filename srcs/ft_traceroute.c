#include "../incs/ft_traceroute.h"

void usage_error(void) {
    printf("usage: ./ft_ping [-h, -f, -m, -i, -n, -p] hostname\n");
    printf("\t./ft_ping -h to print the help\n");
    exit(1);
}

void help_and_exit(void) {
    printf("FT_PING: help:\nusage: ./ft_ping [-h, -v, -c, -D -n, -t, -w] hostname\n");
    printf("\t-h\n\t\tprint this help\n\n");
    printf("\t-f first_ttl\n\t\tSpecifies with what TTL to start. Defaults to 1.\n\n");
    printf("\t-m max_ttl\n\t\tSpecifies the maximum number of hops (max time-to-live value) traceroute will probe. The default is 30.\n\n");
    printf("\t-i interface\n\t\tSpecifies the interface through which traceroute should send packets. By default, the interface is selected according to the routing table.\n\n");
    printf("\t-n\n\t\tDo not try to map IP addresses to host names when displaying them.\n\n");
    printf("\t-p port\n\t\tFor ICMP tracing, specifies the initial ICMP sequence value (incremented by each probe too).\n"); // print response ttl
    exit(0);
}

void error_exit(char *err) {
    printf("ft_traceroute: %s\n", err);
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

char *ft_strdup(char *s) {
    size_t len = ft_strlen(s) + 1;
    char *dup = malloc(len);
    if (dup == NULL) {
        error_exit("malloc failed");
    }
    for (size_t i = 0; i < len; i++) {
        dup[i] = s[i];
    }
    dup[len] = '\0';
    return dup;
}

void print_stats(t_env *env) {
    (void)env;
    printf("print_stats\n");
    exit(0);
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
    if (getuid() != 0) {
        error_exit("not running as root: socket will fail");
    }
    
    env->host_src = "0.0.0.0"; // nous
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
    env->port_sequence = 0;
    env->timeout = 1;
    env->first_ttl = 1;
    env->max_ttl = 30;
    env->interface = "eth0"; // get_default_ipv4_interface();

    env->numeric = false;
}


bool is_argument(char *str) {
    // List of valid options
    char *options[] = { "-f", "-m", "-p", "-i", "-n" };
    int num_options = sizeof(options) / sizeof(options[0]);

    for (int i = 0; i < num_options; i++) {
        if (ft_strcmp(str, options[i]) == 0) {
            return true;
        }
    }
    return false;
}


void arg_handler(t_env *env, int ac, char **av) {
    char *hostname = NULL;
    for (int i = 1; i < ac; i++) {
        if (hostname != NULL && is_argument(av[i]) == false) {
            printf("ft_traceroute: unsupported agument %s\n", av[i]);
            exit(1);
        }
        if (hostname == NULL && is_argument(av[i]) == false) {
            hostname = ft_strdup(av[i]);
        } else if (ft_strcmp(av[i], "-f") == 0) {
            if (i + 1 >= ac) {
                error_exit("missing argument for -f option");
            }
            env->first_ttl = atoi(av[i + 1]);
            i++;
        } else if (ft_strcmp(av[i], "-m") == 0) {
            if (i + 1 >= ac) {
                error_exit("missing argument for -m option");
            }
            env->max_ttl = atoi(av[i + 1]);
            i++;
        } else if (ft_strcmp(av[i], "-i") == 0) {
            if (i + 1 >= ac) {
                error_exit("missing argument for -i option");
            }
            env->interface = av[i + 1];
            i++;
        } else if (ft_strcmp(av[i], "-n") == 0) {
            env->numeric = true;
        } else if (ft_strcmp(av[i], "-p") == 0 ) {
            if (i + 1 >= ac) {
                error_exit("missing argument for -p option");
            }
            env->port_sequence = atoi(av[i]);
        } else {
            error_exit("fqdn or ipv4 already set");
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
    printf("traceroute to %s (%s), %d hops max, 60 bytes of data.\n", env.hostname, env.host_dst, env.max_ttl);
}

void setup_send(t_env *env, unsigned int ttl, int nb_probe) {
    ft_memset(&(env->buffer), 0, sizeof(env->buffer));

    env->ip->ip_v = 4;            // Set the IP version to IPv4
    env->ip->ip_hl = 5;           // Set the header length to 20 bytes (5 words)
    env->ip->ip_tos = 0;          // Type of Service (set to 0 for default)
    env->ip->ip_len = htons(sizeof(env->buffer));
    env->ip->ip_id = 0; // Unique identification (you can choose a suitable value)
    env->ip->ip_off = 0;          // Fragment offset and flags (set to 0 for no fragmentation)
    env->ip->ip_ttl = ttl;         // Time to Live (adjust as needed)
    env->ip->ip_p = env->res->ai_protocol;  // Protocol (e.g., ICMP)
    env->ip->ip_sum = 0;          // Set checksum to 0 for now (calculate it later)
    inet_pton(env->res->ai_family, env->host_src, &(env->ip->ip_src.s_addr));
    inet_pton(env->res->ai_family, env->host_dst, &(env->ip->ip_dst.s_addr));

    env->icmp->icmp_type = ICMP_ECHO;
    env->icmp->icmp_code = 0;
    env->icmp->icmp_id = env->pid;
    env->icmp->icmp_seq = env->port_sequence + nb_probe;

    env->icmp->icmp_cksum = 0;
    env->icmp->icmp_cksum = ft_checksum((unsigned short *) env->icmp, sizeof(env->icmp));
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

void receive_packet(struct timeval send_time, unsigned int ttl, t_env *env) {
    (void)ttl; // needed for structure place ??
    (void)send_time; // needed for calculating time elapsed since send
    setup_receive(env);
    
	struct timeval tv_current;
	struct timeval tv_next;

	if (gettimeofday(&tv_current, NULL) < 0)
		error_exit("gettimeofday");
	tv_next = tv_current;
	tv_next.tv_sec += env->timeout;
    int packets_recv = 0;
    printf("receive_packet\n");
    while (1) {
        char buffer[200];
        ssize_t packet_size = recvfrom(env->socket_fd, buffer, sizeof(buffer), 0, NULL, NULL);

        if (packet_size < 0) {
            if (gettimeofday(&tv_current, NULL) < 0)
                error_exit("gettimeofday");
            if (tv_current.tv_sec * 1000000 + tv_current.tv_usec > tv_next.tv_sec * 1000000 + tv_next.tv_usec) {
                printf("break timeout\n");
                break; // pas sur de la formule
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }
            error_exit("recvfrom");
        }

        struct iphdr *ip_packet = (struct iphdr *) buffer;
        struct icmp *icmp_packet = (struct icmp *) (buffer + (ip_packet->ihl * 4));

        packets_recv += 1;
        // if (icmp_packet->icmp_type == ICMP_TIME_EXCEEDED) {
        //     printf("Time to live exceeded.\n");
        // } else {
            // set time in struct
            struct timeval receive_time;
            (void)receive_time; // receive_time - send_time
            printf("%ld bytes from %s: icmp_seq=%u ttl=%d\n",
                packet_size - sizeof(struct iphdr), inet_ntoa(*(struct in_addr *)&ip_packet->saddr),
                icmp_packet->icmp_seq, ip_packet->ttl);
        // }
        if (packets_recv == NB_PROBES) {
            printf("break probes\n");
            break ;
        }

        if (gettimeofday(&tv_current, NULL) < 0)
            error_exit("gettimeofday");
        if (tv_current.tv_sec * 1000000 + tv_current.tv_usec > tv_next.tv_sec * 1000000 + tv_next.tv_usec) {
            printf("break 3\n");
            break;
        }
    }
}

void print_env(t_env *env) {
    printf("env->pid |%d|\n", env->pid);
    printf("env->port_sequence |%d|\n", env->port_sequence);
    printf("env->timeout |%d|\n", env->timeout);
    printf("env->first_ttl |%d|\n", env->first_ttl);
    printf("env->max_ttl |%d|\n", env->max_ttl);
    printf("env->interface |%s|\n", env->interface);
    printf("env->numeric |%s|\n", env->numeric ? "true" : "false");
    printf("\n\n");
}

void traceroute(t_env *env) {
    print_env(env);
    unsigned int ttl = env->first_ttl;
    while (ttl <= env->max_ttl) {
        printf("enter loop ttl = %d\n", ttl);
        struct timeval send_time;
        int i = 0;
        if (gettimeofday(&send_time, NULL) < 0)
            error_exit("gettimeofday");
        while (i < NB_PROBES) {
            setup_send(env, ttl, i);
            // set time send for probe i
            if (sendto(env->socket_fd, env->buffer, sizeof(env->buffer), 0, env->res->ai_addr, env->res->ai_addrlen) < 0) {
                error_exit("sendto: could not send");
            }
            i += 1;
        }
        receive_packet(send_time, ttl, env); // interval = 1
        ttl += 1;
        printf("\n");
    }
    return ;
}

int main(int ac, char **av) {
    if (ac < 2) {
        usage_error();
    }

    init_env(&env); // set default values
    arg_handler(&env, ac, av); // get hostname and options

    create_socket(&env); // create socket

    // init ip and icmp structs
    env.ip = (struct ip *)env.buffer;
    env.icmp = (struct icmp *)(env.ip + 1);

    print_host(env);
    traceroute(&env);

    return 0;
}
