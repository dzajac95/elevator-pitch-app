#include <android/log.h>
#include <arpa/inet.h>
#include <bits/signal_types.h>
#include <errno.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <net/if.h>
#include <poll.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <sys/msg.h>
#include <stdio.h>

#include "dns_task.h"
#include "mdns.h"

#define MY_LOG_TAG "dns_task"

#define printf(...) do { __android_log_print(ANDROID_LOG_INFO, MY_LOG_TAG, __VA_ARGS__); } while(0)
#define LOG_INFO(...) do { __android_log_print(ANDROID_LOG_INFO, MY_LOG_TAG, __VA_ARGS__); } while(0)
#define LOG_ERR(...) do { __android_log_print(ANDROID_LOG_ERROR, MY_LOG_TAG, __VA_ARGS__); } while(0)
#define LOG_DEBUG(...) do { __android_log_print(ANDROID_LOG_DEBUG, MY_LOG_TAG, __VA_ARGS__); } while(0)

typedef struct {
    char query[256];
    dns_done_fn callback;
    dns_res_t *res;
} msg_t;

static int msgq_id;
static volatile sig_atomic_t running = 1;

#define WR_SOCK 0
#define RD_SOCK 1
static int msg_sockets[2];

static mdns_string_t
ipv4_address_to_string(char* buffer, size_t capacity, const struct sockaddr_in* addr,
                       size_t addrlen) {
    char host[NI_MAXHOST] = {0};
    char service[NI_MAXSERV] = {0};
    int ret = getnameinfo((const struct sockaddr*)addr, (socklen_t)addrlen, host, NI_MAXHOST,
                          service, NI_MAXSERV, NI_NUMERICSERV | NI_NUMERICHOST);
    int len = 0;
    if (ret == 0) {
        if (addr->sin_port != 0)
            len = snprintf(buffer, capacity, "%s:%s", host, service);
        else
            len = snprintf(buffer, capacity, "%s", host);
    }
    if (len >= (int)capacity)
        len = (int)capacity - 1;
    mdns_string_t str;
    str.str = buffer;
    str.length = len;
    return str;
}

static mdns_string_t
ipv6_address_to_string(char* buffer, size_t capacity, const struct sockaddr_in6* addr,
                       size_t addrlen) {
    char host[NI_MAXHOST] = {0};
    char service[NI_MAXSERV] = {0};
    int ret = getnameinfo((const struct sockaddr*)addr, (socklen_t)addrlen, host, NI_MAXHOST,
                          service, NI_MAXSERV, NI_NUMERICSERV | NI_NUMERICHOST);
    int len = 0;
    if (ret == 0) {
        if (addr->sin6_port != 0)
            len = snprintf(buffer, capacity, "[%s]:%s", host, service);
        else
            len = snprintf(buffer, capacity, "%s", host);
    }
    if (len >= (int)capacity)
        len = (int)capacity - 1;
    mdns_string_t str;
    str.str = buffer;
    str.length = len;
    return str;
}

static mdns_string_t
ip_address_to_string(char* buffer, size_t capacity, const struct sockaddr* addr, size_t addrlen) {
    if (addr->sa_family == AF_INET6)
        return ipv6_address_to_string(buffer, capacity, (const struct sockaddr_in6*)addr, addrlen);
    return ipv4_address_to_string(buffer, capacity, (const struct sockaddr_in*)addr, addrlen);
}

// Open sockets for sending one-shot multicast queries from an ephemeral port
static int
open_client_sockets(int* sockets, int max_sockets, int port) {
    // When sending, each socket can only send to one network interface
    // Thus we need to open one socket for each interface and address family
    int num_sockets = 0;

    struct ifaddrs* ifaddr = 0;
    struct ifaddrs* ifa = 0;

    if (getifaddrs(&ifaddr) < 0)
        printf("Unable to get interface addresses\n");

    int first_ipv4 = 1;
    for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr)
            continue;
        if (!(ifa->ifa_flags & IFF_UP) || !(ifa->ifa_flags & IFF_MULTICAST))
            continue;
        if ((ifa->ifa_flags & IFF_LOOPBACK) || (ifa->ifa_flags & IFF_POINTOPOINT))
            continue;

        if (ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in* saddr = (struct sockaddr_in*)ifa->ifa_addr;
            if (saddr->sin_addr.s_addr != htonl(INADDR_LOOPBACK)) {
                int log_addr = 0;
                if (first_ipv4) {
                    first_ipv4 = 0;
                    log_addr = 1;
                }
                if (num_sockets < max_sockets) {
                    saddr->sin_port = htons(port);
                    int sock = mdns_socket_open_ipv4(saddr);
                    if (sock >= 0) {
                        sockets[num_sockets++] = sock;
                        log_addr = 1;
                    } else {
                        log_addr = 0;
                    }
                }
                if (log_addr) {
                    char buffer[64];
                    mdns_string_t addr_str = ipv4_address_to_string(buffer, sizeof(buffer), saddr, sizeof(struct sockaddr_in));
                    printf("Local IPv4 address: %.*s\n", MDNS_STRING_FORMAT(addr_str));
                }
            }
        }
    }

    freeifaddrs(ifaddr);

    return num_sockets;
}

static char addrbuffer[64];
static char entrybuffer[256];
static char namebuffer[256];
static char sendbuffer[1024];
static mdns_record_txt_t txtbuffer[128];
static int query_answered = 0;

// Callback handling parsing answers to queries sent
static int
query_callback(int sock, const struct sockaddr* from, size_t addrlen, mdns_entry_type_t entry,
               uint16_t query_id, uint16_t rtype, uint16_t rclass, uint32_t ttl, const void* data,
               size_t size, size_t name_offset, size_t name_length, size_t record_offset,
               size_t record_length, void* _user_data) {
    (void)sizeof(sock);
    (void)sizeof(query_id);
    (void)sizeof(name_length);
    msg_t *user_data = _user_data;
    mdns_string_t fromaddrstr = ip_address_to_string(addrbuffer, sizeof(addrbuffer), from, addrlen);
    if (entry != MDNS_ENTRYTYPE_ANSWER) {
        return 0;
    }
    mdns_string_t entrystr =
        mdns_string_extract(data, size, &name_offset, entrybuffer, sizeof(entrybuffer));
    if (rtype == MDNS_RECORDTYPE_A) {
        struct sockaddr_in addr;
        mdns_record_parse_a(data, size, record_offset, record_length, &addr);
        mdns_string_t addrstr =
            ipv4_address_to_string(namebuffer, sizeof(namebuffer), &addr, sizeof(addr));
        printf("%.*s : %.*s A %.*s\n", MDNS_STRING_FORMAT(fromaddrstr),
               MDNS_STRING_FORMAT(entrystr), MDNS_STRING_FORMAT(addrstr));
        user_data->res->res = 0;
        user_data->res->addr = addr;
        query_answered = 1;
        return 1;
    }
    return 0;
}

// Send a mDNS query
static void
send_mdns_query(msg_t *user_data) {
    char *hostname = user_data->query;
    int sockets[32];
    int query_id[32];

    user_data->res->res = -1;
    int num_sockets = open_client_sockets(sockets, sizeof(sockets) / sizeof(sockets[0]), 0);
    if (num_sockets <= 0) {
        printf("Failed to open any client sockets\n");
        user_data->callback();
        return;
    }
    printf("Opened %d socket%s for mDNS query\n", num_sockets, num_sockets ? "s" : "");

    size_t capacity = 2048;
    void* buffer = malloc(capacity);

    printf("Sending mDNS query\n");
    for (int isock = 0; isock < num_sockets; ++isock) {
        query_id[isock] =
            mdns_query_send(sockets[isock], MDNS_RECORDTYPE_A, hostname, strlen(hostname), buffer, capacity, 0);
        if (query_id[isock] < 0)
            printf("Failed to send mDNS query: %s\n", strerror(errno));
    }

    // This is a simple implementation that loops for 5 seconds or as long as we get replies
    int res;
    printf("Reading mDNS query replies\n");
    struct timeval timeout;
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;

    int nfds = 0;
    fd_set readfs;
    FD_ZERO(&readfs);
    for (int isock = 0; isock < num_sockets; ++isock) {
        if (sockets[isock] >= nfds)
            nfds = sockets[isock] + 1;
        FD_SET(sockets[isock], &readfs);
    }

    res = select(nfds, &readfs, 0, 0, &timeout);
    if (res > 0) {
        for (int isock = 0; isock < num_sockets; ++isock) {
            if (FD_ISSET(sockets[isock], &readfs)) {
                size_t rec = mdns_query_recv(sockets[isock], buffer, capacity, query_callback,
                        user_data, query_id[isock]);
                if (query_answered) {
                    break;
                }
            }
            FD_SET(sockets[isock], &readfs);
        }
    }

    free(buffer);
    query_answered = 0;
    user_data->callback();

    for (int isock = 0; isock < num_sockets; ++isock)
        mdns_socket_close(sockets[isock]);
    printf("Closed socket%s\n", num_sockets ? "s" : "");

    return;
}

bool dns_task_submit_query(const char *query, dns_done_fn callback, dns_res_t *res)
{
    int ret;
    msg_t msg = {0};
    strncpy(msg.query, query, 256);
    msg.callback = callback;
    msg.res = res;
    ret = send(msg_sockets[WR_SOCK], &msg, sizeof(msg), 0);
    if (ret < 0) {
        LOG_ERR("Failed to submit query to queue: %d", ret);
        return false;
    }
    return true;
}

static void* dns_task(void *_args)
{
    msg_t msg;
    int read_sock = msg_sockets[RD_SOCK];
    struct pollfd pfd = {
        .fd = read_sock,
        .events = POLLIN,
    };
    while (running) {
        if (poll(&pfd, 1, -1)) {
            recv(read_sock, &msg, sizeof(msg), 0);
            LOG_INFO("Received query: %s", msg.query);
            send_mdns_query(&msg);
        }
    }

    return (void*) 0;
}

bool dns_task_start(void)
{
    int ret;

    ret = socketpair(AF_UNIX, SOCK_STREAM, 0, msg_sockets);
    if (ret < 0) {
        LOG_ERR("Failed to create socket pair: %d", ret);
        return false;
    }

    pthread_t dns_thread;
    ret = pthread_create(&dns_thread, NULL, dns_task, NULL);
    if (ret != 0) {
        LOG_ERR("Failed to create pthread: %d", ret);
        return false;
    }
    return true;
}

void dns_task_shutdown(void)
{
    running = 0;
}
