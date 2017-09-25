#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <poll.h>
#include <sys/time.h>
#include <inttypes.h>

#include "utp.h"

typedef struct {
    uint32_t  ip;
    uint16_t  port;
    char      host_str[16];
    char      port_str[6];
} utp_session_t;

#define UTP_MAX_SESSIONS_CNT         1024

typedef struct {
    utp_session_t sessions[UTP_MAX_SESSIONS_CNT];
    int           current;
} utp_sessions_t;

typedef enum {
    N_UTP_SERVER,
    N_UTP_CLIENT
} utp_role_t;

typedef struct {
    int   fd;
} utp_sockdesc_t;

typedef struct {
    utp_context  *ctx;
    utp_socket   *sock;
} utp_desc_t;

#define UTP_LOG_LEVEL_INFO     3
#define UTP_LOG_LEVEL_DEBUG    2
#define UTP_LOG_LEVEL_WARN     1
#define UTP_LOG_LEVEL_ERR      0

typedef struct {
    utp_sessions_t *remote_sessions;
    utp_role_t      role;
    utp_session_t   local_session;
    utp_session_t   remote_session;
    utp_sockdesc_t  sock_desc;
    int             log_level;
    int             running;
    int             bitrate;
    utp_desc_t      utp_desc;
    int             use_utp;
} utp_application_t;

static utp_application_t g_utp_app;

static uint64_t __now(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}


#define LOG(level, fmt, ...) do { \
        if (level <= g_utp_app.log_level) { \
            printf("[%s:%d:%"PRIu64"]"fmt"\n", __FUNCTION__, __LINE__,      \
                    __now(), ##__VA_ARGS__);                                \
        } \
    } while (0)

static utp_role_t __app_role(char *role_str)
{
    if (0 == strcmp(role_str, "server")) {
        return N_UTP_SERVER;
    } else {
        return N_UTP_CLIENT;
    }
}

static uint32_t __ip2dec(char *ip_str)
{
    char *str = ip_str;
    char *t = ip_str;
    uint32_t ip = 0;

    if (NULL == (t = strstr(str, "."))) {
        return 0;
    }
    *t++ = '\0';
    ip = atoi(str) << 24;
    str = t;
    if (NULL == (t = strstr(str, "."))) {
        return 0;
    }
    *t++ = '\0';
    ip |= atoi(str) << 16;
    str = t;
    if (NULL == (t = strstr(str, "."))) {
        return 0;
    }
    *t++ = '\0';
    ip |= atoi(str) << 8;
    str = t;
    ip |= atoi(str);

    return ip;
}

static int __parse_config(int argc, char *argv[], utp_application_t *app)
{
    int c = 0;
#define UTP_OPT_STRING   "r:p:h:d:b:u"
    while (-1 != (c = getopt(argc, argv, UTP_OPT_STRING))) {
        switch (c) {
        case 'r': app->role = __app_role(optarg);            break;
        case 'p':
            app->remote_session.port = atoi(optarg);
            strcpy(app->remote_session.port_str, optarg);
            break;
        case 'h':
            strcpy(app->remote_session.host_str, optarg);
            app->remote_session.ip = __ip2dec(optarg);
            break;
        case 'd': app->log_level = atoi(optarg);             break;
        case 'b': app->bitrate = atoi(optarg);               break;
        case 'u': app->use_utp = 1;                          break;
        default:                                             break;
        }
    }

    if (N_UTP_CLIENT == app->role) {
        if (0 == app->remote_session.ip ||
            0 == app->remote_session.port) {
            LOG(UTP_LOG_LEVEL_ERR, "client must have a remote host:ip");
            return -1;
        }
    }

    return 0;
}

static int __final_socket(utp_application_t *app)
{
    if (NULL != app->remote_sessions) {
        free(app->remote_sessions);
    }
    close(app->sock_desc.fd);
    return 0;
}

static int __setup_socket(utp_application_t *app)
{
    int fd = -1;
    int on = 1;
    struct addrinfo hints, *res = NULL;
    struct sockaddr_in sin, *sinp = NULL;
    socklen_t len = sizeof(sin);
    char *local_host_str = "0.0.0.0";
    char *local_port_str = "50994";
    int ret = 0;

    if ((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        return -1;
    }

    if (0 != setsockopt(fd, SOL_IP, IP_RECVERR, &on, sizeof(on))) {
        goto L_ERROR_SOCKOPT;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;

    if (N_UTP_CLIENT == app->role) {
        local_port_str = "0";
    }

    if (0 == app->local_session.ip || 0 == app->local_session.port) {
        if (0 != (ret = getaddrinfo(local_host_str,
                    local_port_str, &hints, &res))) {
            LOG(UTP_LOG_LEVEL_ERR, "cannot get addr info host=%s,port=%s err=%s",
                    local_host_str, local_port_str, strerror(ret));
            goto L_ERROR_SOCKOPT;
        }
    }

    if (0 != bind(fd, res->ai_addr, res->ai_addrlen)) {
        goto L_ERROR_SOCKBIND;
    }

    if (0 != getsockname(fd, (struct sockaddr *)&sin, &len)) {
        goto L_ERROR_SOCKBIND;
    }

    LOG(UTP_LOG_LEVEL_INFO, "bind to %s:%d",
            inet_ntoa(sin.sin_addr), ntohs(sin.sin_port));
    app->sock_desc.fd = fd;

    return 0;

L_ERROR_SOCKBIND:
    freeaddrinfo(res);
L_ERROR_SOCKOPT:
    close(fd);
    return -1;
}

static void __utp_resp(utp_socket *sock)
{
    char data[1];

    if (NULL == sock) {
        return;
    }

    utp_write(sock, data, 1);
}

static void __main_loop(utp_application_t *app)
{
    struct pollfd poll_fd[1];
#define UTP_MAX_DATALEN     4096
#define UTP_MAX_SENDLEN     1449
    unsigned char data[UTP_MAX_DATALEN] = {0};
    unsigned char senddata[UTP_MAX_SENDLEN];
    int recvlen = 0;
    int sentlen = 0;
    int fd = app->sock_desc.fd;
    struct sockaddr_in src_addr;
    struct sockaddr_in dest_addr;
    socklen_t addrlen = sizeof(src_addr);
    utp_role_t role = app->role;
    int ret = 0;
    int per_send_cnt = 0;
    int per_send_gap = 2;
    int timeout = 0;
    uint64_t now = __now();;
    uint64_t last_send_ts = 0;
    uint64_t last_utptmo_check_ts = 0;
    uint64_t last_ack_ts = 0;
#define UTP_TIMEOUT_CHECK_INTERVAL    500

    if (0 == app->bitrate) {
        app->bitrate = 1 * 1024 * 1024;
    }

    if (500 < app->bitrate / (UTP_MAX_SENDLEN * 8)) {
        per_send_cnt = (app->bitrate / (UTP_MAX_SENDLEN * 8)) / 500;
        per_send_gap = 2;
    } else {
        per_send_gap = 1000 / (app->bitrate / (UTP_MAX_SENDLEN * 8));
        per_send_cnt = 1;
    }

    per_send_cnt = (0 == per_send_cnt) ? 1: per_send_cnt;

    app->running = 1;
    LOG(UTP_LOG_LEVEL_INFO, "per send cnt=%d gap=%d",
            per_send_cnt, per_send_gap);

    while (app->running) {
        poll_fd[0].fd = fd;
        poll_fd[0].events = POLLIN;

        ret = poll(poll_fd, 1, timeout);
        now = __now();
        if (0 < ret) {
            if (POLLIN == (poll_fd[0].revents & POLLIN)) {
                do {
                    recvlen = recvfrom(fd, data, sizeof(data),
                            MSG_DONTWAIT, (struct sockaddr *)&src_addr,
                            &addrlen);
                    if (recvlen < 0) {
                        if (EAGAIN == errno || EWOULDBLOCK == errno) {
                            utp_issue_deferred_acks(app->utp_desc.ctx);
                            break;
                        } else {
                            LOG(UTP_LOG_LEVEL_ERR, "socket error %s", strerror(errno));
                            return;
                        }
                    }

                    LOG(UTP_LOG_LEVEL_INFO, "recv %d bytes from %s:%d",
                            recvlen, inet_ntoa(src_addr.sin_addr),
                            ntohs(src_addr.sin_port));
                    if (0 == utp_process_udp(app->utp_desc.ctx, data,
                                recvlen, (struct sockaddr *)&src_addr,
                                addrlen)) {
                        LOG(UTP_LOG_LEVEL_WARN, "not handled by utp");
                    }
                } while (1);
            }
        } else if (0 == ret) {
            LOG(UTP_LOG_LEVEL_ERR, "socket timeout %s", strerror(errno));
        } else {
            LOG(UTP_LOG_LEVEL_ERR, "socket error %s", strerror(errno));
        }

        if (N_UTP_CLIENT == role && last_send_ts + per_send_gap <= now) {
            int i = 0;
            dest_addr.sin_family = AF_INET;
            dest_addr.sin_port = htons(app->remote_session.port);
            dest_addr.sin_addr.s_addr  = htonl(app->remote_session.ip);
            for (i = 0; i < per_send_cnt; i++) {
                if (0 == app->use_utp) {
                    sentlen = sendto(fd, senddata, UTP_MAX_SENDLEN, 0,
                            (struct sockaddr *)&dest_addr, addrlen);
                } else {
                    sentlen = utp_write(app->utp_desc.sock,
                            senddata, UTP_MAX_SENDLEN);
                    if (0 == sentlen) {
                        timeout = (per_send_gap < now - last_send_ts) ?
                            per_send_gap : (now - last_send_ts);
                        LOG(UTP_LOG_LEVEL_INFO, "adjust to wait for %d ms", timeout);
                        break;
                    }
                }

                if (0 < sentlen) {
                    LOG(UTP_LOG_LEVEL_INFO, "send %d bytes to %s:%d%s",
                            UTP_MAX_SENDLEN, inet_ntoa(dest_addr.sin_addr),
                            ntohs(dest_addr.sin_port),
                            (0 == app->use_utp) ? "" : " via utp");
                }
            }

            last_send_ts = now;
        } else if (N_UTP_SERVER == role) {
            timeout = UTP_TIMEOUT_CHECK_INTERVAL;
        }

        if (last_utptmo_check_ts + UTP_TIMEOUT_CHECK_INTERVAL <= now) {
            utp_check_timeouts(app->utp_desc.ctx);
        } else {
            timeout = UTP_TIMEOUT_CHECK_INTERVAL - (now - last_utptmo_check_ts);
        }
    }
}

static uint64 __log_handler(utp_callback_arguments *arg)
{
    LOG(UTP_LOG_LEVEL_INFO, "utp: %s", arg->buf);
    return 0;
}

static uint64 __sendto_handler(utp_callback_arguments *arg)
{
    struct sockaddr_in *sin = (struct sockaddr_in *)arg->address;
    char *sin_addr_str = inet_ntoa(sin->sin_addr);

    sendto(g_utp_app.sock_desc.fd, arg->buf, arg->len,
            0, arg->address, arg->address_len);
    LOG(UTP_LOG_LEVEL_INFO, "send utp packet %zd bytes", arg->len);

    return 0;
}

static uint64 __error_handler(utp_callback_arguments *arg)
{
    return 0;
}

static uint64 __state_change_handler(utp_callback_arguments *arg)
{
    utp_socket_stats *stats = NULL;

    switch (arg->state) {
    case UTP_STATE_CONNECT:
    case UTP_STATE_WRITABLE:
        __utp_resp(arg->socket);
        break;

    case UTP_STATE_EOF:
        utp_close(arg->socket);
        break;

    case UTP_STATE_DESTROYING:
        break;
    }

    return 0;
}

static uint64 __read_handler(utp_callback_arguments *arg)
{
    utp_read_drained(arg->socket);
    return 0;
}

static uint64 __firewall_handler(utp_callback_arguments *arg)
{
    return 0;
}

static uint64 __accept_handler(utp_callback_arguments *arg)
{
    g_utp_app.utp_desc.sock = arg->socket;
    __utp_resp(arg->socket);
    return 0;
}

static uint64 __get_mtu_handler(utp_callback_arguments *arg)
{
    return 1472;
}

static int __setup_utp(utp_application_t *app)
{
    utp_context *ctx = NULL;
    utp_socket  *sock = NULL;
    struct addrinfo hints, *res = NULL;
    struct sockaddr_in sin, *sinp = NULL;
    int ret = 0;

    if (NULL == (ctx = utp_init(2))) {
        return -1;
    }

    utp_set_callback(ctx, UTP_LOG,              &__log_handler);
    utp_set_callback(ctx, UTP_SENDTO,           &__sendto_handler);
    utp_set_callback(ctx, UTP_ON_ERROR,         &__error_handler);
    utp_set_callback(ctx, UTP_ON_STATE_CHANGE,  &__state_change_handler);
    utp_set_callback(ctx, UTP_ON_READ,          &__read_handler);
    utp_set_callback(ctx, UTP_ON_FIREWALL,      &__firewall_handler);
    utp_set_callback(ctx, UTP_ON_ACCEPT,        &__accept_handler);
    utp_set_callback(ctx, UTP_GET_UDP_MTU,      &__get_mtu_handler);

    if (UTP_LOG_LEVEL_INFO <= app->log_level) {
        utp_context_set_option(ctx, UTP_LOG_NORMAL, 1);
        utp_context_set_option(ctx, UTP_LOG_MTU,    1);
        utp_context_set_option(ctx, UTP_LOG_DEBUG,  1);
    }

    if (N_UTP_CLIENT == app->role) {
        if (NULL == (sock = utp_create_socket(ctx))) {
            goto L_ERROR_UTPSOCK;
        }

        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_protocol = IPPROTO_UDP;

        if (0 != (ret = getaddrinfo(app->remote_session.host_str,
                        app->remote_session.port_str, &hints, &res))) {
            LOG(UTP_LOG_LEVEL_ERR, "cannot get addr info %s:%s err=%s",
                    app->remote_session.host_str,
                    app->remote_session.port_str, strerror(ret));
            goto L_ERROR_UTPSOCK;
        }

        sinp = (struct sockaddr_in *)res->ai_addr;
        LOG(UTP_LOG_LEVEL_INFO, "connecting to %s:%d\n",
                inet_ntoa(sinp->sin_addr), ntohs(sinp->sin_port));

        utp_connect(sock, res->ai_addr, res->ai_addrlen);
        freeaddrinfo(res);

        app->utp_desc.sock = sock;
    }

    app->utp_desc.ctx = ctx;

    return 0;

L_ERROR_UTPSOCK:
    utp_destroy(ctx);
    return -1;
}

static int __final_utp(utp_application_t *app)
{
    utp_close(app->utp_desc.sock);
    utp_destroy(app->utp_desc.ctx);
}

int main(int argc, char *argv[])
{
    memset(&g_utp_app, 0x0, sizeof(g_utp_app));
    if (__parse_config(argc, argv, &g_utp_app) < 0) {
        return -1;
    }
    if (__setup_socket(&g_utp_app) < 0) {
        return -1;
    }
    if (__setup_utp(&g_utp_app) < 0) {
        return -1;
    }

    __main_loop(&g_utp_app);

    __final_utp(&g_utp_app);
    __final_socket(&g_utp_app);
    return 0;
}
