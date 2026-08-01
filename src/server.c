#include "server.h"

#include "acct.h"
#include "authen.h"
#include "author.h"
#include "io.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void handle_connection(int fd, const tac_config_t *cfg)
{
    for (;;) {
        tac_header_t hdr;
        uint8_t *body = NULL;
        size_t body_len = 0;
        if (tac_read_packet(fd, cfg->key, &hdr, &body, &body_len) != 0) {
            free(body);
            break;
        }

        switch (hdr.type) {
        case TAC_PLUS_AUTHEN:
            tac_authen_handle(fd, cfg->key, cfg, &hdr, body, body_len);
            break;
        case TAC_PLUS_AUTHOR:
            tac_author_handle(fd, cfg->key, cfg, &hdr, body, body_len);
            break;
        case TAC_PLUS_ACCT:
            tac_acct_handle(fd, cfg->key, cfg, &hdr, body, body_len);
            break;
        default:
            break;
        }

        free(body);
    }
}

int tac_server_run(const tac_config_t *cfg)
{
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("socket");
        return -1;
    }

    int one = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((uint16_t)cfg->port);

    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(listen_fd);
        return -1;
    }

    if (listen(listen_fd, 16) < 0) {
        perror("listen");
        close(listen_fd);
        return -1;
    }

    /* Auto-reap children so connection handlers never become zombies. */
    signal(SIGCHLD, SIG_IGN);

    fprintf(stderr, "tacacs: listening on port %d\n", cfg->port);

    for (;;) {
        struct sockaddr_in peer;
        socklen_t peer_len = sizeof(peer);
        int conn_fd = accept(listen_fd, (struct sockaddr *)&peer, &peer_len);
        if (conn_fd < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("accept");
            continue;
        }

        pid_t pid = fork();
        if (pid < 0) {
            perror("fork");
            close(conn_fd);
            continue;
        }
        if (pid == 0) {
            close(listen_fd);
            handle_connection(conn_fd, cfg);
            close(conn_fd);
            exit(0);
        }
        close(conn_fd);
    }
}
