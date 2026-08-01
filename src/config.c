#define _POSIX_C_SOURCE 200809L

#include "config.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *next_token(char **saveptr)
{
    char *tok;
    do {
        tok = strtok_r(NULL, " \t\r\n", saveptr);
    } while (tok != NULL && strcmp(tok, "=") == 0);
    return tok;
}

int tac_config_load(const char *path, tac_config_t *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->port = 49; /* the IANA-assigned TACACS+ port */

    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "tacacs: cannot open config file '%s': %s\n", path, strerror(errno));
        return -1;
    }

    char line[512];
    int lineno = 0;
    while (fgets(line, sizeof(line), f)) {
        lineno++;
        char *saveptr;
        char *cmd = strtok_r(line, " \t\r\n", &saveptr);
        if (!cmd || cmd[0] == '#') {
            continue;
        }

        if (strcmp(cmd, "key") == 0) {
            char *val = next_token(&saveptr);
            if (!val) {
                fprintf(stderr, "tacacs: %s:%d: 'key' requires a value\n", path, lineno);
                fclose(f);
                return -1;
            }
            strncpy(cfg->key, val, sizeof(cfg->key) - 1);
        } else if (strcmp(cmd, "port") == 0) {
            char *val = next_token(&saveptr);
            if (!val) {
                fprintf(stderr, "tacacs: %s:%d: 'port' requires a value\n", path, lineno);
                fclose(f);
                return -1;
            }
            cfg->port = atoi(val);
        } else if (strcmp(cmd, "user") == 0) {
            char *username = next_token(&saveptr);
            char *password = next_token(&saveptr);
            if (!username || !password) {
                fprintf(stderr, "tacacs: %s:%d: 'user' requires <name> <password>\n", path, lineno);
                fclose(f);
                return -1;
            }
            tac_user_t *u = calloc(1, sizeof(*u));
            if (!u) {
                fclose(f);
                return -1;
            }
            strncpy(u->username, username, sizeof(u->username) - 1);
            strncpy(u->password, password, sizeof(u->password) - 1);
            u->next = cfg->users;
            cfg->users = u;
        } else {
            fprintf(stderr, "tacacs: %s:%d: unknown directive '%s'\n", path, lineno, cmd);
            fclose(f);
            return -1;
        }
    }

    fclose(f);

    if (cfg->key[0] == '\0') {
        fprintf(stderr, "tacacs: config file '%s' must set 'key'\n", path);
        tac_config_free(cfg);
        return -1;
    }

    return 0;
}

void tac_config_free(tac_config_t *cfg)
{
    tac_user_t *u = cfg->users;
    while (u) {
        tac_user_t *next = u->next;
        free(u);
        u = next;
    }
    cfg->users = NULL;
}

const tac_user_t *tac_config_find_user(const tac_config_t *cfg, const char *username)
{
    for (const tac_user_t *u = cfg->users; u; u = u->next) {
        if (strcmp(u->username, username) == 0) {
            return u;
        }
    }
    return NULL;
}
