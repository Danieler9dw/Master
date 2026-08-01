/* Minimal config file format:
 *
 *   key = <shared secret>
 *   port = <tcp port>          (optional, defaults to 49)
 *   user <name> <password>     (one line per user)
 *
 * Lines starting with '#' and blank lines are ignored.
 */
#ifndef TAC_CONFIG_H
#define TAC_CONFIG_H

#define TAC_MAX_KEY_LEN 128
#define TAC_MAX_USERNAME_LEN 64
#define TAC_MAX_PASSWORD_LEN 64

typedef struct tac_user {
    char username[TAC_MAX_USERNAME_LEN];
    char password[TAC_MAX_PASSWORD_LEN];
    struct tac_user *next;
} tac_user_t;

typedef struct {
    char key[TAC_MAX_KEY_LEN];
    int port;
    tac_user_t *users;
} tac_config_t;

/* Returns 0 on success, -1 on error (a message is printed to stderr). */
int tac_config_load(const char *path, tac_config_t *cfg);
void tac_config_free(tac_config_t *cfg);

const tac_user_t *tac_config_find_user(const tac_config_t *cfg, const char *username);

#endif
