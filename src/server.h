#ifndef TAC_SERVER_H
#define TAC_SERVER_H

#include "config.h"

/* Binds/listens on cfg->port and serves connections forever, forking one
 * child per accepted TCP connection. Returns -1 on a fatal setup error (a
 * message has already been printed to stderr); otherwise never returns. */
int tac_server_run(const tac_config_t *cfg);

#endif
