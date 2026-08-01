/* TACACS+ authorization (RFC 8907 section 6): a single REQUEST/RESPONSE
 * exchange, no CONTINUE. This server does not evaluate individual
 * arguments -- it grants (PASS_ADD, adding no extra args) to any known
 * user and denies everyone else. */
#ifndef TAC_AUTHOR_H
#define TAC_AUTHOR_H

#include "config.h"
#include "packet.h"

void tac_author_handle(int fd, const char *key, const tac_config_t *cfg,
                        tac_header_t *hdr, const uint8_t *body, size_t body_len);

#endif
