/* TACACS+ accounting (RFC 8907 section 7): a single REQUEST/REPLY
 * exchange. This server does not persist accounting records anywhere
 * beyond a log line -- it always reports SUCCESS. */
#ifndef TAC_ACCT_H
#define TAC_ACCT_H

#include "config.h"
#include "packet.h"

void tac_acct_handle(int fd, const char *key, const tac_config_t *cfg,
                      tac_header_t *hdr, const uint8_t *body, size_t body_len);

#endif
