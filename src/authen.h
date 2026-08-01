/* TACACS+ authentication (RFC 8907 section 5): ASCII login only. */
#ifndef TAC_AUTHEN_H
#define TAC_AUTHEN_H

#include "config.h"
#include "packet.h"

/* Drives one ASCII-login exchange to completion, given the already-read
 * START packet (hdr/body/body_len). Prompts for username and/or password
 * over CONTINUE packets as needed, checks credentials against cfg, and
 * sends a final PASS/FAIL/ERROR reply. hdr is updated in place as the
 * session's sequence number advances. */
void tac_authen_handle(int fd, const char *key, const tac_config_t *cfg,
                        tac_header_t *hdr, const uint8_t *body, size_t body_len);

#endif
