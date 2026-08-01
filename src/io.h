/* Reads/writes whole TACACS+ packets on a connected socket, handling the
 * body obfuscation transparently. */
#ifndef TAC_IO_H
#define TAC_IO_H

#include "packet.h"

/* Reads one full packet from fd and decrypts the body in place (unless
 * TAC_PLUS_UNENCRYPTED_FLAG is set). On success *body_out is a malloc'd
 * buffer the caller must free (NULL if the body is empty). Returns 0 on
 * success, -1 on I/O error, EOF, or a malformed header. */
int tac_read_packet(int fd, const char *key, tac_header_t *hdr, uint8_t **body_out, size_t *body_len_out);

/* Writes header + body (encrypting a copy of body first unless
 * TAC_PLUS_UNENCRYPTED_FLAG is set). Returns 0 on success, -1 on I/O error. */
int tac_write_packet(int fd, const char *key, const tac_header_t *hdr, const uint8_t *body, size_t body_len);

#endif
