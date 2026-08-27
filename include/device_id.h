/* device_id.h - Syncthing device ID derivation and parsing for amisync
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 *
 * A Syncthing device ID is derived from a node's self-signed certificate:
 *
 *     raw   = SHA-256(DER-encoded certificate)            32 bytes
 *     b32   = base32(raw)                                 52 chars (RFC 4648,
 *                                                         A-Z2-7, no padding)
 *     luhn  = + one mod-32 Luhn check char per 13 chars   56 chars
 *     id    = group into 8 runs of 7, joined with '-'     63 chars
 *
 * This module is deliberately free of socket and protobuf dependencies so the
 * genid tool can link it without dragging the rest of the daemon in. The
 * cert-input functions use AmiSSL's OpenSSL API; the caller must have opened
 * AmiSSL first (see the ssl module). The string functions are pure.
 */

#ifndef AMISYNC_DEVICE_ID_H
#define AMISYNC_DEVICE_ID_H

/* Length of a formatted device ID ("ABCDEFG-...", 8x7 + 7 dashes) and the
 * buffer size that holds it including the NUL terminator. The same buffer
 * comfortably holds the 56-char canonical (dash-free) form too. */
#define DEVICE_ID_LEN    63
#define DEVICE_ID_BUFSZ  64

/* Derive the formatted device ID from a DER-encoded certificate. 'out' must
 * be at least DEVICE_ID_BUFSZ bytes. Returns 1 on success, 0 on bad input.
 * Requires AmiSSL to be open in the calling process. */
int device_id_from_cert_der(const unsigned char *der, int len,
                            char out[DEVICE_ID_BUFSZ]);

/* As above, reading a PEM certificate from 'pem_path' (an AmigaOS path such
 * as "ENVARC:Amisync/cert.pem"). Returns 1 on success, 0 if the file cannot
 * be read or parsed. Requires AmiSSL to be open in the calling process. */
int device_id_from_cert_file(const char *pem_path, char out[DEVICE_ID_BUFSZ]);

/* Normalize a device ID into its canonical comparison form: dashes and
 * whitespace stripped, upper-cased, validated against the mod-32 Luhn check.
 * Writes the 56-char canonical form to 'out' (DEVICE_ID_BUFSZ). Returns 1 if
 * 'in' is a well-formed device ID, 0 otherwise. Pure (no AmiSSL needed). */
int device_id_normalize(const char *in, char out[DEVICE_ID_BUFSZ]);

/* Compare two device IDs for identity, tolerating differences in case,
 * dashes and surrounding whitespace. Returns 1 if both normalize and are
 * equal, 0 otherwise. Pure (no AmiSSL needed). */
int device_id_equal(const char *a, const char *b);

/* Decode a (formatted or canonical) device ID back into the raw 32-byte key
 * it was derived from - i.e. the SHA-256 of the certificate. This is what goes
 * on the wire as a BEP Device.id or a discovery Announce.id. Returns 1 on a
 * well-formed ID, 0 otherwise. Pure (no AmiSSL needed). */
int device_id_to_raw(const char *in, unsigned char out[32]);

/* Format a raw 32-byte device key (e.g. from a discovery Announce.id) into the
 * displayed device ID string. The inverse of device_id_to_raw(). 'out' is
 * DEVICE_ID_BUFSZ. Any 32 bytes are valid, so this cannot fail. Pure. */
void device_id_from_raw(const unsigned char raw[32], char out[DEVICE_ID_BUFSZ]);

#endif /* AMISYNC_DEVICE_ID_H */
