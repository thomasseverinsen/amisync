/* device_id.c - Syncthing device ID derivation and parsing for amisync
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 *
 * The derivation (base32 + mod-32 Luhn + chunking) must reproduce Syncthing
 * byte-for-byte; it is checked against a verified reference vector in
 * tests/test_device_id.c. The bit-twiddling lives in pure static helpers so
 * that unit check can run on the build host with no AmiSSL/OpenSSL present:
 * defining DEVICE_ID_HOST_TEST excludes the certificate-input functions.
 */

#include <string.h>
#include <ctype.h>

#include "device_id.h"

#ifndef DEVICE_ID_HOST_TEST
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#endif

/* RFC 4648 base32 alphabet, the same one Syncthing's device IDs use. */
static const char B32_ALPHA[32] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/* Map a base32 character (assumed already upper-cased) to its 0..31 value,
 * or -1 if it is not in the alphabet. */
static int b32_index(char c)
{
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= '2' && c <= '7')
        return 26 + (c - '2');
    return -1;
}

/* Compute the mod-32 Luhn check character over the first 'n' base32 chars of
 * 's'. This is the Luhn algorithm carried out in the 32-symbol alphabet, NOT
 * decimal Luhn: the factor alternates 1/2, each product is folded with
 * addend = addend/32 + addend%32, and the check is (32 - sum%32) % 32. */
static char luhn32(const char *s, int n)
{
    int factor = 1, sum = 0, i;

    for (i = 0; i < n; i++) {
        int addend = factor * b32_index(s[i]);
        factor = (factor == 2) ? 1 : 2;
        addend = addend / 32 + addend % 32;
        sum += addend;
    }
    return B32_ALPHA[(32 - sum % 32) % 32];
}

/* Base32-encode exactly 32 bytes into 52 characters (RFC 4648, no padding).
 * 'out' receives 52 chars and is not NUL-terminated. */
static void b32_encode_256(const unsigned char *in, char *out)
{
    unsigned long buffer = 0;
    int bits = 0, idx = 0, i;

    for (i = 0; i < 32; i++) {
        buffer = (buffer << 8) | in[i];
        bits += 8;
        while (bits >= 5) {
            out[idx++] = B32_ALPHA[(buffer >> (bits - 5)) & 31];
            bits -= 5;
        }
        buffer &= (1UL << bits) - 1;
    }
    /* 256 bits leaves 1 bit over; left-align it into a final char. */
    if (bits > 0)
        out[idx++] = B32_ALPHA[(buffer << (5 - bits)) & 31];
}

/* Turn a 32-byte hash into the formatted device ID. 'out' is DEVICE_ID_BUFSZ.
 * The 52 base32 chars become 56 after a Luhn check char is inserted per
 * 13-char chunk, then they are regrouped into 8 runs of 7 joined by '-'. */
void device_id_from_raw(const unsigned char hash[32], char out[DEVICE_ID_BUFSZ])
{
    char b32[52];
    char luhned[56];
    char *d, *o;
    int i, g;

    b32_encode_256(hash, b32);

    d = luhned;
    for (i = 0; i < 4; i++) {
        memcpy(d, b32 + i * 13, 13);
        d += 13;
        *d++ = luhn32(b32 + i * 13, 13);
    }

    o = out;
    for (g = 0; g < 8; g++) {
        if (g)
            *o++ = '-';
        memcpy(o, luhned + g * 7, 7);
        o += 7;
    }
    *o = '\0';
}

int device_id_normalize(const char *in, char out[DEVICE_ID_BUFSZ])
{
    char canon[56];
    int n = 0, i;

    if (!in)
        return 0;

    for (; *in; in++) {
        char c = *in;
        if (c == '-' || isspace((unsigned char)c))
            continue;
        c = (char)toupper((unsigned char)c);
        if (b32_index(c) < 0)
            return 0;
        if (n >= 56)
            return 0;
        canon[n++] = c;
    }
    if (n != 56)
        return 0;

    /* The canonical form is four 14-char chunks: 13 data chars + 1 Luhn check.
     * Re-derive each check char and reject on any mismatch. */
    for (i = 0; i < 4; i++) {
        if (luhn32(canon + i * 14, 13) != canon[i * 14 + 13])
            return 0;
    }

    memcpy(out, canon, 56);
    out[56] = '\0';
    return 1;
}

int device_id_equal(const char *a, const char *b)
{
    char na[DEVICE_ID_BUFSZ], nb[DEVICE_ID_BUFSZ];

    if (!device_id_normalize(a, na) || !device_id_normalize(b, nb))
        return 0;
    return strcmp(na, nb) == 0;
}

int device_id_to_raw(const char *in, unsigned char out[32])
{
    char canon[DEVICE_ID_BUFSZ];
    char b32[52];
    unsigned long buffer = 0;
    int i, di = 0, bits = 0, oi = 0;

    if (!device_id_normalize(in, canon))
        return 0;

    /* The 56-char canonical form is four 14-char chunks of 13 data chars + 1
     * Luhn check; drop the four check chars to recover the 52 base32 data
     * chars, then base32-decode them to 32 bytes (260 bits -> 256 + 4 spare). */
    for (i = 0; i < 56; i++)
        if (i % 14 != 13)
            b32[di++] = canon[i];

    for (i = 0; i < 52; i++) {
        buffer = (buffer << 5) | (unsigned long)b32_index(b32[i]);
        bits += 5;
        if (bits >= 8) {
            out[oi++] = (unsigned char)((buffer >> (bits - 8)) & 0xff);
            bits -= 8;
        }
    }
    return oi == 32;
}

#ifndef DEVICE_ID_HOST_TEST

int device_id_from_cert_der(const unsigned char *der, int len,
                            char out[DEVICE_ID_BUFSZ])
{
    unsigned char hash[32];

    if (!der || len <= 0)
        return 0;

    SHA256(der, (size_t)len, hash);
    device_id_from_raw(hash, out);
    return 1;
}

int device_id_from_cert_file(const char *pem_path, char out[DEVICE_ID_BUFSZ])
{
    BIO *bio;
    X509 *cert;
    unsigned char *der = NULL;
    int len, ok = 0;

    if (!pem_path)
        return 0;

    bio = BIO_new_file(pem_path, "r");
    if (!bio)
        return 0;

    cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!cert)
        return 0;

    len = i2d_X509(cert, &der);
    if (len > 0)
        ok = device_id_from_cert_der(der, len, out);

    OPENSSL_free(der);
    X509_free(cert);
    return ok;
}

#endif /* DEVICE_ID_HOST_TEST */
