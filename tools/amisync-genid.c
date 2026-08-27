/* amisync-genid.c - identity generator for amisync
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 *
 * A standalone CLI tool, run once per device. It generates an Ed25519 keypair
 * and a self-signed certificate matching Syncthing's conventions, writes them
 * to ENVARC:Amisync/, and prints the derived Syncthing device ID. No
 * networking happens here - it links the ssl module only to bring up AmiSSL's
 * crypto, and the device_id module to derive the ID from the certificate.
 *
 *   amisync-genid            generate identity; refuses to clobber an existing one
 *   amisync-genid FORCE      overwrite an existing identity
 *   amisync-genid SHOWID     print the device ID of the existing cert, nothing else
 *
 * Key type is fixed at Ed25519 (Syncthing's current default, OID 1.3.101.112):
 * the smallest cert and fastest keygen on a 68k, and a byte-for-byte match for
 * modern Syncthing. No key-type selection is offered - a -keytype flag would be
 * added reactively only if a peer ever rejected Ed25519.
 */

#include <stdio.h>
#include <string.h>

#include <dos/dos.h>
#include <proto/dos.h>

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/bn.h>

#include "device_id.h"
#include "ssl.h"
#include "log.h"
#include "version.h"

/* AmigaOS $VER: cookie, so `Version amisync-genid` reports the version. */
static const char version_cookie[] __attribute__((used)) =
    AMISYNC_VERTAG("amisync-genid");

/* Identity lives in ENVARC: so it survives a reboot; the daemon reads it from
 * here. genid creates the directory if absent. */
#define IDENTITY_DIR  "ENVARC:Amisync"
#define KEY_PATH      "ENVARC:Amisync/key.pem"
#define CERT_PATH     "ENVARC:Amisync/cert.pem"
#define LOG_PATH      "T:amisync.log"

/* TLS and certificate work want more stack than the default. */
const char stack_size[] = "$STACK:16384";

static int has_arg(int argc, char **argv, const char *want)
{
    int i;
    for (i = 1; i < argc; i++)
        if (strcmp(argv[i], want) == 0)
            return 1;
    return 0;
}

/* True if a filesystem object exists at 'path'. */
static int path_exists(const char *path)
{
    BPTR lock = Lock((STRPTR)path, SHARED_LOCK);
    if (lock) {
        UnLock(lock);
        return 1;
    }
    return 0;
}

/* Ensure the identity directory exists, creating it if needed. Returns 1 if it
 * exists afterwards, 0 if it could not be created. */
static int ensure_dir(const char *path)
{
    BPTR lock = Lock((STRPTR)path, SHARED_LOCK);
    if (lock) {                 /* already there */
        UnLock(lock);
        return 1;
    }
    lock = CreateDir((STRPTR)path);
    if (lock) {
        UnLock(lock);
        return 1;
    }
    return 0;
}

/* Generate a fresh Ed25519 keypair, or NULL on failure. */
static EVP_PKEY *gen_ed25519(void)
{
    EVP_PKEY     *pkey = NULL;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);

    if (!pctx)
        return NULL;

    if (EVP_PKEY_keygen_init(pctx) <= 0 || EVP_PKEY_keygen(pctx, &pkey) <= 0)
        pkey = NULL;            /* keygen leaves pkey untouched on failure */

    EVP_PKEY_CTX_free(pctx);
    return pkey;
}

/* Build a self-signed certificate around 'pkey', matching Syncthing's
 * conventions, or NULL on failure. The caller owns the returned X509. */
static X509 *make_cert(EVP_PKEY *pkey)
{
    X509      *x  = X509_new();
    BIGNUM    *bn = NULL;
    X509_NAME *name;

    if (!x)
        return NULL;

    X509_set_version(x, 2);     /* X.509 v3 */

    /* Random 128-bit positive serial, as Syncthing uses. The serial does not
     * affect interop (the device ID is just SHA-256 of our whole cert), but a
     * random one avoids cross-device collisions and looks like Syncthing. */
    bn = BN_new();
    if (!bn || !BN_rand(bn, 128, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY) ||
        !BN_to_ASN1_INTEGER(bn, X509_get_serialNumber(x)))
        goto fail;

    /* Fixed validity window (R-3): a far-past notBefore and a year-2049
     * notAfter so that even an Amiga with a dead RTC battery - reading a wildly
     * wrong "now" - still falls inside the window. Syncthing ignores the
     * validity period during its own (cert-pinning) verification anyway. */
    if (!ASN1_TIME_set_string_X509(X509_getm_notBefore(x), "20000101000000Z") ||
        !ASN1_TIME_set_string_X509(X509_getm_notAfter(x),  "20490101000000Z"))
        goto fail;

    /* CN "syncthing": Syncthing uses a fixed CN; the identity comes from the
     * key, not the subject. Self-signed, so issuer == subject. */
    name = X509_get_subject_name(x);
    if (!X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                    (unsigned char *)"syncthing", -1, -1, 0))
        goto fail;
    if (!X509_set_issuer_name(x, name))
        goto fail;

    if (!X509_set_pubkey(x, pkey))
        goto fail;

    /* Ed25519 is PureEdDSA: the signing digest MUST be NULL. */
    if (!X509_sign(x, pkey, NULL))
        goto fail;

    BN_free(bn);
    return x;

fail:
    BN_free(bn);
    X509_free(x);
    return NULL;
}

/* Derive the device ID from an in-memory cert by serializing it to DER. */
static int compute_id(X509 *x, char out[DEVICE_ID_BUFSZ])
{
    unsigned char *der = NULL;
    int            len, ok = 0;

    len = i2d_X509(x, &der);
    if (len > 0)
        ok = device_id_from_cert_der(der, len, out);

    OPENSSL_free(der);
    return ok;
}

/* Write a PEM private key (unencrypted PKCS#8) to 'path'. */
static int write_pem_key(EVP_PKEY *pkey, const char *path)
{
    BIO *bio = BIO_new_file(path, "w");
    int  ok;

    if (!bio)
        return 0;
    ok = PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL);
    BIO_free_all(bio);
    return ok;
}

/* Write a PEM certificate to 'path'. */
static int write_pem_cert(X509 *x, const char *path)
{
    BIO *bio = BIO_new_file(path, "w");
    int  ok;

    if (!bio)
        return 0;
    ok = PEM_write_bio_X509(bio, x);
    BIO_free_all(bio);
    return ok;
}

int main(int argc, char **argv)
{
    int       force  = has_arg(argc, argv, "FORCE");
    int       showid = has_arg(argc, argv, "SHOWID");
    char      id[DEVICE_ID_BUFSZ];
    EVP_PKEY *pkey = NULL;
    X509     *cert = NULL;
    int       rc   = RETURN_ERROR;

    log_init(LOG_PATH, LOG_INFO);

    /* AmiSSL provides the keygen, certificate and SHA-256 machinery. */
    if (!ssl_open()) {
        printf("amisync-genid: cannot open AmiSSL/bsdsocket\n");
        log_printf(LOG_ERROR, "genid: ssl_open() failed");
        goto out;
    }

    if (showid) {
        if (!device_id_from_cert_file(CERT_PATH, id)) {
            printf("amisync-genid: no usable identity at %s\n", CERT_PATH);
            goto out;
        }
        printf("%s\n", id);
        log_printf(LOG_INFO, "genid: showid %s", id);
        rc = RETURN_OK;
        goto out;
    }

    if (!force && (path_exists(CERT_PATH) || path_exists(KEY_PATH))) {
        printf("amisync-genid: identity already exists in %s\n"
               "  use FORCE to overwrite, or SHOWID to print the current ID\n",
               IDENTITY_DIR);
        goto out;
    }

    if (!ensure_dir(IDENTITY_DIR)) {
        printf("amisync-genid: cannot create %s\n", IDENTITY_DIR);
        goto out;
    }

    if (!(pkey = gen_ed25519())) {
        printf("amisync-genid: Ed25519 key generation failed\n");
        goto out;
    }
    if (!(cert = make_cert(pkey))) {
        printf("amisync-genid: certificate generation failed\n");
        goto out;
    }
    if (!compute_id(cert, id)) {
        printf("amisync-genid: device ID derivation failed\n");
        goto out;
    }

    /* Write the key first, then the cert. */
    if (!write_pem_key(pkey, KEY_PATH)) {
        printf("amisync-genid: cannot write %s\n", KEY_PATH);
        goto out;
    }
    if (!write_pem_cert(cert, CERT_PATH)) {
        printf("amisync-genid: cannot write %s\n", CERT_PATH);
        goto out;
    }

    printf("amisync-genid: identity written to %s\n", IDENTITY_DIR);
    printf("Device ID: %s\n", id);
    log_printf(LOG_INFO, "genid: created identity, device ID %s", id);
    rc = RETURN_OK;

out:
    if (cert)
        X509_free(cert);
    if (pkey)
        EVP_PKEY_free(pkey);
    ssl_close();
    log_close();
    return rc;
}
