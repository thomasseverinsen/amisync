/* test_device_id.c - host unit check for the device_id derivation
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 *
 * Built and run on the build host with plain cc (see `make test`), NOT
 * cross-compiled. It exercises the pure base32 + mod-32 Luhn + chunking logic
 * against Syncthing's own published reference vector, so it needs no AmiSSL or
 * OpenSSL. DEVICE_ID_HOST_TEST excludes the certificate-input functions and
 * lets us reach the static derivation helper directly.
 */

#define DEVICE_ID_HOST_TEST
#include "../src/device_id.c"

#include <stdio.h>

static int failures;

static void check_str(const char *what, const char *got, const char *want)
{
    if (strcmp(got, want) != 0) {
        printf("FAIL %s:\n  got  %s\n  want %s\n", what, got, want);
        failures++;
    } else {
        printf("ok   %s\n", what);
    }
}

static void check_int(const char *what, int got, int want)
{
    if (got != want) {
        printf("FAIL %s: got %d, want %d\n", what, got, want);
        failures++;
    } else {
        printf("ok   %s\n", what);
    }
}

int main(void)
{
    /* SYNCTHING'S OWN reference vector, from lib/protocol/deviceid_test.go,
     * where it is the 'formatted' constant every parse case must produce.
     * The 32 bytes are that string decoded: dashes out, each group's Luhn
     * check digit dropped, the remaining 52 base32 characters decoded.
     *
     * Deliberately upstream's rather than one of ours. A vector we generated
     * with this same code would only prove the code agrees with itself; this
     * one proves it agrees with the implementation it has to interoperate
     * with. It also keeps a real device's ID out of a public repository -
     * this file used to carry the author's own. */
    static const unsigned char hash[32] = {
        0x7f, 0x7c, 0x87, 0x23, 0xec, 0xca, 0x5b, 0x4d,
        0x22, 0x06, 0x1c, 0x49, 0x81, 0xb3, 0x4c, 0x34,
        0xd8, 0x65, 0xec, 0x37, 0x6b, 0xe1, 0xeb, 0x74,
        0x33, 0x08, 0x73, 0xc9, 0xa6, 0xf9, 0xb2, 0x05
    };
    static const char *expect =
        "P56IOI7-MZJNU2Y-IQGDREY-DM2MGTI-MGL3BXN-PQ6W5BM-TBBZ4TJ-XZWICQ2";

    char id[DEVICE_ID_BUFSZ];
    char norm[DEVICE_ID_BUFSZ];
    char messy[80];
    char bad[80];
    size_t i;

    /* The headline check: derivation must reproduce the reference ID. */
    device_id_from_raw(hash, id);
    check_str("derive id from reference hash", id, expect);

    /* normalize accepts the formatted id and yields the 56-char canonical. */
    check_int("normalize accepts valid id", device_id_normalize(expect, norm), 1);
    check_int("canonical length is 56", (int)strlen(norm), 56);

    /* Case and dashes are not significant. */
    for (i = 0; expect[i]; i++)
        messy[i] = (char)tolower((unsigned char)expect[i]);
    messy[i] = '\0';
    {
        char n2[DEVICE_ID_BUFSZ];
        check_int("normalize accepts lower-case", device_id_normalize(messy, n2), 1);
        check_str("normalize is case/dash-insensitive", n2, norm);
    }
    check_int("equal: formatted vs lower-case", device_id_equal(expect, messy), 1);

    /* A single corrupted character must fail the Luhn check. */
    strcpy(bad, expect);
    bad[0] = (bad[0] == 'K') ? 'L' : 'K';
    check_int("normalize rejects corrupted id", device_id_normalize(bad, norm), 0);
    check_int("equal: id vs corrupted", device_id_equal(expect, bad), 0);

    /* to_raw inverts the derivation: decoding the reference ID must reproduce
     * the original 32-byte hash exactly. */
    {
        unsigned char raw[32];
        check_int("to_raw accepts valid id", device_id_to_raw(expect, raw), 1);
        check_int("to_raw reproduces hash", memcmp(raw, hash, 32), 0);
    }

    /* from_raw is the public formatter (used for discovered-device IDs): it must
     * reproduce the reference ID, and round-trip with to_raw. */
    {
        char          fr[DEVICE_ID_BUFSZ];
        unsigned char raw[32];
        device_id_from_raw(hash, fr);
        check_str("from_raw reproduces reference id", fr, expect);
        device_id_to_raw(fr, raw);
        check_int("from_raw round-trips to_raw", memcmp(raw, hash, 32), 0);
    }

    /* Wrong length and illegal characters are rejected. */
    check_int("normalize rejects short id", device_id_normalize("ABC", norm), 0);
    check_int("normalize rejects bad char (0/1/8)",
              device_id_normalize("K01U65V-NAYB5J5-X6RSLVX-HAL336V-"
                                  "MGL3BXN-PQ6W5BM-TBBZ4TJ-XZWICQ2", norm), 0);

    if (failures) {
        printf("\n%d check(s) FAILED\n", failures);
        return 1;
    }
    printf("\nall device_id checks passed\n");
    return 0;
}
