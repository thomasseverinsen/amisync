/* bep.h - Block Exchange Protocol framing + handshake for amisync
 * Copyright (c) 2026 Thomas Severinsen, MIT licensed, see LICENSE
 *
 * BEP rides on top of a TLS 1.3 session. This module owns the wire framing and
 * the encode/decode of the core message set (Hello, ClusterConfig, Ping,
 * Close) using the pbuf codec. It is deliberately transport-agnostic: all I/O
 * goes through a caller-supplied read/write pair (BepTransport), so the daemon
 * wires it to an AmiSSL SSL object while the host unit tests wire it to an
 * in-memory buffer. That keeps bep free of AmiSSL and fully testable.
 *
 * Wire framing (all multi-byte integers big-endian), per the BEP v1 spec:
 *
 *   Hello (once, right after TLS):
 *       uint32  magic = 0x2EA7D90B
 *       uint16  length
 *       bytes   Hello protobuf
 *
 *   Every later message:
 *       uint16  headerLen
 *       bytes   Header protobuf   (type, compression)
 *       uint32  messageLen
 *       bytes   message protobuf  (LZ4-framed iff Header.compression == LZ4)
 */

#ifndef AMISYNC_BEP_H
#define AMISYNC_BEP_H

#include <stdint.h>

#define BEP_MAGIC          0x2EA7D90Bu

/* Header.type (MessageType) wire values - stable across Syncthing versions. */
#define BEP_CLUSTER_CONFIG     0
#define BEP_INDEX              1
#define BEP_INDEX_UPDATE       2
#define BEP_REQUEST            3
#define BEP_RESPONSE           4
#define BEP_DOWNLOAD_PROGRESS  5
#define BEP_PING               6
#define BEP_CLOSE              7

/* Header.compression (MessageCompression) wire values. */
#define BEP_COMPRESS_NONE      0
#define BEP_COMPRESS_LZ4       1

/* Sizing. A device ID raw key is the 32-byte SHA-256 of the peer cert.
 *
 * The per-connection scratch buffers (see BepConn) hold one BEP message at a
 * time. A Request/Response transfers one block, so a buffer must be able to hold
 * one block at our largest supported block size (folder.h FOLDER_MAX_BLOCK_SIZE
 * = 1 MiB) plus protobuf framing - that worst case is BEP_MSG_MAX, the hard
 * ceiling no message may exceed. But most connections only ever carry the
 * default 128 KiB block, so the buffers START at BEP_MSG_INIT and grow on demand
 * toward BEP_MSG_MAX (bep_conn_init + the internal ensure-cap path). A typical
 * connection therefore costs ~3x BEP_MSG_INIT, not ~3x BEP_MSG_MAX, and only a
 * connection that actually transfers a near-2 GiB file (1 MiB blocks) pays the
 * full ~3.2 MB. Kept independent of folder.h, but BEP_MSG_MAX MUST exceed
 * FOLDER_MAX_BLOCK_SIZE. */
#define BEP_DEVICE_KEY_LEN     32
#define BEP_MSG_INIT           ((128 + 16) * 1024)    /* 128 KiB block + framing */
/* Per-buffer starting sizes; each grows toward BEP_MSG_MAX on demand. 'out' is
 * sized so a full WK_INDEX_BATCH of ordinary records fits without a grow -
 * announcing is the hot path and should not realloc its way through a folder. */
#define BEP_WIRE_INIT          (16 * 1024)
#define BEP_PLAIN_INIT         (64 * 1024)
/* 'out' keeps the full size on purpose, and it is the one buffer NOT shrunk.
 * An index batch is built in it, so its capacity IS the batch size: records
 * carrying block hashes run to a few KB each, so 64 KB would hold a couple of
 * dozen where 144 KB holds three times as many, and the announce would send
 * proportionally more messages. That undoes the batching this was all built
 * around, for a folder of large files, to save 80 KB.
 *
 * (An earlier note here claimed a measurement showed exactly that. It did not:
 * that run had debug logging on, which writes a line per skipped record and was
 * the real cost. The reasoning above stands on its own; the number did not, and
 * a folder of tombstones like the test rig's could not have shown it either
 * way.) */
#define BEP_OUT_INIT           BEP_MSG_INIT
#define BEP_MSG_MAX            ((1024 + 64) * 1024)   /* 1 MiB block + 64 KiB margin */
#define BEP_NAME_MAX           64
#define BEP_VERSION_MAX        32
#define BEP_FOLDER_ID_MAX      64
#define BEP_MAX_FOLDERS        16
#define BEP_MAX_DEVICES        16

/* ---- transport abstraction ------------------------------------------ */

/* read: fill up to 'len' bytes; return bytes read (>0), 0 on clean EOF, -1 on
 * error. write: send 'len' bytes; return bytes written (>0) or -1 on error. */
typedef int (*BepReadFn)(void *ctx, void *buf, int len);
typedef int (*BepWriteFn)(void *ctx, const void *buf, int len);

typedef struct {
    void       *ctx;
    BepReadFn   read;
    BepWriteFn  write;
} BepTransport;

/* A live BEP connection: the transport plus the scratch buffers used to handle
 * one message at a time. 'wire'/'plain' are the receive side (raw, then
 * decompressed if LZ4); 'out' is the send side. The send buffer is kept
 * separate so encoding an outbound message never clobbers a received message we
 * are still reading - notably when handle_index() emits IndexUpdates while
 * iterating an inbound (decompressed) Index that lives in 'plain'.
 *
 * The three buffers are heap-allocated (not inline) so they can start small and
 * grow: all three share one capacity 'cap', sized at BEP_MSG_INIT by
 * bep_conn_init and raised toward BEP_MSG_MAX as larger messages are seen. A
 * connection only carrying default 128 KiB blocks stays at ~3x BEP_MSG_INIT.
 * Allocate the BepConn struct itself in the worker (still too big for the stack)
 * and call bep_conn_init before use, bep_conn_free at teardown. */
/* Every message is framed [uint16 headerLen][Header][uint32 bodyLen][body].
 * Written as four separate calls that is four TLS records - each with its own
 * record header, AEAD tag and socket write - to carry a body that is often
 * smaller than the framing around it. An index record is ~150 bytes and cost
 * four encrypted writes; announcing a 3385-record folder to three peers was
 * ~40000 of them, and measured out at ~58ms per record where the same bytes
 * as bulk data move in about one.
 *
 * So the frame is assembled in one buffer, and a body small enough to join it
 * is copied in and the whole message goes out as a SINGLE write. Index
 * records, ClusterConfigs, Requests and Close all fit. A block Response does
 * not and is written as frame-then-body, two writes rather than four, which
 * for 128 KiB of payload is noise either way.
 *
 * 2 KiB covers a FileInfo with a long name and ~48 block hashes. Anything
 * larger simply takes the two-write path, so the bound is a tuning knob and
 * never a correctness one. It lives in the (heap) BepConn rather than on the
 * stack: this code runs in detached subprocesses, and a couple of KB of stack
 * is not free there. */
#define BEP_COALESCE_MAX  2048
#define BEP_FRAME_MAX     22    /* 2 + max encoded Header (16) + 4 */

typedef struct {
    BepTransport   t;
    unsigned char *wire;    /* raw body as read off the wire              */
    unsigned char *plain;   /* decompressed body, if LZ4                  */
    unsigned char *out;     /* outbound message being encoded             */
    /* One capacity each, because their needs differ by an order of magnitude
     * and a shared cap made every connection pay the largest of them three
     * times over. 'wire' holds an inbound message, so it reaches block size on
     * a connection that RECEIVES files. 'out' holds an outbound one, so it
     * reaches block size only on one that SERVES them. 'plain' is the
     * compression scratch and the decompressed body - and Syncthing compresses
     * metadata only by default, so it usually stays at index-batch size and
     * never sees a 128 KiB block at all.
     *
     * All three still grow on demand toward BEP_MSG_MAX; they simply start at
     * what they are actually for rather than at the worst case of the worst of
     * them. */
    int32_t        wire_cap;
    int32_t        plain_cap;
    int32_t        out_cap;
    unsigned char  frame[BEP_FRAME_MAX + BEP_COALESCE_MAX];
} BepConn;

/* Allocate the three scratch buffers at BEP_MSG_INIT. Call once after zeroing
 * the BepConn and wiring up its transport; returns 1, or 0 on OOM. Does not
 * allocate the BepConn struct itself. Pair with bep_conn_free. */
int  bep_conn_init(BepConn *c);

/* Free the three scratch buffers (not the struct) and zero the pointers. Safe to
 * call on a zeroed/partly-initialised BepConn. */
void bep_conn_free(BepConn *c);

/* ---- message structures --------------------------------------------- */

typedef struct {
    char device_name[BEP_NAME_MAX];
    char client_name[BEP_NAME_MAX];
    char client_version[BEP_VERSION_MAX];
} BepHello;

typedef struct {
    int type;          /* one of the BEP_* message types       */
    int compression;   /* BEP_COMPRESS_NONE / BEP_COMPRESS_LZ4  */
} BepHeader;

typedef struct {
    unsigned char id[BEP_DEVICE_KEY_LEN];  /* raw 32-byte device key */
    char          name[BEP_NAME_MAX];
    /* Index metadata (BEP Device fields 6 and 8). Syncthing validates its
     * stored copy of a device's index against these on EVERY ClusterConfig:
     * a repeated CC claiming max_sequence BELOW what the peer has already
     * received from that device reads as an index regression and makes it
     * doubt the newest records. So the entry for OURSELVES must carry a
     * stable index_id and our folder's live sequence - implicit zeros only
     * survive because the handshake CC is graded leniently. */
    int64_t       max_sequence;
    uint64_t      index_id;
} BepDevice;

/* Folder.type (FolderType) wire values - match config's FolderMode. */
#define BEP_FOLDER_SEND_RECEIVE  0
#define BEP_FOLDER_SEND_ONLY     1
#define BEP_FOLDER_RECEIVE_ONLY  2

typedef struct {
    char      id[BEP_FOLDER_ID_MAX];
    char      label[BEP_NAME_MAX];
    int       type;                 /* BEP_FOLDER_* */
    BepDevice devices[BEP_MAX_DEVICES];
    int       num_devices;
} BepFolder;

/* ~30 KB (BEP_MAX_FOLDERS x BepFolder, each carrying BEP_MAX_DEVICES
 * devices): heap- or static-allocate it, never on a task stack. */
typedef struct {
    BepFolder folders[BEP_MAX_FOLDERS];
    int       num_folders;
} BepClusterConfig;

/* ---- Index / Request / Response -------------------------------------- */

/* FileInfo.type (FileInfoType). */
#define BEP_FILE_FILE        0
#define BEP_FILE_DIRECTORY   1
#define BEP_FILE_SYMLINK     4

/* Response.code (ErrorCode). */
#define BEP_ERR_NONE          0
#define BEP_ERR_GENERIC       1
#define BEP_ERR_NO_SUCH_FILE  2
#define BEP_ERR_INVALID_FILE  3

#define BEP_HASH_LEN        32           /* SHA-256 block / request hash */
#define BEP_PATH_MAX       256
#define BEP_MAX_BLOCKS      16           /* per-file cap (fixed buffers) */
/* Version-vector counters we store/parse per file. One per device that has
 * ever modified the file, so it must be >= the peers we support
 * (CONFIG_MAX_PEERS = 16) or a vector from a folder with more modifying
 * devices than that is truncated - losing updates and inventing false
 * conflicts. src/worker.c asserts the relation at compile time. */
#define BEP_MAX_COUNTERS    16

typedef struct {
    int64_t       offset;
    int32_t       size;
    unsigned char hash[BEP_HASH_LEN];
    int           has_hash;
} BepBlockInfo;

typedef struct {
    uint64_t id;
    uint64_t value;
} BepCounter;

typedef struct {
    BepCounter counters[BEP_MAX_COUNTERS];
    int        num_counters;
} BepVector;

typedef struct {
    char          name[BEP_PATH_MAX];
    int           type;
    int64_t       size;
    uint32_t      permissions;
    int64_t       modified_s;
    int32_t       modified_ns;
    uint64_t      modified_by;       /* short device ID of the last modifier -
                                      * informational (Syncthing shows it as
                                      * "Mod. Device" and in conflict names),
                                      * never part of conflict resolution     */
    int           deleted;
    int           invalid;
    int64_t       sequence;
    int32_t       block_size;
    BepVector     version;
    BepBlockInfo  blocks[BEP_MAX_BLOCKS];
    int           num_blocks;        /* total blocks (may exceed BEP_MAX_BLOCKS
                                      * when filled by the streaming decoder)   */
    /* Not wire fields: a locally-computed "blocksHash" (SHA-256 over the
     * concatenated per-block hashes, i.e. Syncthing's blocksHash). It is the
     * peer's authoritative content fingerprint when folded from a received
     * FileInfo's block hashes, and ours when folded on scan. Set by the worker
     * /folder layer (AmiSSL), never by the pure encode/decode here. */
    unsigned char content_hash[BEP_HASH_LEN];
    int           has_content_hash;
} BepFileInfo;

typedef struct {
    int32_t       id;
    char          folder[BEP_FOLDER_ID_MAX];
    char          name[BEP_PATH_MAX];
    int64_t       offset;
    int32_t       size;
    unsigned char hash[BEP_HASH_LEN];
    int           has_hash;
    int           from_temporary;
    int32_t       block_no;
} BepRequest;

typedef struct {
    int32_t              id;
    const unsigned char *data;     /* points into a caller buffer */
    int                  data_len;
    int                  code;      /* BEP_ERR_* */
} BepResponse;

/* Codec convention, here and under the handshake-codec banner below: each
 * returns 1 on success, 0 on failure (buffer too small / malformed). Encoders
 * write into 'buf'/'cap' and report the byte length via 'outlen'. Decoders read
 * 'len' bytes from 'buf' and skip unknown fields (forward compatibility with
 * newer Syncthing). All of it is pure and host-testable - no BepConn, no I/O. */
int bep_encode_file_info(const BepFileInfo *fi, void *buf, int cap, int *outlen);

/* Decodes blocks into fi->blocks (capped at BEP_MAX_BLOCKS). The daemon uses
 * the _cb form below instead - this one exists for the host tests and the
 * fuzzer, which want the whole entry in one struct. */
int bep_decode_file_info(const void *buf, int len, BepFileInfo *fi);

/* Streaming block callback: invoked once per BlockInfo while decoding a
 * FileInfo, so a caller can fold a content_hash / collect block hashes without
 * the decoder having to store an unbounded block array. Return 1 to continue,
 * 0 to abort the decode. 'index' is the 0-based block number. */
typedef int (*BepBlockFn)(void *ctx, int index, const BepBlockInfo *blk);

/* Like bep_decode_file_info but blocks are streamed to 'cb' (if non-NULL)
 * instead of stored in fi->blocks. fi->num_blocks is set to the total count
 * regardless. Lets the worker handle files with far more than BEP_MAX_BLOCKS. */
int bep_decode_file_info_cb(const void *buf, int len, BepFileInfo *fi,
                            BepBlockFn cb, void *ctx);

int bep_encode_request(const BepRequest *rq, void *buf, int cap, int *outlen);
int bep_decode_request(const void *buf, int len, BepRequest *rq);

int bep_encode_response(const BepResponse *rs, void *buf, int cap, int *outlen);
int bep_decode_response(const void *buf, int len, BepResponse *rs);

/* Cheap Index/IndexUpdate inspection without materializing every FileInfo:
 * extracts the folder name and counts the files. Returns 1 on success.
 * Test-facing, like the two array-materializing forms noted above and below:
 * the daemon reads indexes through bep_index_iter_*_cb only. */
int bep_index_summary(const void *buf, int len,
                      char folder[BEP_FOLDER_ID_MAX], int *num_files);

/* Encode an Index/IndexUpdate body: a folder id followed by 'n' FileInfo
 * entries. Returns 1 on success, 0 if it does not fit in 'cap'. */
int bep_encode_index(const char *folder, const BepFileInfo *files, int n,
                     void *buf, int cap, int *outlen);

/* Encode an Index/IndexUpdate carrying a single file whose block list is
 * supplied externally as 'num_blocks' SHA-256 hashes (so it need not fit in
 * BepFileInfo.blocks). Block geometry is derived: offset = i*meta->block_size,
 * size = min(block_size, meta->size - offset). 'meta' supplies every other
 * FileInfo field. Returns 1 on success, 0 if it does not fit. */
int bep_encode_index_file(const char *folder, const BepFileInfo *meta,
                          const unsigned char (*hashes)[BEP_HASH_LEN],
                          int num_blocks, void *buf, int cap, int *outlen);

/* ---- batched Index/IndexUpdate --------------------------------------
 *
 * An Index body is a folder id followed by REPEATED FileInfo entries, and
 * Syncthing packs many per message. Sending one message per file makes the
 * per-message cost - encode, frame, encrypt, write, and one trip through the
 * TCP stack - a per-FILE cost instead, which is what made announcing a folder
 * of a few thousand records take minutes on a 68k.
 *
 * A batch accumulates entries directly in the connection's own send buffer, so
 * nothing is copied twice and a big FileInfo (tens of KiB of block hashes) is
 * bounded by the same capacity as any other message. Fill it until add says
 * no, send, begin again:
 *
 *     bep_index_batch_begin(c, &b, folder_id);
 *     for (...) {
 *         if (!bep_index_batch_add(&b, &fi, hashes, nb)) {
 *             if (!bep_send_index_batch(c, type, &b)) return 0;
 *             bep_index_batch_begin(c, &b, folder_id);
 *             if (!bep_index_batch_add(&b, &fi, hashes, nb))
 *                 ... one record too big for an empty batch: send it alone ...
 *         }
 *     }
 *     if (b.num && !bep_send_index_batch(c, type, &b)) return 0;
 *
 * A failed add leaves the batch exactly as it was, so the caller can always
 * flush what it has and retry the entry that did not fit. */
typedef struct {
    unsigned char *buf;      /* the connection's send buffer   */
    int            cap;
    int            len;      /* bytes of body written so far   */
    int            num;      /* FileInfo entries appended      */
    int            error;    /* set if begin could not even write the folder */
} BepIndexBatch;

/* Start a batch in c's send buffer, writing the folder id. */
void bep_index_batch_begin(BepConn *c, BepIndexBatch *b, const char *folder);

/* Append one FileInfo. Returns 1 if it went in, 0 if it did not fit (batch
 * unchanged) or the batch is in error. */
int  bep_index_batch_add(BepIndexBatch *b, const BepFileInfo *meta,
                         const unsigned char (*hashes)[BEP_HASH_LEN],
                         int num_blocks);

/* Send the accumulated batch as one message. Returns the transport result;
 * sending an empty batch is a no-op success. */
int  bep_send_index_batch(BepConn *c, int type, BepIndexBatch *b);

/* Walk the FileInfo entries of an Index/IndexUpdate body without copying it all
 * at once. Begin extracts the folder id (into 'folder') and arms the iterator;
 * each next() decodes the following FileInfo into 'fi' and returns 1, or 0 when
 * the entries are exhausted (check it->error to tell "done" from "malformed").
 * The body buffer must outlive the iteration. */
typedef struct {
    const unsigned char *p;
    const unsigned char *end;
    int                  error;
} BepIndexIter;

void bep_index_iter_begin(BepIndexIter *it, const void *buf, int len,
                          char folder[BEP_FOLDER_ID_MAX]);

/* Test-facing, as bep_decode_file_info: materializes the entry's blocks. */
int  bep_index_iter_next(BepIndexIter *it, BepFileInfo *fi);

/* As bep_index_iter_next, but streams the entry's blocks to 'cb' (see
 * bep_decode_file_info_cb) instead of materializing them. */
int  bep_index_iter_next_cb(BepIndexIter *it, BepFileInfo *fi,
                            BepBlockFn cb, void *ctx);

/* ---- handshake codecs (pure, host-testable) ------------------------- */

int bep_encode_hello(const BepHello *h, void *buf, int cap, int *outlen);
int bep_decode_hello(const void *buf, int len, BepHello *h);

int bep_encode_header(const BepHeader *hdr, void *buf, int cap, int *outlen);
int bep_decode_header(const void *buf, int len, BepHeader *hdr);

int bep_encode_cluster_config(const BepClusterConfig *cc, void *buf, int cap, int *outlen);
int bep_decode_cluster_config(const void *buf, int len, BepClusterConfig *cc);

/* ---- framed transport ----------------------------------------------- */

/* Every sender below returns 1 on success, 0 on failure; bep_read_message is
 * the one exception and documents its own tri-state return. */

/* Send the Hello frame (magic + length + encoded Hello). Returns 1/0. */
int bep_send_hello(BepConn *c, const BepHello *local);

/* Read the peer's Hello frame, validating the magic. Returns 1/0. */
int bep_read_hello(BepConn *c, BepHello *remote);

/* Send a post-Hello message. Metadata messages >= 1 KiB are LZ4-compressed
 * when that shrinks them; block Responses are always sent uncompressed
 * (Syncthing's own default - file data rarely compresses, and the LZ4 pass
 * over every served block is pure CPU cost on the 68k). LZ4 is always decoded
 * on receive. 'msg'/'msglen' is the already-encoded message body. */
int bep_send_message(BepConn *c, int type, const void *msg, int msglen);

/* Convenience wrappers around bep_send_message. */
int bep_send_cluster_config(BepConn *c, const BepClusterConfig *cc);
int bep_send_ping(BepConn *c);
int bep_send_close(BepConn *c, const char *reason);

/* Send a Request / Response / Index as a framed message. bep_send_index takes
 * the message type (BEP_INDEX or BEP_INDEX_UPDATE). */
int bep_send_request(BepConn *c, const BepRequest *rq);
int bep_send_response(BepConn *c, const BepResponse *rs);
int bep_send_index(BepConn *c, int type, const char *folder,
                   const BepFileInfo *files, int n);

/* Send an Index/IndexUpdate for one file with an external block-hash list (see
 * bep_encode_index_file). */
int bep_send_index_file(BepConn *c, int type, const char *folder,
                        const BepFileInfo *meta,
                        const unsigned char (*hashes)[BEP_HASH_LEN],
                        int num_blocks);

/* Read one post-Hello message. On success fills *hdr, points *body at the
 * decoded (decompressed if needed) message body inside the BepConn, and sets
 * *bodylen. The pointer is valid until the next read. Returns 1 on success, 0
 * on clean EOF/peer close, -1 on error. */
int bep_read_message(BepConn *c, BepHeader *hdr,
                     const unsigned char **body, int *bodylen);

/* Do the opening exchange: send our Hello, read the peer's Hello, then send
 * our ClusterConfig. After this the caller runs the idle loop (read messages,
 * send periodic Pings). Returns 1 on success, 0 on failure. */
int bep_handshake(BepConn *c, const BepHello *local, BepHello *remote,
                  const BepClusterConfig *cc);

#endif /* AMISYNC_BEP_H */
