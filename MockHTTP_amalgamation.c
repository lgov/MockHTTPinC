/* Copyright 2014 Lieven Govaerts
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef MockHTTP_private_H
#define MockHTTP_private_H

#include <apr_pools.h>
#include <apr_hash.h>
#include <apr_tables.h>
#include <apr_poll.h>
#include <apr_time.h>
#include <apr_thread_proc.h>

#include "MockHTTP.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define MH_VERBOSE 0

/* Simple macro to return from function when status != 0
   expects 'apr_status_t status;' declaration. */
#define STATUSERR(x) if ((status = (x))) return status;

#define READ_ERROR(status) ((status) \
                                && !APR_STATUS_IS_EOF(status) \
                                && !APR_STATUS_IS_EAGAIN(status))

#define STATUSREADERR(x) if (((status = (x)) && READ_ERROR(status)))\
                            return status;

#define MH_STATUS_START (APR_OS_START_USERERR + 1500)

/* This code indicates that the server is waiting for a timed event */
#define MH_STATUS_WAITING (MH_STATUS_START + 1)

#define MH_STATUS_INCOMPLETE_REQUEST (MH_STATUS_START + 1)

typedef short int bool;
static const bool YES = 1;
static const bool NO = 0;

typedef struct _mhClientCtx_t _mhClientCtx_t;

typedef enum expectation_t {
    RequestsReceivedOnce    = 0x00000001,
    RequestsReceivedInOrder = 0x00000002,
} expectation_t;

struct MockHTTP {
    apr_pool_t *pool;
    mhServCtx_t *servCtx;
    char *errmsg;
    unsigned long expectations;
    mhStats_t *verifyStats;             /* Statistics gathered by the server */
    mhResponse_t *defResponse;          /* Default req matched response */
    mhResponse_t *defErrorResponse;     /* Default req not matched response */
    mhServCtx_t *proxyCtx;
    apr_array_header_t *connMatchers;   /* array of mhConnMatcherBldr_t *'s */
    apr_array_header_t *reqMatchers;    /* array of ReqMatcherRespPair_t *'s */
    apr_array_header_t *incompleteReqMatchers;       /*       .... same type */
};

typedef struct ReqMatcherRespPair_t {
    mhRequestMatcher_t *rm;
    mhResponse_t *resp;
    mhAction_t action;
} ReqMatcherRespPair_t;

typedef enum servMode_t {
    ModeServer,
    ModeProxy,
    ModeTunnel,
} servMode_t;


typedef enum loopRequestState_t {
    NoReqsReceived = 0,
    PartialReqReceived = 1,
    FullReqReceived = 2,
} loopRequestState_t;

struct mhServCtx_t {
    apr_pool_t *pool;
    const MockHTTP *mh;        /* keep const to avoid thread race problems */
    const char *hostname;
    const char *serverID;      /* unique id for this server */
    apr_port_t port;
    apr_pollset_t *pollset;
    apr_socket_t *skt;         /* Server listening socket */
    mhServerType_t type;
    mhThreading_t threading;
#if APR_HAS_THREADS
    bool cancelThread;         /* Variable used to signal that the thread should
                                  be cancelled. */
    apr_thread_t * threadid;
#endif
    loopRequestState_t reqState;  /* 1 if a request is in progress, 0 if
                                  no req received yet or read completely. */
    unsigned int maxRequests;  /* Max. nr of reqs per connection. */

    apr_array_header_t *clients;        /* array of _mhClientCtx_t *'s */

    /* HTTPS specific */
    const char *certFilesPrefix;
    const char *keyFile;
    const char *passphrase;
    apr_array_header_t *certFiles;
    mhClientCertVerification_t clientCert;
    int protocols;              /* SSL protocol versions */

    apr_array_header_t *reqsReceived;   /* array of mhRequest_t *'s */
    apr_array_header_t *connMatchers;   /* array of mhConnMatcherBldr_t *'s */
    apr_array_header_t *reqMatchers;    /* array of ReqMatcherRespPair_t *'s */
    apr_array_header_t *incompleteReqMatchers;       /*       .... same type */
};
    

typedef enum reqReadState_t {
    ReadStateStatusLine = 0,
    ReadStateHeaders,
    ReadStateBody,
    ReadStateChunked,
    ReadStateChunkedHeader,
    ReadStateChunkedChunk,
    ReadStateChunkedTrailer,
    ReadStateDone
} reqReadState_t;


typedef enum method_t {
    MethodOther = 0,
    MethodACL,
    MethodBASELINE_CONTROL,
    MethodCHECKIN,
    MethodCHECKOUT,
    MethodCONNECT,
    MethodCOPY,
    MethodDELETE,
    MethodGET,
    MethodHEAD,
    MethodLABEL,
    MethodLOCK,
    MethodMERGE,
    MethodMKACTIVITY,
    MethodMKCOL,
    MethodMKWORKSPACE,
    MethodMOVE,
    MethodOPTIONS,
    MethodORDERPATCH,
    MethodPATCH,
    MethodPOST,
    MethodPROPFIND,
    MethodPROPPATCH,
    MethodPUT,
    MethodREPORT,
    MethodSEARCH,
    MethodTRACE,
    MethodUNCHECKOUT,
    MethodUNLOCK,
    MethodUPDATE,
    MethodVERSION_CONTROL
} method_t;

struct mhRequest_t {
    apr_pool_t *pool;
    const char *method;
    method_t methodCode;
    const char *url;
    apr_table_t *hdrs;
    apr_array_header_t *hdrHashes;
    int version;
    apr_array_header_t *body; /* array of iovec strings that form the raw body */
    apr_size_t bodyLen;
    bool chunked;
    /* array of iovec strings that form the dechunked body */
    apr_array_header_t *chunks;
    reqReadState_t readState;
    bool incomplete_chunk; /* chunk reading in progress */
};

struct mhResponse_t {
    apr_pool_t *pool;
    const MockHTTP *mh;
    bool built;
    unsigned int code;
    apr_table_t *hdrs;
    apr_array_header_t *body; /* array of iovec strings that form the raw body */
    apr_size_t bodyLen;
    bool chunked;
    /* array of iovec strings that form the dechunked body */
    const apr_array_header_t *chunks;
    const char *raw_data;
    size_t raw_data_length;
    apr_array_header_t *builders;
    bool closeConn;
    mhRequest_t *req;  /* mhResponse_t instance is reply to req */
};


/* Builder structures for server setup, request matching and response creation */
enum { MagicKey = 0x4D484244 }; /* MHBD */

typedef enum builderType_t {
    BuilderTypeReqMatcher,
    BuilderTypeConnMatcher,
    BuilderTypeServerSetup,
    BuilderTypeResponse,
    BuilderTypeNone,           /* A noop builder */
} builderType_t;


typedef struct builder_t {
    unsigned int magic;
    builderType_t type;
} builder_t;

typedef bool (*reqmatchfunc_t)(const mhReqMatcherBldr_t *mp,
                               const mhRequest_t *req);

struct mhRequestMatcher_t {
    apr_pool_t *pool;

    apr_array_header_t *matchers; /* array of mhReqMatcherBldr_t *'s. */
    bool incomplete;
};

struct mhReqMatcherBldr_t {
    builder_t builder;
    const void *baton; /* use this for an expected string */
    unsigned long ibaton;
    const void *baton2;
    reqmatchfunc_t matcher;
    const char *describe_key;
    const char *describe_value;
    bool match_incomplete; /* Don't wait for full valid requests */
};

typedef bool (*connmatchfunc_t)(const mhConnMatcherBldr_t *cmb,
                                const _mhClientCtx_t *cctx);

struct mhConnMatcherBldr_t {
    builder_t builder;
    const void *baton;
    connmatchfunc_t connmatcher;
    const char *describe_key;
    const char *describe_value;
};

typedef bool (*serversetupfunc_t)(const mhServerSetupBldr_t *ssb,
                                  mhServCtx_t *ctx);

struct mhServerSetupBldr_t {
    builder_t builder;
    const void *baton;
    unsigned int ibaton;
    serversetupfunc_t serversetup;
};


typedef bool (* respbuilderfunc_t)(const mhResponseBldr_t *rb,
                                   mhResponse_t *resp);

struct mhResponseBldr_t {
    builder_t builder;
    const void *baton;
    unsigned int ibaton;
    respbuilderfunc_t respbuilder;
};

method_t methodToCode(const char *code);
unsigned long calculateHeaderHash(const char *hdr, const char *val);

const char *getHeader(apr_table_t *hdrs, const char *hdr);
void setHeader(apr_table_t *hdrs, const char *hdr, const char *val);

/* Initialize a mhRequest_t object. */
mhRequest_t *_mhInitRequest(apr_pool_t *pool);

bool _mhRequestMatcherMatch(const mhRequestMatcher_t *rm,
                            const mhRequest_t *req);
bool _mhClientcertcn_matcher(const mhConnMatcherBldr_t *mp,
                             const _mhClientCtx_t *cctx);
bool _mhClientcert_valid_matcher(const mhConnMatcherBldr_t *mp,
                                 const _mhClientCtx_t *cctx);

/* Build a response */
void _mhBuildResponse(mhResponse_t *resp);

void _mhErrorUnexpectedBuilder(const MockHTTP *mh, void *actual,
                               builderType_t expected);

/* Test servers */
apr_status_t _mhRunServerLoop(mhServCtx_t *ctx);

void _mhLog(int verbose_flag, apr_socket_t *skt, const char *fmt, ...);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* MockHTTP_private_H */
 /* Copyright 2014 Lieven Govaerts
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* This file includes code originally submitted to the Serf project, covered by
 * the Apache License, Version 2.0, copyright Justin Erenkrantz & Greg Stein.
 */
#include <apr_strings.h>
#include <apr_uri.h>
#include <apr_lib.h>

#include <stdlib.h>


/* Copied from serf.  */
#if defined(APR_VERSION_AT_LEAST) && defined(WIN32)
#if APR_VERSION_AT_LEAST(1,4,0)
#define BROKEN_WSAPOLL
#endif
#endif

/* Forward declarations */
static apr_status_t initSSLCtx(_mhClientCtx_t *cctx);
static apr_status_t sslHandshake(_mhClientCtx_t *cctx);
static apr_status_t sslSocketWrite(_mhClientCtx_t *cctx, const char *data,
                                   apr_size_t *len);
static apr_status_t sslSocketRead(apr_socket_t *skt, void *baton, char *data,
                                  apr_size_t *len);
static apr_status_t renegotiateSSLSession(_mhClientCtx_t *cctx);

typedef apr_status_t (*handshake_func_t)(_mhClientCtx_t *cctx);
typedef apr_status_t (*reset_conn_func_t)(_mhClientCtx_t *cctx);
typedef apr_status_t (*send_func_t)(_mhClientCtx_t *cctx, const char *data,
                                    apr_size_t *len);
typedef apr_status_t (*receive_func_t)(apr_socket_t *skt, void *baton,
                                       char *data, apr_size_t *len);

typedef struct sslCtx_t sslCtx_t;
typedef struct bucket_t bucket_t;
static const int DefaultSrvPort =   30080;
static const int DefaultProxyPort = 38080;

/* Buffer size for incoming and outgoing data */
#define BUFSIZE 32768

struct _mhClientCtx_t {
    apr_pool_t *pool;
    apr_socket_t *skt;         /* Socket for conn client <-> proxy/server */
    apr_int16_t reqevents;
    apr_socket_t *proxyskt;    /* Socket for conn proxy <-> server */
    apr_int16_t proxyreqevents;
    const char *proxyhost;     /* Proxy host:port */

    const char *respBody;
    apr_size_t respRem;
    apr_array_header_t *respQueue;  /* test will queue a response */
    mhResponse_t *currResp;         /* response in progress */
    unsigned int reqsReceived;      /* # of reqs received on this connection */
    mhRequest_t *req;
    bool closeConn;
    sslCtx_t *ssl_ctx;
    int protocols;                  /* SSL protocol versions */
    servMode_t mode;      /* default = server, but can switch to proxy/tunnel */

    send_func_t send;
    receive_func_t read;

    bucket_t *stream; /* Bucket for incoming data */

    /* Proxy buffers */
    char osbuf[BUFSIZE]; /* buffer for data to be sent from proxy to the server */
    apr_size_t osbuflen;
    apr_size_t osbufrem;

    char ocbuf[BUFSIZE]; /* buffer for data to be sent from proxy/server to client */
    apr_size_t ocbuflen;
    apr_size_t ocbufrem;


    /* SSL-only callback functions, should be NULL when not implemented */
    handshake_func_t handshake;
    reset_conn_func_t reset;
    const char *keyFile;
    const char *passphrase;
    apr_array_header_t *certFiles;
    mhClientCertVerification_t clientCert;
};

/**
 * Start up a server in a separate thread.
 */
static void * APR_THREAD_FUNC run_thread(apr_thread_t *tid, void *baton)
{
    mhServCtx_t *ctx = baton;

    while (!ctx->cancelThread) {
        _mhRunServerLoop(ctx);
    }

    apr_thread_exit(tid, APR_SUCCESS);
    return NULL;
}

/**
 * Callback called when the mhServCtx_t pool is destroyed. 
 */
static apr_status_t cleanupServer(void *baton)
{
    mhServCtx_t *ctx = baton;
    apr_status_t status = APR_SUCCESS;

    /* If mhCleanup() wasn't called before pool cleanup, the server is still
       running. Stop it here to avoid a crash, but this will result in a 
       (currently unidentified) pool cleanup crash.
       Conclusion: Always run mhCleanup() at the end of a test!
     */
    mhStopServer(ctx);

    if (ctx->pollset) {
        apr_pollset_destroy(ctx->pollset);
        ctx->pollset = NULL;
    }
    if (ctx->skt) {
        status = apr_socket_close(ctx->skt);
        ctx->skt = NULL;
    }

    return status;
}

/**
 * Callback, writes DATA of length LEN to the socket stored in CCTX.
 */
static apr_status_t socketWrite(_mhClientCtx_t *cctx, const char *data,
                                apr_size_t *len)
{
    return apr_socket_send(cctx->skt, data, len);
}

/**
 * Callback, reads data from the socket stored in CCTX and stores it in DATA,
 * the available bytes will be stored in *LEN.
 */
static apr_status_t socketRead(apr_socket_t *skt, void *baton, char *data,
                               apr_size_t *len)
{
    return apr_socket_recv(skt, data, len);
}

/**
 * Sets up a listener on the socket stored in CTX.
 */
static apr_status_t setupTCPServer(mhServCtx_t *ctx)
{
    apr_sockaddr_t *serv_addr;
    apr_pool_t *pool = ctx->pool;
    apr_status_t status;

    while (1) {
        STATUSERR(apr_sockaddr_info_get(&serv_addr, ctx->hostname,
                                        APR_UNSPEC, ctx->port, 0,
                                        pool));

        /* Create server socket */
        /* Note: this call requires APR v1.0.0 or higher */
        STATUSERR(apr_socket_create(&ctx->skt, serv_addr->family,
                                    SOCK_STREAM, 0, pool));

        STATUSERR(apr_socket_opt_set(ctx->skt, APR_SO_NONBLOCK, 1));
        STATUSERR(apr_socket_timeout_set(ctx->skt, 0));
        STATUSERR(apr_socket_opt_set(ctx->skt, APR_SO_REUSEADDR, 1));

        /* Try the next port until bind succeeds */
        status = apr_socket_bind(ctx->skt, serv_addr);
        if (status == EADDRINUSE) {
            ctx->port++;
            continue;
        }
        /* Listen for clients */
        STATUSERR(apr_socket_listen(ctx->skt, SOMAXCONN));
        break;
    };

    /* Create a new pollset, avoid broken WSAPoll implemenation on Windows. */
#ifdef BROKEN_WSAPOLL
    STATUSERR(apr_pollset_create_ex(&ctx->pollset, 32, pool, 0,
                                    APR_POLLSET_SELECT));
#else
    STATUSERR(apr_pollset_create(&ctx->pollset, 32, pool, 0));
#endif

    /* Listen for POLLIN events on this socket */
    {
        apr_pollfd_t pfd = { 0 };

        pfd.desc_type = APR_POLL_SOCKET;
        pfd.desc.s = ctx->skt;
        pfd.reqevents = APR_POLLIN;

        STATUSERR(apr_pollset_add(ctx->pollset, &pfd));
    }

    return APR_SUCCESS;
}

/**
 * Opens a non-blocking connection to a remote server at URL (in form 
 * localhost:30080).
 */
static apr_status_t connectToServer(mhServCtx_t *ctx, _mhClientCtx_t *cctx)
{
    apr_sockaddr_t *address;
    char *host, *scopeid;
    apr_port_t port;
    apr_status_t status;

    STATUSERR(apr_parse_addr_port(&host, &scopeid, &port, cctx->proxyhost,
                                  cctx->pool));
    STATUSERR(apr_sockaddr_info_get(&address, host, APR_UNSPEC,
                                    port, 0, cctx->pool));

    /* Create server socket */
    /* Note: this call requires APR v1.0.0 or higher */
    STATUSERR(apr_socket_create(&cctx->proxyskt, address->family,
                                SOCK_STREAM, 0, cctx->pool));
    STATUSERR(apr_socket_opt_set(cctx->proxyskt, APR_SO_NONBLOCK, 1));
    STATUSERR(apr_socket_timeout_set(cctx->proxyskt, 0));
    STATUSERR(apr_socket_opt_set(cctx->proxyskt, APR_SO_REUSEADDR, 1));

    status = apr_socket_connect(cctx->proxyskt, address);
    if (status == APR_SUCCESS || APR_STATUS_IS_EINPROGRESS(status)) {
        apr_pollfd_t pfd = { 0 };

        pfd.desc_type = APR_POLL_SOCKET;
        pfd.desc.s = cctx->proxyskt;
        pfd.reqevents = APR_POLLIN | APR_POLLOUT;
        pfd.client_data = cctx;
        STATUSERR(apr_pollset_add(ctx->pollset, &pfd));
        cctx->proxyreqevents = pfd.reqevents;
    }

    return status;
}

/**
 * Initialize the server context.
 */
static mhServCtx_t *
initServCtx(const MockHTTP *mh, const char *hostname, apr_port_t port)
{
    apr_pool_t *pool = mh->pool;

    mhServCtx_t *ctx = apr_pcalloc(pool, sizeof(mhServCtx_t));
    ctx->pool = pool;
    ctx->mh = mh;
    ctx->hostname = apr_pstrdup(pool, hostname);
    ctx->port = port;
    ctx->clients = apr_array_make(pool, 5, sizeof(_mhClientCtx_t *));
    ctx->reqsReceived = apr_array_make(pool, 5, sizeof(mhRequest_t *));
    /* Default settings */
    ctx->clientCert = mhCCVerifyNone;
    ctx->protocols = mhProtoUnspecified;
    ctx->threading = mhThreadMain;
    ctx->reqMatchers = apr_array_make(pool, 5, sizeof(ReqMatcherRespPair_t *));
    ctx->incompleteReqMatchers = apr_array_make(pool, 5,
                                                sizeof(ReqMatcherRespPair_t *));

    apr_pool_cleanup_register(pool, ctx,
                              cleanupServer,
                              apr_pool_cleanup_null);

    return ctx;
}

/******************************************************************************/
/* Parse a request structure from incoming data                               */
/******************************************************************************/

/**
 * Initialize a mhRequest_t object
 */
mhRequest_t *_mhInitRequest(apr_pool_t *pool)
{
    mhRequest_t *req = apr_pcalloc(pool, sizeof(mhRequest_t));
    req->pool = pool;
    req->hdrs = apr_table_make(pool, 5);
    req->hdrHashes = apr_array_make(pool, 5, sizeof(unsigned long));
    req->body = apr_array_make(pool, 5, sizeof(struct iovec));
    req->chunks = apr_array_make(pool, 5, sizeof(struct iovec));

    return req;
}

/******************* BUCKETS **************************************************/
typedef struct _mhBucketType_t {

    const char *name;

    apr_status_t (*read)(bucket_t *bucket, apr_size_t requested,
                         const char **data, apr_size_t *len);

    apr_status_t (*readLine)(bucket_t *bucket,
                             /* int acceptable, int *found, CR, LF? */
                             const char **data, apr_size_t *len);

    apr_status_t (*peek)(bucket_t *bucket, apr_size_t *len);

} _mhBucketType_t;

struct bucket_t {

    /** the type of this bucket */
    const _mhBucketType_t *type;

    /** bucket-private data */
    void *data;
};

/* Buffered Socket buffer */
typedef struct _bufferedSocketCtx_t {
    apr_socket_t *skt;
    receive_func_t read;
    void *read_baton;
    char buf[BUFSIZE];  /* buffer for data received from the client @ server */
    apr_size_t remaining;  /* remaining bytes in the buffer */
    apr_size_t offset;  /* offset of the first available byte */
} _bufferedSocketCtx_t;

/**
 * Reads data from the socket and stores it in CCTX->buf.
 */
static apr_status_t readFromSocket(bucket_t *bkt)
{
    _bufferedSocketCtx_t *ctx = bkt->data;
    apr_status_t status;

    // assert(ctx->offset = 0);
    apr_size_t len = BUFSIZE - ctx->remaining;
    STATUSREADERR(ctx->read(ctx->skt, ctx->read_baton,
                            ctx->buf + ctx->remaining, &len));
    if (len) {
        _mhLog(MH_VERBOSE, ctx->skt,
               "recvd with status %d:\n%.*s\n---- %d ----\n",
               status, (unsigned int)len, ctx->buf + ctx->remaining,
               (unsigned int)len);
        ctx->remaining += len;
    }
    return status;
}

/**
 * Read a complete line from the buffer in CCTX.
 * *LEN will be non-0 if a line ending with CRLF was found. BUF will be copied
 * in mem allocatod from cctx->pool, cctx->buf ptrs will be moved.
 */
static apr_status_t
buffSktReadLine(bucket_t *bkt, const char **data, apr_size_t *len)
{
    _bufferedSocketCtx_t *ctx = bkt->data;
    const char *ptr = ctx->buf;
    apr_status_t status;

    /* eat data read in a previous read call */
    if (ctx->offset > 0) {
        memmove(ctx->buf, ctx->buf + ctx->offset, BUFSIZE - ctx->offset);
        ctx->offset = 0;
    }

    status = readFromSocket(bkt);

    /* return one line of data */
    *len = 0;
    while (*ptr && ptr - ctx->buf < ctx->remaining) {
        if (*ptr == '\r' && *(ptr+1) == '\n') {
            *len = ptr - ctx->buf + 2;
            *data = ctx->buf;

            ctx->offset += *len;
            ctx->remaining -= *len;

            break;
        }
        ptr++;
    }

    if (ctx->remaining > 0)
        return APR_SUCCESS;

    return status;
}

static apr_status_t buffSktRead(bucket_t *bkt, apr_size_t requested,
                                const char **data, apr_size_t *len)
{
    _bufferedSocketCtx_t *ctx = bkt->data;
    apr_status_t status;

    /* eat data read in a previous read call */
    if (ctx->offset > 0) {
        memmove(ctx->buf, ctx->buf + ctx->offset, BUFSIZE - ctx->offset);
        ctx->offset = 0;
    }

    status = readFromSocket(bkt);

    /* return requested data */
    *len = ctx->remaining <= requested ? ctx->remaining : requested; /* this packet */
    *data = ctx->buf;

    ctx->offset += *len;
    ctx->remaining -= *len;

    if (ctx->remaining > 0)
        return APR_SUCCESS;

    return status;
}


static apr_status_t buffSktPeek(bucket_t *bkt, apr_size_t *len)
{
    _bufferedSocketCtx_t *ctx = bkt->data;
    apr_status_t status;

    /* eat data read in a previous read call */
    if (ctx->offset > 0) {
        memmove(ctx->buf, ctx->buf + ctx->offset, BUFSIZE - ctx->offset);
        ctx->offset = 0;
    }

    status = readFromSocket(bkt);

    *len = ctx->remaining;
    if (ctx->remaining > *len)
        return APR_SUCCESS;

    return status;
}

const _mhBucketType_t BufferedSocketBucketType = {
    "BUFFSOCKET",
    buffSktRead,
    buffSktReadLine,
    buffSktPeek,
};

static bucket_t *
createBufferedSocketBucket(apr_socket_t *skt, receive_func_t read,
                           void *baton, apr_pool_t *pool)
{
    _bufferedSocketCtx_t *ctx = apr_pcalloc(pool, sizeof(_bufferedSocketCtx_t));
    bucket_t *bkt = apr_palloc(pool, sizeof(bucket_t));

    ctx->skt = skt;
    ctx->read = read;
    ctx->read_baton = baton;
    bkt->type = &BufferedSocketBucketType;
    bkt->data = ctx;
    return bkt;
}

#define FAIL_ON_EOL(ptr)\
    if (*ptr == '\0') return APR_EGENERAL; /* TODO: error code */

/**
 * Reads the request line from the buffer in CCTX, REQ will be updated
 * with the info read from the request line.
 *
 * Returns APR_EAGAIN if the request line isn't completely available,
 *         APR_SUCCESS + *DONE = YES if request line parsed.
 *         error in case the request line couldn't be parsed successfully
 */
static apr_status_t
readReqLine(bucket_t *bkt, mhRequest_t *req, bool *done)
{
    const char *start, *ptr, *version;
    const char *buf;
    apr_size_t len;
    apr_status_t status;

    *done = FALSE;

    status = bkt->type->readLine(bkt, &buf, &len);
    if (!len) return status;

    /* TODO: add checks for incomplete request line */
    start = ptr = buf;
    while (*ptr && *ptr != ' ' && *ptr != '\r') ptr++;
    FAIL_ON_EOL(ptr);
    req->method = apr_pstrndup(req->pool, start, ptr-start);
    req->methodCode = methodToCode(req->method);

    ptr++; start = ptr;
    while (*ptr && *ptr != ' ' && *ptr != '\r') ptr++;
    FAIL_ON_EOL(ptr);
    req->url = apr_pstrndup(req->pool, start, ptr-start);

    ptr++; start = ptr;
    while (*ptr && *ptr != ' ' && *ptr != '\r') ptr++;
    if (ptr - start != strlen("HTTP/x.y")) {
        return APR_EGENERAL;
    }
    version = apr_pstrndup(req->pool, start, ptr-start);
    req->version = (version[5] - '0') * 10 +
    version[7] - '0';

    *done = TRUE;

    return APR_SUCCESS;
}

/* simple hash implementation (djb2). */
unsigned long calculateHeaderHash(const char *hdr, const char *val)
{
    unsigned long hash = 5381;
    int c;

    if (!val)
        return 0;

    while ((c = apr_tolower(*hdr++)))
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    hash = ((hash << 5) + hash) + ':';
    while ((c = *val++))
        hash = ((hash << 5) + hash) + c;

    return hash;
}

static void setRequestHeader(mhRequest_t *req, const char *hdr, const char *val)
{
    apr_table_t *hdrs = req->hdrs;
    unsigned long hash;

    apr_table_add(hdrs, hdr, val);
    hash = calculateHeaderHash(hdr, val);
    APR_ARRAY_PUSH(req->hdrHashes, unsigned long) = hash;
}

/**
 * Reads a HTTP header from the buffer in CCTX, header will be added to REQ.
 *
 * Returns APR_EAGAIN if a header line isn't completely available.
 *         APR_SUCCESS if a header line was successfully parsed, maybe more
 *                     are available.
 *           + *DONE = YES when the last header was successfully parsed.
 *         error in case the header line couldn't be parsed successfully
 */
static apr_status_t
readHeader(bucket_t *bkt, mhRequest_t *req, bool *done)
{
    const char *buf;
    apr_size_t len;
    apr_status_t status;

    *done = NO;

    STATUSREADERR(bkt->type->readLine(bkt, &buf, &len));
    if (!len) return APR_EAGAIN;

    /* Last header? */
    if (len == 2 && *buf == '\r' && *(buf+1) == '\n') {
        *done = YES;
        return APR_SUCCESS;
    } if (len < 5) {
        /* TODO: error handling. header line is too short */
        return APR_EGENERAL;
    } else {
        const char *start = buf, *ptr = buf, *end = buf + len;
        const char *hdr, *val;

        /* Read header from a line in the form of 'Header: value' */
        while (*ptr && ptr < end && *ptr != ':' && *ptr != '\r') ptr++;
        hdr = apr_pstrndup(req->pool, start, ptr-start);

        /* skip : and blanks */
        ptr++; while (*ptr && ptr < end && *ptr == ' ') ptr++; start = ptr;

        /* Read value */
        while (*ptr && ptr < end && *ptr != '\r') ptr++;
        val = apr_pstrndup(req->pool, start, ptr-start);

        setRequestHeader(req, hdr, val);
    }
    return APR_SUCCESS;
}

/**
 * Append a block of data in BUF of length LEN (not-'\0' terminated) to the 
 * list in REQ. Data will be copied in the REQ->pool.
 */
static void
storeRawDataBlock(mhRequest_t *req, const char *buf, apr_size_t len)
{
    struct iovec vec;
    vec.iov_base = apr_pstrndup(req->pool, buf, len);
    vec.iov_len = len;
    *((struct iovec *)apr_array_push(req->body)) = vec;
    req->bodyLen += len;
}

/**
 * Reads the unencoded (not chunked) body from the buffer in CCTX. The length
 * of the body is determined by reading the "Content-Length" header in REQ.
 * The body will be copied in REQ->pool and stored in REQ.
 *
 * Returns APR_EAGAIN if the body isn't completely available.
 *         APR_SUCCESS + *DONE = YES when the whole body was read completely.
 *         error in case the "Content-Length" header isn't set.
 */
static apr_status_t readBody(bucket_t *bkt, mhRequest_t *req, bool *done)
{
    const char *clstr, *data;
    char *body;
    long cl;
    apr_size_t len;
    apr_status_t status;

    req->chunked = NO;

    clstr = getHeader(req->hdrs, "Content-Length");
    /* TODO: error if no Content-Length header */
    cl = atol(clstr);

    len = cl - req->bodyLen; /* remaining # of bytes */

    STATUSREADERR(bkt->type->read(bkt, len, &data, &len));

    /* copy data to the request */
    if (req->body == NULL) {
        req->body = apr_palloc(req->pool, sizeof(struct iovec) * 256);
    }
    body = apr_palloc(req->pool, len + 1);
    memcpy(body, data, len);
    *(body + len) = '\0';
    storeRawDataBlock(req, body, len);

    if (req->bodyLen < cl)
        return APR_EAGAIN;

    *done = YES;
    return APR_SUCCESS;
}

/**
 * Reads a chunk of the body from the buffer in CCTX. The length
 * of the body is determined by reading the chunk header, length of current 
 * chunk and partial read data will be stored in REQ->chunks.
 * The chunk will be copied in REQ->pool and stored in REQ.
 *
 * Returns APR_EAGAIN if the chunk isn't completely available.
 *         APR_SUCCESS if a chunk was read completely, maybe more are available.
 *           + *DONE = YES when the last chunk and the trailer were read.
 *         error in case of problems parsing the chunk header, length or trailer.
 */
static apr_status_t readChunk(bucket_t *bkt, mhRequest_t *req, bool *done)
{
    *done = NO;
    apr_status_t status;

    switch (req->readState) {
        case ReadStateBody:
        case ReadStateChunked:
            req->readState = ReadStateChunkedHeader;
            /* fall through */
        case ReadStateChunkedHeader:
        {
            struct iovec vec;
            const char *data;
            apr_size_t len, chlen;
            
            STATUSREADERR(bkt->type->readLine(bkt, &data, &len));
            if (!len)
                return APR_EAGAIN;
            storeRawDataBlock(req, data, len);

            chlen = apr_strtoi64(data, NULL, 16); /* read hex chunked length */
            vec.iov_len = chlen;
            *((struct iovec *)apr_array_push(req->chunks)) = vec;
            if (chlen == 0) {
                req->readState = ReadStateChunkedTrailer;
                return APR_SUCCESS;
            }

            req->readState = ReadStateChunkedChunk;
            /* fall through */
        }
        case ReadStateChunkedChunk:
        {
            const char *data;
            struct iovec *vec;
            apr_size_t chlen, curchunklen, len;

            vec = &APR_ARRAY_IDX(req->chunks, req->chunks->nelts - 1,
                                 struct iovec);
            chlen = vec->iov_len;

            /* already read some data of this chunk? */
            if (req->incomplete_chunk) {
                const char *tmp;
                curchunklen = strlen(vec->iov_base);
                /* read as much as possible from remaining part */
                STATUSREADERR(bkt->type->read(bkt, chlen - curchunklen,
                                              &data, &len));
                tmp = apr_pstrndup(req->pool, data, len);
                storeRawDataBlock(req, data, len);
                vec->iov_base = apr_pstrcat(req->pool, vec->iov_base, tmp, NULL);
                curchunklen += len;
            } else {
                /* read as much as possible */
                STATUSREADERR(bkt->type->read(bkt, chlen, &data, &len));
                vec->iov_base = apr_pstrndup(req->pool, data, len);
                storeRawDataBlock(req, data, len);
                curchunklen = len;
            }

            if (curchunklen < chlen) {
                /* More data is needed to read one chunk */
                req->incomplete_chunk = YES;
                return APR_EAGAIN;
            }
            req->incomplete_chunk = NO;
            req->readState = ReadStateChunkedTrailer;

            /* fall through */
        }
        case ReadStateChunkedTrailer:
        {
            const char *data;
            apr_size_t len, chlen;
            struct iovec vec;

            vec = APR_ARRAY_IDX(req->chunks, req->chunks->nelts - 1, struct iovec);
            chlen = vec.iov_len;

            STATUSREADERR(bkt->type->readLine(bkt, &data, &len));
            if (len < 2)
                return APR_EAGAIN;
            storeRawDataBlock(req, data, len);
            if (len == 2 && *data == '\r' && *(data+1) == '\n') {
                if (chlen == 0) {
                    /* body ends with chunk of length 0 */
                    *done = YES;
                    req->readState = ReadStateDone;
                    /* remove the 0-chunk from the request*/
                    apr_array_pop(req->chunks);
                } else {
                    req->readState = ReadStateChunked;
                }
            } else {
                return APR_EGENERAL; /* TODO: error code */
            }
            break;
        }
        default:
            break;
    }

    return APR_SUCCESS;
}

/**
 * Keeps reading chunks until no more data is available.
 *
 * Returns APR_EAGAIN if a chunk isn't completely available.
 *         APR_SUCCESS + *DONE = YES when the last chunk and the trailer were 
 *              read.
 *         error in case of problems parsing the chunk header, length or trailer.
 */
static apr_status_t
readChunked(bucket_t *bkt, mhRequest_t *req, bool *done)
{
    apr_status_t status;

    *done = NO;
    req->chunked = YES;

    while (*done == NO)
        STATUSERR(readChunk(bkt, req, done));

    return status;
}

/**
 * New request data is available, read status line/hdrs/body (chunks).
 *
 * Returns APR_EAGAIN: wait for more data
 *         APR_EOF: request received, or no more data available.
 *         MH_STATUS_INCOMPLETE_REQUEST: APR_EOF but the request wasn't received 
 *             completely.
 */
static apr_status_t readRequest(_mhClientCtx_t *cctx, mhRequest_t **preq)
{
    mhRequest_t *req = *preq;
    bucket_t *bkt;
    apr_status_t status = APR_SUCCESS;

    bkt = cctx->stream;
    if (req == NULL) {
        apr_size_t len;
        STATUSREADERR(bkt->type->peek(bkt, &len));
        if (!len)
            return status;
        req = *preq = _mhInitRequest(cctx->pool);
    }

    while (!status) { /* read all available data */
        bool done = NO;

        switch(cctx->req->readState) {
            case ReadStateStatusLine: /* status line */
                STATUSREADERR(readReqLine(bkt, req, &done));
                if (done) req->readState = ReadStateHeaders;
                break;
            case ReadStateHeaders: /* headers */
                STATUSREADERR(readHeader(bkt, req, &done));
                if (done) req->readState = ReadStateBody;
                break;
            case ReadStateBody: /* body */
            case ReadStateChunked:
            case ReadStateChunkedHeader:
            case ReadStateChunkedChunk:
            case ReadStateChunkedTrailer:
            {
                const char *clstr, *chstr;
                chstr = getHeader(req->hdrs, "Transfer-Encoding");
                /* TODO: chunked can be one of more encodings */
                /* Read Transfer-Encoding first, ignore C-L when T-E is set */
                if (chstr && apr_strnatcasecmp(chstr, "chunked") == 0) {
                    STATUSREADERR(readChunked(bkt, req, &done));
                } else {
                    clstr = getHeader(req->hdrs, "Content-Length");
                    if (clstr) {
                        STATUSREADERR(readBody(bkt, req, &done));
                    } else {
                        done = YES; /* no body to read */
                    }
                }
                if (done) {
                    _mhLog(MH_VERBOSE, cctx->skt, "Server received request: %s %s\n",
                           req->method, req->url);
                    return APR_EOF;
                }
            }
            case ReadStateDone:
                break;
        }
    }
#if 0
    /* TODO: fix or cleanup */
    if (!cctx->buflen) {
        if (APR_STATUS_IS_EOF(status))
            return MH_STATUS_INCOMPLETE_REQUEST;

        return status;
    }
#endif

    return status;
}

/******************************************************************************/
/* Send a response                                                            */
/******************************************************************************/

/**
 * Translate a HTTP status code to a string representation.
 */
static const char *codeToString(unsigned int code)
{
    switch(code) {
        case 100: return "Continue"; break;
        case 101: return "Switching Protocols"; break;
        case 200: return "OK"; break;
        case 201: return "Created"; break;
        case 202: return "Accepted"; break;
        case 203: return "Non-Authoritative Information"; break;
        case 204: return "No Content"; break;
        case 205: return "Reset Content"; break;
        case 206: return "Partial Content"; break;
        case 300: return "Multiple Choices"; break;
        case 301: return "Moved Permanently"; break;
        case 302: return "Found"; break;
        case 303: return "See Other"; break;
        case 304: return "Not Modified"; break;
        case 305: return "Use Proxy"; break;
        case 307: return "Temporary Redirect"; break;
        case 400: return "Bad Request"; break;
        case 401: return "Unauthorized"; break;
        case 402: return "Payment Required"; break;
        case 403: return "Forbidden"; break;
        case 404: return "Not Found"; break;
        case 405: return "Method Not Allowed"; break;
        case 406: return "Not Acceptable"; break;
        case 407: return "Proxy Authentication Required"; break;
        case 408: return "Request Timeout"; break;
        case 409: return "Conflict"; break;
        case 410: return "Gone"; break;
        case 411: return "Length Required"; break;
        case 412: return "Precondition Failed"; break;
        case 413: return "Request Entity Too Large"; break;
        case 414: return "Request-URI Too Long"; break;
        case 415: return "Unsupported Media Type"; break;
        case 416: return "Requested Range Not Satisfiable"; break;
        case 417: return "Expectation Failed"; break;
        case 500: return "Internal Server Error"; break;
        case 501: return "Not Implemented"; break;
        case 502: return "Bad Gateway"; break;
        case 503: return "Service Unavailable"; break;
        case 504: return "Gateway Timeout"; break;
        case 505: return "HTTP Version Not Supported"; break;
        default: return "<not defined>";
    }
}

/**
 * Serializes the response RESP to a '\0'-terminated string, allocated in POOL.
 */
static char *respToString(apr_pool_t *pool, mhResponse_t *resp)
{
    char *str;
    const apr_table_entry_t *elts;
    const apr_array_header_t *arr;
    int i;

    /* status line */
    str = apr_psprintf(pool, "HTTP/1.1 %d %s\r\n", resp->code,
                       codeToString(resp->code));

    /* headers */
    arr = apr_table_elts(resp->hdrs);
    elts = (const apr_table_entry_t *)arr->elts;

    for (i = 0; i < arr->nelts; ++i) {
        str = apr_psprintf(pool, "%s%s: %s\r\n", str, elts[i].key, elts[i].val);
    }
    str = apr_psprintf(pool, "%s\r\n", str);

    /* body */
    if (resp->chunked == NO) {
        int i;
        for (i = 0 ; i < resp->body->nelts; i++) {
            struct iovec vec;

            vec = APR_ARRAY_IDX(resp->body, i, struct iovec);
            str = apr_psprintf(pool, "%s%.*s", str, (unsigned int)vec.iov_len,
                               (const char *)vec.iov_base);
        }
    } else {
        int i;
        bool emptyChunk = NO; /* empty response should atleast have 0-chunk */
        for (i = 0 ; i < resp->chunks->nelts; i++) {
            struct iovec vec;

            vec = APR_ARRAY_IDX(resp->chunks, i, struct iovec);
            str = apr_psprintf(pool, "%s%" APR_UINT64_T_HEX_FMT "\r\n%.*s\r\n",
                               str, (apr_uint64_t)vec.iov_len,
                               (unsigned int)vec.iov_len, (char *)vec.iov_base);
            emptyChunk = vec.iov_len == 0 ? YES : NO;
        }
        if (!emptyChunk) /* Add 0 chunk only if last chunk wasn't empty already */
            str = apr_psprintf(pool, "%s0\r\n\r\n", str);
    }
    return str;
}

/**
 * Serializes the response RESP and writes it to the socket. Unwritten data will
 * be stored in CCTX->respBody.
 */
static apr_status_t writeResponse(_mhClientCtx_t *cctx, mhResponse_t *resp)
{
    apr_pool_t *pool = cctx->pool;
    apr_size_t len;
    apr_status_t status;

    if (!cctx->respRem) {
        _mhBuildResponse(resp);
        if (resp->raw_data) {
            cctx->respBody = resp->raw_data;
            cctx->respRem = resp->raw_data_length;
        } else {
            cctx->respBody = respToString(pool, resp);
            cctx->respRem = strlen(cctx->respBody);
        }
    }

    len = cctx->respRem;
    STATUSREADERR(cctx->send(cctx, cctx->respBody, &len));
    _mhLog(MH_VERBOSE, cctx->skt, "sent with status %d:\n%.*s\n---- %d ----\n",
           status, (unsigned int)len, cctx->respBody, (unsigned int)len);

    if (len < cctx->respRem) {
        cctx->respBody += len;
        cctx->respRem -= len;
        cctx->currResp = resp;
    } else {
        cctx->respBody = NULL;
        cctx->respRem = 0;
        cctx->currResp = 0;
        return APR_EOF;
    }
    return status;
}

/******************************************************************************/
/* Match a request                                                            */
/******************************************************************************/

/**
 * Stores a request matcher RM on the list of matchers for server CTX.
 */
void mhPushRequest(MockHTTP *mh, mhServCtx_t *ctx, mhRequestMatcher_t *rm)
{
    apr_array_header_t *matchers;
    ReqMatcherRespPair_t *pair;
    int i;

    if (ctx) {
        pair = apr_palloc(ctx->pool, sizeof(ReqMatcherRespPair_t));
    } else {
        pair = apr_palloc(mh->pool, sizeof(ReqMatcherRespPair_t));
    }
    pair->rm = rm;
    pair->resp = NULL;
    pair->action = mhActionInitiateNone;

    /* Check if any of this request's matchers work on an incomplete request. */
    for (i = 0 ; i < rm->matchers->nelts; i++) {
        const mhReqMatcherBldr_t *mp;

        mp = APR_ARRAY_IDX(rm->matchers, i, mhReqMatcherBldr_t *);
        if (mp->match_incomplete == YES) {
            rm->incomplete = YES;
            break;
        }
    }

    if (ctx) {
        matchers = rm->incomplete ? ctx->incompleteReqMatchers : ctx->reqMatchers;
    } else {
        matchers = rm->incomplete ? mh->incompleteReqMatchers : mh->reqMatchers;
    }
    *((ReqMatcherRespPair_t **)apr_array_push(matchers)) = pair;
}

/**
 * Tries to match the request REQ with any of the request matchers MATCHERS.
 * Returns NO if the request wasn't matched.
 *         YES + *RESP + *ACTION if the request was matched successfully.
 */

/* TOOD:
   This function is the main bottleneck for performance. Possible fixes:
   - if a test is setup to continuously add new request matchers while sending
     requests, evaluation the matchers from last to first drastically
     improves matching performance. Problem: user expects matches are run in
     order of definition.
   - when using a header with an unique value per request, we could create
     an index on that header:value (hashtable or b-tree) to bypass this whole
     loop. Probably requires a new API so the user can specify the index.
   - create a universal string that contains the union of all criteria
     of all matchers, e.g. "GET/header1:value1/header2:value2" and create an
     index on that string. Problem is updating that index with new matchers when
     they use new criteria (OTOH: as long as the criteria are sorted this
     shouldn't be a problem, a criteria not defined = 0 bytes in the string).
 */
static bool
matchRequest(mhRequest_t *req, mhResponse_t **resp,
             mhAction_t *action, const apr_array_header_t *matchers)
{
    int i;

    for (i = 0 ; i < matchers->nelts; i++) {
        const ReqMatcherRespPair_t *pair;

        pair = APR_ARRAY_IDX(matchers, i, ReqMatcherRespPair_t *);

        if (_mhRequestMatcherMatch(pair->rm, req) == YES) {
            *resp = pair->resp;
            *action = pair->action;
            return YES;
        }
    }

    *resp = NULL;
    return NO;
}

/**
 * Tries to match a complete request REQ with the list of complete request
 * matchers.
 * Returns NO if the request wasn't matched.
 *         YES + *RESP + *ACTION if the request was matched successfully.
 */
static bool
_mhMatchRequest(const mhServCtx_t *ctx, const _mhClientCtx_t *cctx,
                mhRequest_t *req, mhResponse_t **resp, mhAction_t *action)
{
    bool found;
    const MockHTTP *mh = ctx->mh;

    /* Try to see if a request matcher for this server exists */
    found = matchRequest(req, resp, action, ctx->reqMatchers);
    if (found) return found;

    /* Nope, then see of there's a request matcher for all servers */
    found = matchRequest(req, resp, action, mh->reqMatchers);
    if (found) return found;

    _mhLog(MH_VERBOSE, cctx->skt, "Couldn't match request!\n");
    return NO;
}

/**
 * Tries to match an incomplete (partial) request REQ with the list of 
 * incomplete request matchers.
 * Returns NO if the request wasn't matched.
 *         YES + *RESP + *ACTION if the request was matched successfully.
 */
static bool
_mhMatchIncompleteRequest(const mhServCtx_t *ctx, const _mhClientCtx_t *cctx,
                          mhRequest_t *req, mhResponse_t **resp,
                          mhAction_t *action)
{
    bool found;
    const MockHTTP *mh = ctx->mh;

    /* Try to see if a request matcher for this server exists */
    found = matchRequest(req, resp, action, ctx->incompleteReqMatchers);
    if (found) return found;

    /* Nope, then see of there's a request matcher for all servers */
    found = matchRequest(req, resp, action, mh->incompleteReqMatchers);
    if (found) return found;

    _mhLog(MH_VERBOSE, cctx->skt, "Couldn't match incomplete request!\n");
    return NO;
}

/**
 * Deep copy of a response RESP to a new response allocated in POOL.
 */
static mhResponse_t *cloneResponse(apr_pool_t *pool, mhResponse_t *resp)
{
    mhResponse_t *clone;
    clone = apr_pmemdup(pool, resp, sizeof(mhResponse_t));
    clone->hdrs = apr_table_copy(pool, resp->hdrs);
    if (resp->chunks)
        clone->chunks = apr_array_copy(pool, resp->chunks);
    if (resp->body)
        clone->body = apr_array_copy(pool, resp->body);
    return clone;
}


/******************************************************************************/
/* Process socket events                                                      */
/******************************************************************************/

/**
 * Process events on connection proxy <-> server, reads all incoming data,
 * writes all outgoing data.
 * This only supports SSL TUNNEL mode at this time.
 */
static apr_status_t processProxy(_mhClientCtx_t *cctx, const apr_pollfd_t *desc)
{
    apr_status_t status = APR_SUCCESS;

    if ((desc->rtnevents & APR_POLLOUT) && (cctx->osbuflen > 0)) {
        apr_size_t len = cctx->osbuflen;
        STATUSREADERR(apr_socket_send(cctx->proxyskt, cctx->osbuf, &len));
        _mhLog(MH_VERBOSE, cctx->proxyskt,
               "Proxy sent to server, status %d:\n%.*s\n---- %d ----\n",
               status, (unsigned int)len, cctx->osbuf, (unsigned int)len);
        cctx->osbufrem += len;
        cctx->osbuflen -= len;
    }

    if (desc->rtnevents & APR_POLLIN) {
        char *buf = cctx->ocbuf + cctx->ocbuflen;
        apr_size_t len = cctx->ocbufrem;
        STATUSREADERR(apr_socket_recv(cctx->proxyskt, buf, &len));
        _mhLog(MH_VERBOSE, cctx->proxyskt,
               "Proxy received from server, status %d:\n%.*s\n---- %d ----\n",
               status, (unsigned int)len, buf, (unsigned int)len);
        cctx->ocbuflen += len;
        cctx->ocbufrem -= len;
    }

    return status;

}

/**
 * Process events on connection client <-> proxy or client <-> server
 * Reads all incoming data, tries to match complete and/or incomplete requests,
 * and then writes responses back to the socket CCTX.
 *
 * Returns APR_EOF when the connection should be closed.
 **/
static apr_status_t processServer(mhServCtx_t *ctx, _mhClientCtx_t *cctx,
                                  const apr_pollfd_t *desc)
{
    apr_status_t status = APR_EAGAIN;
    bucket_t *stream = cctx->stream;
    apr_size_t len;

    /* First sent any pending responses before reading the next request. */
    if (desc->rtnevents & APR_POLLOUT &&
        (cctx->currResp || cctx->respQueue->nelts || cctx->ocbuflen)) {
        mhResponse_t *resp;

        if (cctx->ocbuflen) {
            apr_size_t len = cctx->ocbuflen;
            STATUSREADERR(apr_socket_send(cctx->skt, cctx->ocbuf, &len));
            _mhLog(MH_VERBOSE, cctx->skt,
                   "Proxy/Server sent to client, status %d:\n%.*s\n---- %d ----\n",
                   status, (unsigned int)len, cctx->ocbuf, (unsigned int)len);
            cctx->ocbufrem += len;
            cctx->ocbuflen -= len;
            /* TODO: len < ocbuflen? */
            return status; /* can't send more data */
        }

        while (cctx->currResp || cctx->respQueue->nelts > 0) {
            resp = cctx->currResp ? cctx->currResp :
                            *(mhResponse_t **)apr_array_pop(cctx->respQueue);
            if (resp) {
                _mhLog(MH_VERBOSE, cctx->skt, "Sending response to client.\n");

                status = writeResponse(cctx, resp);
                if (status == APR_EOF) {
                    cctx->currResp = NULL;
                    ctx->mh->verifyStats->requestsResponded++;
                    if (resp->closeConn) {
                        _mhLog(MH_VERBOSE, cctx->skt,
                               "Actively closing connection.\n");
                        return APR_EOF;
                    }
                    status = APR_SUCCESS;
                } else {
                    cctx->currResp = resp;
                    status = APR_EAGAIN;
                    break;
                }
            } else {
                return APR_EGENERAL;
            }
        }
    }

    status = stream->type->peek(stream, &len);
    if (desc->rtnevents & APR_POLLIN || len > 0) {
        mhAction_t action;

        switch (cctx->mode) {
          case ModeServer:
          case ModeProxy:
            /* Read partial or full requests */
            STATUSREADERR(readRequest(cctx, &cctx->req));

            if (!cctx->req)
                return status;

            if (status == APR_EOF) {
                mhResponse_t *resp;
                mhAction_t action;

                /* complete request received */
                ctx->mh->verifyStats->requestsReceived++;
                cctx->reqsReceived++;
                ctx->reqState = FullReqReceived;
                *((mhRequest_t **)apr_array_push(ctx->reqsReceived)) = cctx->req;
                if (_mhMatchRequest(ctx, cctx, cctx->req,
                                    &resp, &action) == YES) {
                    ctx->mh->verifyStats->requestsMatched++;
                    if (resp) {
                        _mhLog(MH_VERBOSE, cctx->skt,
                               "Request matched, queueing response.\n");
                        resp = cloneResponse(cctx->pool, resp);
                    } else {
                        _mhLog(MH_VERBOSE, cctx->skt,
                               "Request matched, queueing default response.\n");
                        resp = cloneResponse(cctx->pool, ctx->mh->defResponse);
                    }

                    switch (action) {
                      case mhActionInitiateSSLTunnel:
                        _mhLog(MH_VERBOSE, cctx->skt, "Initiating SSL tunnel.\n");
                        cctx->mode = ModeTunnel;
                        cctx->proxyhost = apr_pstrdup(cctx->pool,
                                                      cctx->req->url);
                        connectToServer(ctx, cctx);
                        break;
                      case mhActionSSLRenegotiate:
                        _mhLog(MH_VERBOSE, cctx->skt, "Renegotiating SSL "
                               "session.\n");
                        renegotiateSSLSession(cctx);
                        break;
                      case mhActionCloseConnection:
                        /* close conn after response */
                        resp->closeConn = YES;
                        break;
                      default:
                        break;
                    }
                } else {
                    ctx->mh->verifyStats->requestsNotMatched++;
                    _mhLog(MH_VERBOSE, cctx->skt,
                           "Request found no match, queueing error response.\n");
                    resp = cloneResponse(cctx->pool, ctx->mh->defErrorResponse);
                }
                if (ctx->maxRequests && cctx->reqsReceived >= ctx->maxRequests) {
                    setHeader(resp->hdrs, "Connection", "close");
                    resp->closeConn = YES;
                }

                /* Link the request to the response, and push the request on the
                   queue back to the client */
                resp->req = cctx->req;
                *((mhResponse_t **)apr_array_push(cctx->respQueue)) = resp;
                cctx->req = NULL;

                return APR_SUCCESS;
            } else if (status == APR_SUCCESS || status == APR_EAGAIN) {
                ctx->reqState = PartialReqReceived;
            }

            if (ctx->incompleteReqMatchers->nelts > 0 ||
                ctx->mh->incompleteReqMatchers->nelts > 0) {
                mhResponse_t *resp = NULL;
                /* (currently) incomplete request received? */
                if (_mhMatchIncompleteRequest(ctx, cctx, cctx->req,
                                              &resp, &action) == YES) {
                    _mhLog(MH_VERBOSE, cctx->skt,
                           "Incomplete request matched, queueing response.\n");
                    ctx->mh->verifyStats->requestsMatched++;
                    if (!resp)
                        resp = cloneResponse(cctx->pool, ctx->mh->defResponse);
                    resp->req = cctx->req;
                    *((mhResponse_t **)apr_array_push(cctx->respQueue)) = resp;
                    cctx->req = NULL;
                    return APR_SUCCESS;
                }
            }
            break;
          case ModeTunnel:
            {
                const char *data;
                /* Forward raw data */
                len = cctx->osbufrem;
                STATUSREADERR(stream->type->read(stream, len, &data, &len));

                if (len) {
                    memmove(cctx->osbuf, data, len);
                    _mhLog(MH_VERBOSE, cctx->skt,
                           "recvd with status %d:\n%.*s\n---- %d ----\n",
                           status, (unsigned int)len, cctx->osbuf + cctx->osbuflen,
                           (unsigned int)len);
                    cctx->osbuflen += len;
                    cctx->osbufrem -= len;
                }
            }
            break;
          default:
            break;
        }
    }

    return status;
}

/**
 * Initialize the client context. This stores all info related to one client
 * socket in the server.
 */
static _mhClientCtx_t *initClientCtx(apr_pool_t *pool, mhServCtx_t *serv_ctx,
                                     apr_socket_t *cskt, mhServerType_t type)
{
    _mhClientCtx_t *cctx;
    apr_pool_t *ccpool;
    apr_pool_create(&ccpool, pool);

    cctx = apr_pcalloc(ccpool, sizeof(_mhClientCtx_t));
    cctx->pool = ccpool;
    cctx->skt = cskt;
    cctx->ocbuflen = 0;
    cctx->ocbufrem = BUFSIZE;
    cctx->osbuflen = 0;
    cctx->osbufrem = BUFSIZE;
    cctx->closeConn = NO;
    cctx->respQueue = apr_array_make(pool, 5, sizeof(mhResponse_t *));
    cctx->currResp = NULL;
    cctx->mode = ModeServer;
    if (type == mhHTTPv1Server || type == mhHTTPv11Server ||
        type == mhHTTPv1Proxy || type == mhHTTPv11Proxy) {
        cctx->read = socketRead;
        cctx->send = socketWrite;
    }
#ifdef MOCKHTTP_OPENSSL
    if (type == mhHTTPSv1Server || type == mhHTTPSv11Server) {
        cctx->handshake = sslHandshake;
        cctx->read = sslSocketRead;
        cctx->send = sslSocketWrite;
        cctx->keyFile = serv_ctx->keyFile;
        cctx->passphrase = serv_ctx->passphrase;
        cctx->certFiles = serv_ctx->certFiles;
        cctx->clientCert = serv_ctx->clientCert;
        cctx->protocols = serv_ctx->protocols;
        initSSLCtx(cctx);
    }
#endif
    cctx->stream = createBufferedSocketBucket(cskt, cctx->read,
                                              cctx->ssl_ctx, ccpool);
    return cctx;
}

static void closeAndRemoveClientCtx(mhServCtx_t *ctx, _mhClientCtx_t *cctx)
{
    int i;
    apr_array_header_t *clients = ctx->clients;
    apr_pollfd_t pfd = { 0 };

    /* Close socket and clean up client context */
    pfd.desc_type = APR_POLL_SOCKET;
    pfd.desc.s = cctx->skt;
    pfd.reqevents = cctx->reqevents;
    apr_pollset_remove(ctx->pollset, &pfd);
    apr_socket_close(cctx->skt);

    if (cctx->proxyskt) {
        pfd.desc_type = APR_POLL_SOCKET;
        pfd.desc.s = cctx->proxyskt;
        pfd.reqevents = cctx->proxyreqevents;
        apr_pollset_remove(ctx->pollset, &pfd);
        apr_socket_close(cctx->proxyskt);
    }

    /* TODO: a linked list would be more efficient. */
    /* Swap the last element to the location of the element to be
     deleted, then decrease the size of the array by 1 */
    for (i = 0; i < clients->nelts; i++) {
        _mhClientCtx_t *tmp = APR_ARRAY_IDX(clients, i, _mhClientCtx_t *);
        if (cctx == tmp) {
            if (i+1 < clients->nelts) {
                _mhClientCtx_t *last;
                last = APR_ARRAY_IDX(clients, clients->nelts - 1,
                                     _mhClientCtx_t *);
                *(_mhClientCtx_t **)&clients->elts[i] = last;
            }
            clients->nelts--;
        }
    }
}

/**
 * Process all events on all sockets related to this server CTX, i.e. the server
 * socket for incoming connections, the client socket(s) and the outgoing
 * socket in case this server acts as a proxy.
 */
apr_status_t _mhRunServerLoop(mhServCtx_t *ctx)
{
    apr_int32_t num;
    const apr_pollfd_t *desc;
    apr_status_t status;

    if (ctx->reqState == FullReqReceived)
        ctx->reqState = NoReqsReceived;
#if 0
    /* TODO: add a dirty flag to every socket wrapping context, only listen
       for writeable events with the socket is dirty */
    apr_pollfd_t pfd = { 0 };
    cctx = ctx->cctx;
    /* something to write */
    if (cctx && cctx->skt) {
        pfd.desc_type = APR_POLL_SOCKET;
        pfd.desc.s = cctx->skt;
        pfd.reqevents = cctx->reqevents;
        pfd.client_data = cctx;
        apr_pollset_remove(ctx->pollset, &pfd);

        cctx->reqevents = APR_POLLIN;
        if (cctx->currResp || cctx->respQueue->nelts > 0 || cctx->obuflen > 0)
            cctx->reqevents |= APR_POLLOUT;
        pfd.reqevents = ctx->cctx->reqevents;
        STATUSERR(apr_pollset_add(ctx->pollset, &pfd));
    }
#endif
    STATUSERR(apr_pollset_poll(ctx->pollset, APR_USEC_PER_SEC / 100,
                               &num, &desc));

    /* The same socket can be returned multiple times by apr_pollset_poll() */
    while (num--) {
        if (desc->desc.s == ctx->skt) {
            _mhClientCtx_t *cctx;
            apr_socket_t *cskt;
            apr_pollfd_t pfd = { 0 };

            _mhLog(MH_VERBOSE, ctx->skt, "Accepting client connection.\n");

            STATUSERR(apr_socket_accept(&cskt, ctx->skt, ctx->pool));

            STATUSERR(apr_socket_opt_set(cskt, APR_SO_NONBLOCK, 1));
            STATUSERR(apr_socket_timeout_set(cskt, 0));

            /* Push a client context on the ctx->clients stack */
            cctx = initClientCtx(ctx->pool, ctx, cskt, ctx->type);
            pfd.desc_type = APR_POLL_SOCKET;
            pfd.desc.s = cskt;
            pfd.reqevents = APR_POLLIN | APR_POLLOUT;
            pfd.client_data = cctx;
            STATUSERR(apr_pollset_add(ctx->pollset, &pfd));
            cctx->reqevents = pfd.reqevents;
            *((_mhClientCtx_t **)apr_array_push(ctx->clients)) = cctx;

        } else {
            _mhClientCtx_t *cctx = desc->client_data;

            if (!cctx || !cctx->skt) {
                _mhLog(MH_VERBOSE, NULL, "Getting event from unknown socket.\n");
            } else if (desc->desc.s == cctx->proxyskt) {
                /* Connection proxy <-> server */
                STATUSREADERR(processProxy(cctx, desc));
                if (status == APR_EOF) {
                    apr_pollfd_t pfd = { 0 };
                    pfd.desc_type = APR_POLL_SOCKET;
                    pfd.desc.s = cctx->proxyskt;
                    pfd.reqevents = cctx->proxyreqevents;
                    apr_pollset_remove(ctx->pollset, &pfd);
                    apr_socket_close(cctx->proxyskt);

                }
            } else {
                /* Connection client <-> proxy/server */
                status = APR_SUCCESS;

                if (cctx->handshake)
                    status = cctx->handshake(cctx);

                /* APR_SUCCESS -> handshake finished or not needed */
                if (status == APR_SUCCESS) {
                    STATUSREADERR(processServer(ctx, cctx, desc));
                    if (status == APR_EOF) {
                        /* Close the socket and an associated proxy skt */
                        closeAndRemoveClientCtx(ctx, cctx);
                    }
                }
            }
        }
        desc++;
    }

    return status;
}

/******************************************************************************/
/* Init HTTP server                                                           */
/******************************************************************************/

/**
 * Creates a new server on localhost and on the default server port.
 */
mhServCtx_t *mhNewServer(MockHTTP *mh)
{
    mh->servCtx = initServCtx(mh, "localhost", DefaultSrvPort);
    mh->servCtx->type = mhGenericServer;
    return mh->servCtx;
}

/**
 * Creates a new proxy server on localhost and on the default proxy port.
 */
mhServCtx_t *mhNewProxy(MockHTTP *mh)
{
    mh->proxyCtx = initServCtx(mh, "localhost", DefaultProxyPort);
    mh->proxyCtx->type = mhGenericProxy;
    return mh->proxyCtx;
}

/**
 * Returns the server context associated with id SERVERID.
 */
mhServCtx_t *mhFindServerByID(const MockHTTP *mh, const char *serverID)
{
    if (mh->servCtx && mh->servCtx->serverID &&
        strcmp(mh->servCtx->serverID, serverID) == 0) {
        return mh->servCtx;
    }

    if (mh->proxyCtx && mh->proxyCtx->serverID &&
        strcmp(mh->proxyCtx->serverID, serverID) == 0) {
        return mh->proxyCtx;
    }
    return NULL;
}

/**
 * Takes a list of builders of type mhServerSetupBldr_t *'s and executes them 
 * one by one (in the order they are passed as arguments) to configure the
 * server SERV_CTX.
 */
void mhConfigServer(mhServCtx_t *serv_ctx, ...)
{
    va_list argp;

    /* Build the server configuration */
    va_start(argp, serv_ctx);
    while (1) {
        mhServerSetupBldr_t *ssb;
        ssb = va_arg(argp, mhServerSetupBldr_t *);
        if (ssb == NULL)
            break;
        if (ssb->builder.type == BuilderTypeNone)
            continue;
        if (ssb->builder.type != BuilderTypeServerSetup) {
            _mhErrorUnexpectedBuilder(serv_ctx->mh, ssb, BuilderTypeServerSetup);
            break;
        }
        ssb->serversetup(ssb, serv_ctx);
    }
    va_end(argp);

    if (serv_ctx->protocols == mhProtoUnspecified) {
        serv_ctx->protocols = mhProtoAllSecure;
    }
    if (!serv_ctx->serverID) {
        if (serv_ctx->type == mhGenericProxy) {
            serv_ctx->serverID = DEFAULT_PROXY_ID;
        } else {
            serv_ctx->serverID = DEFAULT_SERVER_ID;
        }
    }
}

/**
 * Starts the server CTX, makes it start listening for incoming connections.
 */
void mhStartServer(mhServCtx_t *ctx)
{
    apr_thread_t *thread;
    mhError_t err = MOCKHTTP_NO_ERROR;
    apr_status_t status;

    if (ctx->threading == mhThreadSeparate) {
#if APR_HAS_THREADS
        /* Setup a non-blocking TCP server */
        status = setupTCPServer(ctx);
        if (!status) {
            status = apr_thread_create(&thread, NULL, run_thread,
                                       ctx, ctx->pool);
            if (!status)
                ctx->threadid = thread;
        }
#else
        status = APR_EGENERAL;
#endif
    } else {
        /* Setup a non-blocking TCP server */
        status = setupTCPServer(ctx);
    }

    if (status) {
        err = MOCKHTTP_SETUP_FAILED;
    }
    /* TODO: store error message */
}

void mhStopServer(mhServCtx_t *ctx)
{
    apr_status_t status;
#ifdef APR_HAS_THREADS
    if (ctx->threading == mhThreadSeparate && ctx->threadid) {
        ctx->cancelThread = YES;
        apr_thread_join(&status, ctx->threadid);
    }
#endif
}


/**
 * Factory function, creates a builder of type mhServerSetupBldr_t.
 */
static mhServerSetupBldr_t *createServerSetupBldr(apr_pool_t *pool)
{
    mhServerSetupBldr_t *ssb = apr_pcalloc(pool, sizeof(mhServerSetupBldr_t));
    ssb->builder.magic = MagicKey;
    ssb->builder.type = BuilderTypeServerSetup;
    return ssb;
}

/**
 * Builder callback, sets the server id on server CTX.
 */
static bool set_server_id(const mhServerSetupBldr_t *ssb, mhServCtx_t *ctx)
{
    ctx->serverID = ssb->baton;
    return YES;
}


/**
 * Create a builder of type mhServerSetupBldr_t, sets the server id
 */
mhServerSetupBldr_t *mhSetServerID(mhServCtx_t *ctx, const char *serverID)
{
    apr_pool_t *pool = ctx->pool;
    mhServerSetupBldr_t *ssb = createServerSetupBldr(pool);
    ssb->baton = apr_pstrdup(pool, serverID);
    ssb->serversetup = set_server_id;
    return ssb;
}

/**
 * Builder callback, sets the number of maximum requests per connection on 
 * server CTX.
 */
static bool
set_server_maxreqs_per_conn(const mhServerSetupBldr_t *ssb, mhServCtx_t *ctx)
{
    ctx->maxRequests = ssb->ibaton;
    return YES;
}

/**
 * Create a builder of type mhServerSetupBldr_t, sets the number of maximum 
 * requests per connection.
 */
mhServerSetupBldr_t *
mhSetServerMaxRequestsPerConn(mhServCtx_t *ctx, unsigned int maxRequests)
{
    apr_pool_t *pool = ctx->pool;
    mhServerSetupBldr_t *ssb = createServerSetupBldr(pool);
    ssb->ibaton = maxRequests;
    ssb->serversetup = set_server_maxreqs_per_conn;
    return ssb;
}

unsigned int mhServerByIDPortNr(const MockHTTP *mh, const char *serverID)
{
    mhServCtx_t *ctx = mhFindServerByID(mh, serverID);
    if (ctx)
        return ctx->port;
    return 0;
}

unsigned int mhServerPortNr(const MockHTTP *mh)
{
    return mhServerByIDPortNr(mh, DEFAULT_SERVER_ID);
}

unsigned int mhProxyPortNr(const MockHTTP *mh)
{
    return mhServerByIDPortNr(mh, DEFAULT_PROXY_ID);
}

/**
 * Builder callback, sets the port number on server CTX.
 */
static bool set_server_port(const mhServerSetupBldr_t *ssb, mhServCtx_t *ctx)
{
    ctx->port = ssb->ibaton;
    return YES;
}

/**
 * Create a builder of type mhServerSetupBldr_t, sets the server port
 */
mhServerSetupBldr_t *mhSetServerPort(mhServCtx_t *ctx, unsigned int port)
{
    apr_pool_t *pool = ctx->pool;
    mhServerSetupBldr_t *ssb = createServerSetupBldr(pool);
    ssb->ibaton = port;
    ssb->serversetup = set_server_port;
    return ssb;
}

/**
 * Builder callback, sets the server type on server CTX.
 */
static bool set_server_type(const mhServerSetupBldr_t *ssb, mhServCtx_t *ctx)
{
    mhServerType_t type = ssb->ibaton;

    switch (ctx->type) {
        case mhGenericServer:
            if (type == mhHTTPv1)
                ctx->type = mhHTTPv1Server;
            else if (type == mhHTTPv11)
                ctx->type = mhHTTPv11Server;
            else if (type == mhHTTPSv1)
                ctx->type = mhHTTPSv1Server;
            else
                ctx->type = mhHTTPSv11Server;
            break;
        case mhGenericProxy:
            if (type == mhHTTPv1)
                ctx->type = mhHTTPv1Proxy;
            else if (type == mhHTTPv11)
                ctx->type = mhHTTPv11Proxy;
            else if (type == mhHTTPSv1)
                ctx->type = mhHTTPSv1Proxy;
            else
                ctx->type = mhHTTPSv11Proxy;
            break;
        default:
            /* TODO: error in test configuration. */
            break;
    }
    return YES;
}

/**
 * Create a builder of type mhServerSetupBldr_t, sets the server type
 */
mhServerSetupBldr_t *mhSetServerType(mhServCtx_t *ctx, mhServerType_t type)
{
    apr_pool_t *pool = ctx->pool;
    mhServerSetupBldr_t *ssb = createServerSetupBldr(pool);
    ssb->ibaton = type;
    ssb->serversetup = set_server_type;
    return ssb;
}

/**
 * Builder callback, sets the server's threading mode on server CTX.
 */
static bool
set_server_threading(const mhServerSetupBldr_t *ssb, mhServCtx_t *ctx)
{
    ctx->threading = ssb->ibaton;
    return YES;
}


/**
 * Create a builder of type mhServerSetupBldr_t, sets the server threading mode.
 */
mhServerSetupBldr_t *
mhSetServerThreading(mhServCtx_t *ctx, mhThreading_t threading)
{
    apr_pool_t *pool = ctx->pool;
    mhServerSetupBldr_t *ssb = createServerSetupBldr(pool);
    ssb->ibaton = threading;
    ssb->serversetup = set_server_threading;
    return ssb;
}

/**
 * Builder callback, sets the prefix for certificate paths on server CTX.
 */
static bool
set_server_cert_prefix(const mhServerSetupBldr_t *ssb, mhServCtx_t *ctx)
{
    ctx->certFilesPrefix = ssb->baton;
    return YES;
}


/**
 * Create a builder of type mhServerSetupBldr_t, sets the prefix for cert paths.
 */
mhServerSetupBldr_t *
mhSetServerCertPrefix(mhServCtx_t *ctx, const char *prefix)
{
    apr_pool_t *pool = ctx->pool;
    mhServerSetupBldr_t *ssb = createServerSetupBldr(pool);
    ssb->baton = apr_pstrdup(pool, prefix);
    ssb->serversetup = set_server_cert_prefix;
    return ssb;
}

/**
 * Builder callback, sets the path of the server private key file on server CTX.
 */
static bool
set_server_key_file(const mhServerSetupBldr_t *ssb, mhServCtx_t *ctx)
{
    const char *keyFile = ssb->baton;
    if (ctx->certFilesPrefix) {
        ctx->keyFile = apr_pstrcat(ctx->pool, ctx->certFilesPrefix, "/",
                                   keyFile, NULL);
    } else {
        ctx->keyFile = keyFile;
    }
    return YES;
}


/**
 * Create a builder of type mhServerSetupBldr_t, sets the private key file.
 */
mhServerSetupBldr_t *
mhSetServerCertKeyFile(mhServCtx_t *ctx, const char *keyFile)
{
    apr_pool_t *pool = ctx->pool;
    mhServerSetupBldr_t *ssb = createServerSetupBldr(pool);
    ssb->baton = apr_pstrdup(pool, keyFile);
    ssb->serversetup = set_server_key_file;
    return ssb;
}

/**
 * Builder callback, sets the passphrase to be used to decrypt the private key 
 * file on server CTX.
 */
static bool
set_server_key_passphrase(const mhServerSetupBldr_t *ssb, mhServCtx_t *ctx)
{
    ctx->passphrase = ssb->baton;
    return YES;
}


/**
 * Create a builder of type mhServerSetupBldr_t, sets the private key passphrase.
 */
mhServerSetupBldr_t *
mhSetServerCertKeyPassPhrase(mhServCtx_t *ctx, const char *passphrase)
{
    apr_pool_t *pool = ctx->pool;
    mhServerSetupBldr_t *ssb = createServerSetupBldr(pool);
    ssb->baton = apr_pstrdup(pool, passphrase);
    ssb->serversetup = set_server_key_passphrase;
    return ssb;
}

/**
 * Builder callback, adds a list of certificate files on server CTX.
 */
static bool
add_server_cert_files(const mhServerSetupBldr_t *ssb, mhServCtx_t *ctx)
{
    int i;
    const apr_array_header_t *certFiles = ssb->baton;

    if (!ctx->certFiles)
        ctx->certFiles = apr_array_make(ctx->pool, 5, sizeof(const char *));

    /* Copy over the cert file paths, add prefix */
    for (i = 0; i < certFiles->nelts; i++) {
        const char *certFile = APR_ARRAY_IDX(certFiles, i, const char *);

        if (ctx->certFilesPrefix)
            certFile = apr_pstrcat(ctx->pool, ctx->certFilesPrefix, "/",
                                   certFile, NULL);
        *((const char **)apr_array_push(ctx->certFiles)) = certFile;
    }
    return YES;
}


/**
 * Create a builder of type mhServerSetupBldr_t, adds certificates.
 */
mhServerSetupBldr_t *
mhAddServerCertFiles(mhServCtx_t *ctx, ...)
{
    apr_pool_t *pool = ctx->pool;
    mhServerSetupBldr_t *ssb = createServerSetupBldr(pool);
    va_list argp;
    apr_array_header_t *certFiles;

    certFiles = apr_array_make(ctx->pool, 5, sizeof(const char *));

    va_start(argp, ctx);
    while (1) {
        const char *certFile = va_arg(argp, const char *);
        if (certFile == NULL)
            break;
        *((const char **)apr_array_push(certFiles)) = apr_pstrdup(pool, certFile);
    }
    va_end(argp);

    ssb->baton = certFiles;
    ssb->serversetup = add_server_cert_files;

    return ssb;
}


/**
 * Create a builder of type mhServerSetupBldr_t, adds an array of certificates.
 */
mhServerSetupBldr_t *
mhAddServerCertFileArray(mhServCtx_t *ctx, const char **certFiles)
{
    apr_pool_t *pool = ctx->pool;
    mhServerSetupBldr_t *ssb = createServerSetupBldr(pool);
    apr_array_header_t *certFileAry;
    const char *certFile;
    int i = 0;

    certFileAry = apr_array_make(ctx->pool, 5, sizeof(const char *));

    do {
        certFile = certFiles[i++];
        *((const char **)apr_array_push(certFileAry)) = apr_pstrdup(pool,
                                                                    certFile);
    } while (certFiles[i] != NULL);
    ssb->baton = certFileAry;
    ssb->serversetup = add_server_cert_files;
    return ssb;
}

/**
 * Builder callback, sets how server CTX should request client certificates.
 */
static bool
set_server_request_client_cert(const mhServerSetupBldr_t *ssb, mhServCtx_t *ctx)
{
    ctx->clientCert = ssb->ibaton;
    return YES;
}


/**
 * Create a builder of type mhServerSetupBldr_t, sets how the server should
 * request client certificates.
 */
mhServerSetupBldr_t *
mhSetServerRequestClientCert(mhServCtx_t *ctx, mhClientCertVerification_t v)
{
    apr_pool_t *pool = ctx->pool;
    mhServerSetupBldr_t *ssb = createServerSetupBldr(pool);
    ssb->ibaton = v;
    ssb->serversetup = set_server_request_client_cert;
    return ssb;
}

/**
 * Builder callback, adds an allowed SSL/TLS version on server CTX.
 */
static bool
add_server_ssl_protocol(const mhServerSetupBldr_t *ssb, mhServCtx_t *ctx)
{
    ctx->protocols |= ssb->ibaton;
    return YES;
}

/**
 * Create a builder of type mhServerSetupBldr_t, adds allowed SSL/TLS version.
 */
mhServerSetupBldr_t *mhAddSSLProtocol(mhServCtx_t *ctx, mhSSLProtocol_t proto)
{
    apr_pool_t *pool = ctx->pool;
    mhServerSetupBldr_t *ssb = createServerSetupBldr(pool);
    ssb->ibaton = proto;
    ssb->serversetup = add_server_ssl_protocol;
    return ssb;
}


#ifdef MOCKHTTP_OPENSSL
/******************************************************************************/
/* Init HTTPS server                                                          */
/******************************************************************************/
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

struct sslCtx_t {
    bool handshake_done;
    bool renegotiate;
    apr_status_t bio_read_status;

    SSL_CTX* ctx;
    SSL* ssl;
    BIO *bio;

};

static int init_done = 0;

/**
 * OpenSSL callback, returns the passphrase used to decrypt the private key.
 */
static int pem_passwd_cb(char *buf, int size, int rwflag, void *userdata)
{
    _mhClientCtx_t *cctx = userdata;

    if (!cctx->passphrase)
        return 0;

    strncpy(buf, cctx->passphrase, size);
    buf[size - 1] = '\0';
    return strlen(buf);
}

/**
 * OpenSSL BIO callback. Creates a new BIO structure.
 */
static int bio_apr_socket_create(BIO *bio)
{
    bio->shutdown = 1;
    bio->init = 1;
    bio->num = -1;
    bio->ptr = NULL;

    return 1;
}

/**
 * OpenSSL BIO callback. Cleans up the BIO structure.
 */
static int bio_apr_socket_destroy(BIO *bio)
{
    /* Did we already free this? */
    if (bio == NULL) {
        return 0;
    }

    return 1;
}

/**
 * OpenSSL BIO callback.
 */
static long bio_apr_socket_ctrl(BIO *bio, int cmd, long num, void *ptr)
{
    long ret = 1;

    switch (cmd) {
        default:
            /* abort(); */
            break;
        case BIO_CTRL_FLUSH:
            /* At this point we can't force a flush. */
            break;
        case BIO_CTRL_PUSH:
        case BIO_CTRL_POP:
            ret = 0;
            break;
    }
    return ret;
}

/**
 * OpenSSL BIO callback. Reads data from a socket, returns the amount read.
 */
static int bio_apr_socket_read(BIO *bio, char *in, int inlen)
{
    apr_size_t len = inlen;
    _mhClientCtx_t *cctx = bio->ptr;
    sslCtx_t *ssl_ctx = cctx->ssl_ctx;
    apr_status_t status;

    BIO_clear_retry_flags(bio);

    status = apr_socket_recv(cctx->skt, in, &len);
    ssl_ctx->bio_read_status = status;

    if (len || status != APR_EAGAIN)
        _mhLog(MH_VERBOSE, cctx->skt, "Read %d bytes from ssl socket with "
               "status %d.\n", len, status);

    if (status == APR_EAGAIN) {
        BIO_set_retry_read(bio);
        if (len == 0)
            return -1;
    }

    if (READ_ERROR(status))
        return -1;

    return len;
}

/**
 * OpenSSL BIO callback. Write data to a socket, returns the amount written.
 */
static int bio_apr_socket_write(BIO *bio, const char *in, int inlen)
{
    apr_size_t len = inlen;
    _mhClientCtx_t *cctx = bio->ptr;

    apr_status_t status = apr_socket_send(cctx->skt, in, &len);

    if (len || status != APR_EAGAIN)
        _mhLog(MH_VERBOSE, cctx->skt, "Wrote %d of %d bytes to ssl socket with "
               "status %d.\n", len, inlen, status);

    if (READ_ERROR(status))
        return -1;

    return len;
}


static BIO_METHOD bio_apr_socket_method = {
    BIO_TYPE_SOCKET,
    "APR sockets",
    bio_apr_socket_write,
    bio_apr_socket_read,
    NULL,                        /* Is this called? */
    NULL,                        /* Is this called? */
    bio_apr_socket_ctrl,
    bio_apr_socket_create,
    bio_apr_socket_destroy,
#ifdef OPENSSL_VERSION_NUMBER
    NULL /* sslc does not have the callback_ctrl field */
#endif
};

/**
 * Action: renegotiates a SSL session on client socket CCTX.
 * Returns APR_SUCCESS if the renegotiation handshake was successfull
 *         error if not.
 */
static apr_status_t renegotiateSSLSession(_mhClientCtx_t *cctx)
{
    sslCtx_t *ssl_ctx = cctx->ssl_ctx;

    /* TODO: check for APR_EAGAIN situation */
    if (!SSL_renegotiate(ssl_ctx->ssl))
        return APR_EGENERAL;     /* TODO: log error */
    if (!SSL_do_handshake(ssl_ctx->ssl))
        return APR_EGENERAL;

    ssl_ctx->renegotiate = YES;

    return APR_SUCCESS;
}

/**
 * Pool cleanup callback, cleans up the OpenSSL structures
 */
static apr_status_t cleanupSSL(void *baton)
{
    _mhClientCtx_t *cctx = baton;
    sslCtx_t *ssl_ctx = cctx->ssl_ctx;

    if (ssl_ctx) {
        if (ssl_ctx->ssl)
            SSL_clear(ssl_ctx->ssl);
        SSL_CTX_free(ssl_ctx->ctx);
    }

    return APR_SUCCESS;
}

/**
 * OpenSSL callback, accepts the client certificate.
 */
static int validateClientCertificate(int preverify_ok, X509_STORE_CTX *ctx)
{
    SSL *ssl = X509_STORE_CTX_get_ex_data(ctx,
                                          SSL_get_ex_data_X509_STORE_CTX_idx());
    _mhClientCtx_t *cctx = SSL_get_app_data(ssl);

    _mhLog(MH_VERBOSE, cctx->skt, "validate_client_certificate called, "
                                 "preverify: %d.\n", preverify_ok);
    /* Client cert is valid for now, can be validated later. */
    return 1;
}

/**
 * Inits the OpenSSL SSL structure.
 */
static apr_status_t initSSL(_mhClientCtx_t *cctx)
{
    sslCtx_t *ssl_ctx = cctx->ssl_ctx;

    ssl_ctx->ssl = SSL_new(ssl_ctx->ctx);
    SSL_set_cipher_list(ssl_ctx->ssl, "ALL");
    SSL_set_bio(ssl_ctx->ssl, ssl_ctx->bio, ssl_ctx->bio);
    SSL_set_app_data(ssl_ctx->ssl, cctx);

    return APR_SUCCESS;
}

/**
 * Inits the OpenSSL context.
 */
static apr_status_t initSSLCtx(_mhClientCtx_t *cctx)
{
    sslCtx_t *ssl_ctx = apr_pcalloc(cctx->pool, sizeof(*ssl_ctx));
    cctx->ssl_ctx = ssl_ctx;
    ssl_ctx->bio_read_status = APR_SUCCESS;

    /* Init OpenSSL globally */
    if (!init_done)
    {
        CRYPTO_malloc_init();
        ERR_load_crypto_strings();
        SSL_load_error_strings();
        SSL_library_init();
        OpenSSL_add_all_algorithms();
        init_done = 1;
    }

    if (!ssl_ctx->ctx) {
        X509_STORE *store;
        const char *certfile;
        int i;

        /* Configure supported protocol versions */
        ssl_ctx->ctx = SSL_CTX_new(SSLv23_server_method());
        if (! (cctx->protocols & mhProtoSSLv2))
            SSL_CTX_set_options(ssl_ctx->ctx, SSL_OP_NO_SSLv2);
        if (! (cctx->protocols & mhProtoSSLv3))
            SSL_CTX_set_options(ssl_ctx->ctx, SSL_OP_NO_SSLv3);
        if (! (cctx->protocols & mhProtoTLSv1))
            SSL_CTX_set_options(ssl_ctx->ctx, SSL_OP_NO_TLSv1);
#ifdef SSL_OP_NO_TLSv1_1
        if (! (cctx->protocols & mhProtoTLSv11))
            SSL_CTX_set_options(ssl_ctx->ctx, SSL_OP_NO_TLSv1_1);
#endif
#ifdef SSL_OP_NO_TLSv1_2
        if (! (cctx->protocols & mhProtoTLSv12))
            SSL_CTX_set_options(ssl_ctx->ctx, SSL_OP_NO_TLSv1_2);
#endif

        if (cctx->protocols == mhProtoSSLv2) {
            /* In recent versions of OpenSSL, SSLv2 has been disabled by removing
               all SSLv2 ciphers from the cipher string. 
               If SSLv2 is the only protocol this test wants to be enabled,
               re-add the SSLv2 ciphers. */
            int result = SSL_CTX_set_cipher_list(ssl_ctx->ctx, "SSLv2");
            /* ignore result */
        }

        /* Always set this callback, even if no passphrase is set. Otherwise
           OpenSSL will prompt the user to provide a passphrase if one is 
           needed. */
        SSL_CTX_set_default_passwd_cb(ssl_ctx->ctx, pem_passwd_cb);
        SSL_CTX_set_default_passwd_cb_userdata(ssl_ctx->ctx, cctx);
        if (SSL_CTX_use_PrivateKey_file(ssl_ctx->ctx, cctx->keyFile,
                                        SSL_FILETYPE_PEM) != 1) {
            _mhLog(MH_VERBOSE, cctx->skt,
                   "Cannot load private key from file '%s'\n", cctx->keyFile);
            return APR_EGENERAL;
        }

        /* Set server certificate, add ca certificates if provided. */
        certfile = APR_ARRAY_IDX(cctx->certFiles, 0, const char *);
        if (SSL_CTX_use_certificate_file(ssl_ctx->ctx, certfile,
                                         SSL_FILETYPE_PEM) != 1) {
            _mhLog(MH_VERBOSE, cctx->skt,
                   "Cannot load certificatefrom file '%s'\n", certfile);
            return APR_EGENERAL;
        }

        store = SSL_CTX_get_cert_store(ssl_ctx->ctx);
        for (i = 1; i < cctx->certFiles->nelts; i++) {
            FILE *fp;
            certfile = APR_ARRAY_IDX(cctx->certFiles, i, const char *);
            fp = fopen(certfile, "r");
            if (fp) {
                X509 *ssl_cert = PEM_read_X509(fp, NULL, NULL, NULL);
                fclose(fp);

                SSL_CTX_add_extra_chain_cert(ssl_ctx->ctx, ssl_cert);
                X509_STORE_add_cert(store, ssl_cert);
            }
        }

        /* Check if the server needs to ask the client to send a certificate
           during handshake. */
        switch (cctx->clientCert) {
            case mhCCVerifyNone:
                break;
            case mhCCVerifyPeer:
                SSL_CTX_set_verify(ssl_ctx->ctx, SSL_VERIFY_PEER,
                                   validateClientCertificate);
                break;
            case mhCCVerifyFailIfNoPeerSet:
                SSL_CTX_set_verify(ssl_ctx->ctx,
                                   SSL_VERIFY_PEER |
                                     SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                                   validateClientCertificate);
                break;
            default:
                break;
        }

        SSL_CTX_set_mode(ssl_ctx->ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);

        ssl_ctx->bio = BIO_new(&bio_apr_socket_method);
        ssl_ctx->bio->ptr = cctx;
        initSSL(cctx);

        apr_pool_cleanup_register(cctx->pool, cctx,
                                  cleanupSSL, apr_pool_cleanup_null);
    }
    return APR_SUCCESS;
}

/**
 * Callback, encrypts data of length LEN in buffer DATA and writes to the socket.
 */
static apr_status_t
sslSocketWrite(_mhClientCtx_t *cctx, const char *data, apr_size_t *len)
{
    sslCtx_t *ssl_ctx = cctx->ssl_ctx;

    int result = SSL_write(ssl_ctx->ssl, data, *len);
    if (result > 0) {
        *len = result;
        return APR_SUCCESS;
    }

    if (result == 0)
        return APR_EAGAIN;

    _mhLog(MH_VERBOSE, cctx->skt, "ssl_socket_write: ssl error?\n");

    return APR_EGENERAL;
}

/**
 * Callback, reads data and decrypt it. Decrypted buffer of length LEN is
 * returned in DATA.
 */
static apr_status_t
sslSocketRead(apr_socket_t *skt, void *baton, char *data, apr_size_t *len)
{
    sslCtx_t *ssl_ctx = baton;

    int result = SSL_read(ssl_ctx->ssl, data, *len);
    if (result > 0) {
        *len = result;
        return APR_SUCCESS;
    } else {
        int ssl_err;

        ssl_err = SSL_get_error(ssl_ctx->ssl, result);
        switch (ssl_err) {
            case SSL_ERROR_SYSCALL:
                /* error in bio_bucket_read, probably APR_EAGAIN or APR_EOF */
                *len = 0;
                return ssl_ctx->bio_read_status;
            case SSL_ERROR_WANT_READ:
                *len = 0;
                return APR_EAGAIN;
            case SSL_ERROR_SSL:
            default:
                *len = 0;
                _mhLog(MH_VERBOSE, skt,
                          "ssl_socket_read SSL Error %d: ", ssl_err);
                ERR_print_errors_fp(stderr);
                return APR_EGENERAL;
        }
    }

    /* not reachable */
    return APR_EGENERAL;
}

static void appendSSLErrMessage(const MockHTTP *mh, long result)
{
    apr_size_t startpos = strlen(mh->errmsg);
    ERR_error_string(result, mh->errmsg + startpos);
    /* TODO: debug */
    ERR_print_errors_fp(stderr);
}

/******************************************************************************/
/* Connection-level matchers: define criteria to match different aspects of a */
/* HTTP or HTTPS connection.                                                  */
/******************************************************************************/

/**
 * Builder callback, verifies if the client certificate is valid (its issuer
 * is in the provided list of trusted certificates).
 */
bool _mhClientcert_valid_matcher(const mhConnMatcherBldr_t *mp,
                                 const _mhClientCtx_t *cctx)
{
    sslCtx_t *ssl_ctx = cctx->ssl_ctx;
    X509 *peer;

    /* Check client certificate */
    peer = SSL_get_peer_certificate(ssl_ctx->ssl);
    if (peer) {
        long result = SSL_get_verify_result(ssl_ctx->ssl);
        if (result == X509_V_OK) {
            /* The client sent a certificate which verified OK */
            return YES;
        } else {
//            appendSSLErrMessage(mh, result);
        }
        /* TODO: add to error message */
        _mhLog(MH_VERBOSE, cctx->skt, "No client certificate was received.\n");
    }
    return NO;
}

/**
 * Builder callback, verifies if the client certificate CN equals a certain
 * string.
 */
bool _mhClientcertcn_matcher(const mhConnMatcherBldr_t *mp,
                             const _mhClientCtx_t *cctx)
{
    sslCtx_t *ssl_ctx = cctx->ssl_ctx;
    X509 *peer;
    const char *clientCN = mp->baton;

    /* Check client certificate */
    peer = SSL_get_peer_certificate(ssl_ctx->ssl);
    if (peer) {
        char buf[1024];
        int ret;
        X509_NAME *subject = X509_get_subject_name(peer);

        ret = X509_NAME_get_text_by_NID(subject,
                                        NID_commonName,
                                        buf, 1024);
        if (ret != -1 && strcmp(clientCN, buf) == 0) {
            return YES;
        }

        /* TODO: add to error message */
        _mhLog(MH_VERBOSE, cctx->skt, "Client certificate common name "
               "\"%s\" doesn't match expected \"%s\".\n", buf, clientCN);
        return NO;
    } else {
        /* TODO: add to error message */
        _mhLog(MH_VERBOSE, cctx->skt, "No client certificate was received.\n");
        return NO;
    }
}

/**
 * Performs the SSL handshake on the connection client/proxy <-> server, can be
 * called multiple times until successful.
 * Returns APR_EAGAIN when handshake in progress.
 *         APR_SUCCESS when handshake finished
 *         error in case of error during handshake.
 */
static apr_status_t sslHandshake(_mhClientCtx_t *cctx)
{
    sslCtx_t *ssl_ctx = cctx->ssl_ctx;
    int result;

    if (ssl_ctx->renegotiate) {
        if (!SSL_do_handshake(ssl_ctx->ssl))
            return APR_EGENERAL;
    }

    if (ssl_ctx->handshake_done)
        return APR_SUCCESS;

    /* Initial SSL handshake */
    result = SSL_accept(ssl_ctx->ssl);
    if (result == 1) {
        _mhLog(MH_VERBOSE, cctx->skt, "Handshake successful.\n");
        ssl_ctx->handshake_done = YES;

        return APR_SUCCESS;
    } else {
        int ssl_err;

        ssl_err = SSL_get_error(ssl_ctx->ssl, result);
        switch (ssl_err) {
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
                return APR_EAGAIN;
            case SSL_ERROR_SYSCALL:
                return ssl_ctx->bio_read_status; /* Usually APR_EAGAIN */
            default:
                _mhLog(MH_VERBOSE, cctx->skt, "SSL Error %d: ", ssl_err);
                ERR_print_errors_fp(stderr);
                return APR_EGENERAL;
        }
    }

    /* not reachable */
    return APR_EGENERAL;
}

#else /* TODO: OpenSSL not available => empty implementations */

#endif

/* Copyright 2014 Lieven Govaerts
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <apr_strings.h>
#include <apr_lib.h>

static char *serializeArrayOfIovecs(apr_pool_t *pool,
                                    apr_array_header_t *blocks);
static mhResponse_t *initResponse(MockHTTP *mh);


/* private functions */

/* Header should be stored with their original case to use them in responses.
   Search on header name is case-insensitive per RFC2616. */
const char *getHeader(apr_table_t *hdrs, const char *hdr)
{
    return apr_table_get(hdrs, hdr);
}

void setHeader(apr_table_t *hdrs, const char *hdr, const char *val)
{
    apr_table_add(hdrs, hdr, val);
}

/* To enable calls like Assert(expected, Verify...(), ErrorMessage()), with the
   evaluation order of the arguments not specified in C, we need the pointer to 
   where an error message will be stored before the call to Verify...().
   So we allocate up to ERRMSG_MAXSIZE bytes for the error message memory up 
   front and use it when needed */
#define ERRMSG_MAXSIZE 65000

static void appendErrMessage(const MockHTTP *mh, const char *fmt, ...)
{
    apr_pool_t *scratchpool;
    apr_size_t startpos = strlen(mh->errmsg);
    apr_size_t len;
    const char *msg;
    va_list argp;

    apr_pool_create(&scratchpool, mh->pool);
    msg = apr_pvsprintf(scratchpool, fmt, argp);

    len = strlen(msg) + 1; /* include trailing \0 */
    len = startpos + len > ERRMSG_MAXSIZE ? ERRMSG_MAXSIZE - startpos - 1: len;
    memcpy(mh->errmsg + startpos, msg, len);

    apr_pool_destroy(scratchpool);
}

/* Define a MockHTTP context */
MockHTTP *mhInit()
{
    apr_pool_t *pool;
    MockHTTP *__mh, *mh;
    mhResponse_t *__resp;

    apr_initialize();
    atexit(apr_terminate);

    apr_pool_create(&pool, NULL);
    __mh = mh = apr_pcalloc(pool, sizeof(struct MockHTTP));
    mh->pool = pool;
    mh->errmsg = apr_palloc(pool, ERRMSG_MAXSIZE);
    *mh->errmsg = '\0';
    mh->expectations = 0;
    mh->verifyStats = apr_pcalloc(pool, sizeof(mhStats_t));

    __resp = mhNewDefaultResponse(__mh);
    mhConfigResponse(__resp, WithCode(200), WithBody("Default Response"), NULL);

    __resp = mh->defErrorResponse = initResponse(__mh);
    mhConfigResponse(__resp, WithCode(500),
                     WithBody("Mock server error."), NULL);
    mh->reqMatchers = apr_array_make(pool, 5, sizeof(ReqMatcherRespPair_t *));
    mh->incompleteReqMatchers = apr_array_make(pool, 5,
                                               sizeof(ReqMatcherRespPair_t *));
    return mh;
}

void mhCleanup(MockHTTP *mh)
{
    if (!mh)
        return;

    if (mh->servCtx) {
        mhStopServer(mh->servCtx);
    }

    if (mh->proxyCtx) {
        mhStopServer(mh->proxyCtx);
    }


    /* The MockHTTP * is also allocated from mh->pool, so this will destroy
       the MockHTTP structure and all its allocated memory. */
    apr_pool_destroy(mh->pool);

    /* mh ptr is now invalid */
}

/**
 * Runs both the proxy and the server loops. This function will block as long
 * as there's data to read or write.
 *
 * reqState: NoReqsReceived if no requests were received
 *           PartialReqReceived if either proxy or server blocks on a partly 
 *                              read request.
 *           FullReqReceived if all requests have been read completely.
 */
static apr_status_t runServerLoop(MockHTTP *mh, loopRequestState_t *reqState)
{
    apr_status_t status = APR_EGENERAL;

    *reqState = NoReqsReceived;
    do {
        if (mh->proxyCtx && mh->proxyCtx->threading != mhThreadSeparate) {
            status = _mhRunServerLoop(mh->proxyCtx);
            *reqState = mh->proxyCtx->reqState;
        }
        /* TODO: status? */
        if (mh->servCtx && mh->servCtx->threading != mhThreadSeparate) {
            status = _mhRunServerLoop(mh->servCtx);
            *reqState |= mh->servCtx->reqState;
        }
    } while (status == APR_SUCCESS);

    return status;
}

mhError_t mhRunServerLoop(MockHTTP *mh)
{
    loopRequestState_t dummy;
    apr_status_t status = runServerLoop(mh, &dummy);

    if (status == MH_STATUS_WAITING)
        return MOCKHTTP_WAITING;

    if (READ_ERROR(status) && !APR_STATUS_IS_TIMEUP(status))
        return MOCKHTTP_TEST_FAILED;

    return MOCKHTTP_NO_ERROR;
}

mhError_t mhRunServerLoopCompleteRequests(MockHTTP *mh)
{
    loopRequestState_t reqState = NoReqsReceived;
    apr_status_t status = APR_EGENERAL;
    apr_time_t finish_time = apr_time_now() + apr_time_from_sec(15);

    while (1) {
        status = runServerLoop(mh, &reqState);

        if (status != APR_EAGAIN)
            break;
        if (apr_time_now() > finish_time)
            break;
        if (reqState == FullReqReceived)
            break;
    };

    if (status == APR_EAGAIN)
        return MOCKHTTP_TIMEOUT;

    return status;
}

static const builder_t NoopBuilder = { MagicKey, BuilderTypeNone };

const void *mhSetOnConditionThat(int condition, void *builder)
{
    if (condition)
        return builder;

    return &NoopBuilder;
}

/******************************************************************************/
/* Requests matchers: define criteria to match different aspects of a HTTP    */
/* request received by the MockHTTP server.                                   */
/******************************************************************************/

static mhReqMatcherBldr_t *createReqMatcherBldr(apr_pool_t *pool)
{
    mhReqMatcherBldr_t *mp = apr_pcalloc(pool, sizeof(mhReqMatcherBldr_t));
    mp->builder.magic = MagicKey;
    mp->builder.type = BuilderTypeReqMatcher;
    return mp;
}

/**
 * Builder callback, checks that the response body chunks match what's expected.
 */
static bool
chunks_matcher(const mhReqMatcherBldr_t *mp, apr_array_header_t *chunks)
{
    const char *ptr, *expected = mp->baton;
    int i;

    ptr = expected;
    for (i = 0 ; i < chunks->nelts; i++) {
        struct iovec vec;
        apr_size_t len;

        vec = APR_ARRAY_IDX(chunks, i, struct iovec);
        /* iov_base can be incomplete, so shorter than iov_len */
        len = strlen(vec.iov_base);
        if (strncmp(ptr, vec.iov_base, len) != 0)
            return NO;
        ptr += len;
    }

    /* Up until now the body matches, but maybe the body is expected to be
       longer. */
    if (*ptr != '\0')
        return NO;

    return YES;
}

/**
 * Builder callback, checks that a string matches what's expected.
 */
static bool str_matcher(const mhReqMatcherBldr_t *mp, const char *actual)
{
    const char *expected = mp->baton;

    if (expected == actual)
        return YES; /* case where both are NULL, e.g. test for header not set */

    if ((!expected && *actual == '\0') ||
        (!actual && *expected == '\0'))
        return YES; /* "" and NULL are equal */

    if (expected && actual && strcmp(expected, actual) == 0)
        return YES;

    return NO;
}

/**
 * Builder callback, checks if the request url matches.
 */
static bool url_matcher(const mhReqMatcherBldr_t *mp, const mhRequest_t *req)
{
    return str_matcher(mp, req->url);
}

mhReqMatcherBldr_t *
mhMatchURLEqualTo(const MockHTTP *mh, const char *expected)
{
    apr_pool_t *pool = mh->pool;

    mhReqMatcherBldr_t *mp = createReqMatcherBldr(pool);
    mp->baton = apr_pstrdup(pool, expected);
    mp->matcher = url_matcher;
    mp->describe_key = "URL equal to";
    mp->describe_value = expected;
    return mp;
}

/**
 * Builder callback, checks if the request url doesn't match.
 */
static bool
url_not_matcher(const mhReqMatcherBldr_t *mp, const mhRequest_t *req)
{
    return !str_matcher(mp, req->url);
}

mhReqMatcherBldr_t *
mhMatchURLNotEqualTo(const MockHTTP *mh, const char *expected)
{
    apr_pool_t *pool = mh->pool;

    mhReqMatcherBldr_t *mp = createReqMatcherBldr(pool);
    mp->baton = apr_pstrdup(pool, expected);
    mp->matcher = url_not_matcher;
    mp->describe_key = "URL not equal to";
    mp->describe_value = expected;
    return mp;
}

/**
 * Builder callback, checks if the body (chunked or not chunked) matches what's
 * expected.
 */
static bool
body_matcher(const mhReqMatcherBldr_t *mp, const mhRequest_t *req)
{
    /* ignore chunked or not chunked */
    if (req->chunked == YES)
        return chunks_matcher(mp, req->chunks);
    else {
        return chunks_matcher(mp, req->body);
    }
}

mhReqMatcherBldr_t *
mhMatchBodyEqualTo(const MockHTTP *mh, const char *expected)
{
    apr_pool_t *pool = mh->pool;

    mhReqMatcherBldr_t *mp = createReqMatcherBldr(pool);
    mp->baton = apr_pstrdup(pool, expected);
    mp->matcher = body_matcher;
    mp->describe_key = "Body equal to";
    mp->describe_value = expected;
    return mp;
}


/**
 * Builder callback, checks if the raw body matches what's expected.
 */
static bool
raw_body_matcher(const mhReqMatcherBldr_t *mp, const mhRequest_t *req)
{
    return chunks_matcher(mp, req->body);
}

mhReqMatcherBldr_t *
mhMatchRawBodyEqualTo(const MockHTTP *mh, const char *expected)
{
    apr_pool_t *pool = mh->pool;

    mhReqMatcherBldr_t *mp = createReqMatcherBldr(pool);
    mp->baton = apr_pstrdup(pool, expected);
    mp->matcher = raw_body_matcher;
    mp->describe_key = "Raw body equal to";
    mp->describe_value = expected;
    return mp;
}

mhReqMatcherBldr_t *
mhMatchIncompleteBodyEqualTo(const MockHTTP *mh, const char *expected)
{
    apr_pool_t *pool = mh->pool;

    mhReqMatcherBldr_t *mp = createReqMatcherBldr(pool);
    mp->baton = apr_pstrdup(pool, expected);
    mp->matcher = body_matcher;
    mp->match_incomplete = TRUE;
    mp->describe_key = "Incomplete body equal to";
    mp->describe_value = expected;
    return mp;
}


/**
 * Builder callback, checks if the body is not chunked and it matches the
 * expected body.
 */
static bool
body_notchunked_matcher(const mhReqMatcherBldr_t *mp, const mhRequest_t *req)
{
    if (req->chunked == YES)
        return NO;
    return chunks_matcher(mp, req->body);
}

mhReqMatcherBldr_t *
mhMatchBodyNotChunkedEqualTo(const MockHTTP *mh, const char *expected)
{
    apr_pool_t *pool = mh->pool;

    mhReqMatcherBldr_t *mp = createReqMatcherBldr(pool);
    mp->baton = apr_pstrdup(pool, expected);
    mp->matcher = body_notchunked_matcher;
    mp->describe_key = "Body not chunked equal to";
    mp->describe_value = expected;
    return mp;
}


/**
 * Builder callback, checks if the body is chunked and matches what's
 * expected.
 */
static bool
chunked_body_matcher(const mhReqMatcherBldr_t *mp, const mhRequest_t *req)
{
    if (req->chunked == NO)
        return NO;

    return chunks_matcher(mp, req->chunks);
}

mhReqMatcherBldr_t *
mhMatchChunkedBodyEqualTo(const MockHTTP *mh, const char *expected)
{
    apr_pool_t *pool = mh->pool;

    mhReqMatcherBldr_t *mp = createReqMatcherBldr(pool);
    mp->baton = apr_pstrdup(pool, expected);
    mp->matcher = chunked_body_matcher;
    mp->describe_key = "Chunked body equal to";
    mp->describe_value = expected;
    return mp;
}

/**
 * Builder callback, checks if the body is chunk and each chunk matches exactly
 * the expected chunks.
 */
static bool chunked_body_chunks_matcher(const mhReqMatcherBldr_t *mp,
                                        const mhRequest_t *req)
{
    const apr_array_header_t *chunks;
    int i;

    if (req->chunked == NO)
        return NO;

    chunks = mp->baton;
    if (chunks->nelts != req->chunks->nelts)
        return NO;

    for (i = 0 ; i < chunks->nelts; i++) {
        struct iovec actual, expected;

        actual = APR_ARRAY_IDX(req->chunks, i, struct iovec);
        expected = APR_ARRAY_IDX(chunks, i, struct iovec);

        if (actual.iov_len != expected.iov_len)
            return NO;

        if (strncmp(expected.iov_base, actual.iov_base, actual.iov_len) != 0)
            return NO;
    }

    return YES;
}

mhReqMatcherBldr_t *
mhMatchBodyChunksEqualTo(const MockHTTP *mh, ...)
{
    apr_pool_t *pool = mh->pool;
    apr_array_header_t *chunks;
    mhReqMatcherBldr_t *mp;
    va_list argp;

    chunks = apr_array_make(pool, 5, sizeof(struct iovec));
    va_start(argp, mh);
    while (1) {
        struct iovec vec;
        vec.iov_base = (void *)va_arg(argp, const char *);
        if (vec.iov_base == NULL)
            break;
        vec.iov_len = strlen(vec.iov_base);
        *((struct iovec *)apr_array_push(chunks)) = vec;
    }
    va_end(argp);

    mp = createReqMatcherBldr(pool);
    mp->baton = chunks;
    mp->matcher = chunked_body_chunks_matcher;
    mp->describe_key = "Chunked body with chunks";
    mp->describe_value = serializeArrayOfIovecs(pool, chunks);
    return mp;
}


/**
 * Builder callback, checks if a header's value matches the expected value.
 * When a header isn't set its value will be NULL, so a NULL check can be used
 * to check that the header doesn't exist.
 */
static bool
header_matcher(const mhReqMatcherBldr_t *mp, const mhRequest_t *req)
{
    const char *actual;
    int i, found = 0;
    unsigned long exphash = mp->ibaton;

    /* exphash == 0 means testing that header is NOT set */
    if (exphash) {
        for (i = 0; i < req->hdrHashes->nelts; i++) {
            unsigned long acthash = APR_ARRAY_IDX(req->hdrHashes, i, unsigned long);
            if (exphash == acthash) {
                found = 1;
                break;
            }
        }
        if (found == 0)
            return NO;
    }

    actual = getHeader(req->hdrs, mp->baton2);
    return str_matcher(mp, actual);
}

mhReqMatcherBldr_t *
mhMatchHeaderEqualTo(const MockHTTP *mh, const char *hdr, const char *value)
{
    apr_pool_t *pool = mh->pool;

    mhReqMatcherBldr_t *mp = createReqMatcherBldr(pool);
    mp->baton = apr_pstrdup(pool, value);
    mp->baton2 = apr_pstrdup(pool, hdr);
    mp->ibaton = calculateHeaderHash(hdr, value);
    mp->matcher = header_matcher;
    mp->describe_key = "Header equal to";
    mp->describe_value = apr_psprintf(pool, "%s: %s", hdr, value);
    return mp;
}

/**
 * Builder callback, checks if a header's value is not equal to the expected 
 * value.
 * When a header isn't set its value will be NULL, so a non-NULL check can be 
 * used to check if the header exists.
 */
static bool
header_not_matcher(const mhReqMatcherBldr_t *mp, const mhRequest_t *req)
{
    const char *actual = getHeader(req->hdrs, mp->baton2);
    return !str_matcher(mp, actual);
}

mhReqMatcherBldr_t *
mhMatchHeaderNotEqualTo(const MockHTTP *mh, const char *hdr, const char *value)
{
    apr_pool_t *pool = mh->pool;

    mhReqMatcherBldr_t *mp = createReqMatcherBldr(pool);
    mp->baton = apr_pstrdup(pool, value);
    mp->baton2 = apr_pstrdup(pool, hdr);
    mp->matcher = header_not_matcher;
    mp->describe_key = "Header not equal to";
    mp->describe_value = apr_psprintf(pool, "%s: %s", hdr, value);
    return mp;
}

method_t methodToCode(const char *code)
{
    char ch1, ch2;
    ch1 = toupper(*code);

    if (ch1 == 'G' && strcasecmp(code, "GET") == 0)
        return MethodGET;
    if (ch1 == 'H' && strcasecmp(code, "HEAD") == 0)
        return MethodHEAD;

    ch2 = toupper(*(code+1));
    if (ch1 == 'P') {
        if (ch2 == 'O' && strcasecmp(code, "POST") == 0)
            return MethodPOST;
        if (ch2 == 'A' && strcasecmp(code, "PATCH") == 0)
            return MethodPATCH;
        if (ch2 == 'A' && strcasecmp(code, "PUT") == 0)
            return MethodPUT;
        if (ch2 == 'R') {
            if (strcasecmp(code, "PROPFIND") == 0)
                return MethodPROPFIND;
            if (strcasecmp(code, "PROPPATCH") == 0)
                return MethodPROPPATCH;
        }
        return MethodOther;
    }
    if (ch1 == 'O') {
        if (ch2 == 'P' && strcasecmp(code, "OPTIONS") == 0)
            return MethodOPTIONS;
        if (ch2 == 'R' && strcasecmp(code, "ORDERPATCH") == 0)
            return MethodORDERPATCH;
        return MethodOther;
    }

    if (ch1 == 'A' && strcasecmp(code, "ACL") == 0)
        return MethodACL;
    if (ch1 == 'B' && strcasecmp(code, "BASELINE-CONTROL") == 0)
        return MethodBASELINE_CONTROL;
    if (ch1 == 'L' && strcasecmp(code, "LABEL") == 0)
        return MethodLABEL;
    if (ch1 == 'D' && strcasecmp(code, "DELETE") == 0)
        return MethodDELETE;
    return MethodOther;
}

/**
 * Builder callback, checks if the request method matches the expected method.
 * (case insensitive).
 * TODO: not used at this time!!
 */
static bool method_matcher(const mhReqMatcherBldr_t *mp, const mhRequest_t *req)
{
    const char *method = mp->baton;
    method_t methodCode = mp->ibaton;

    if (methodCode != req->methodCode) {
        return NO;
    } else {
        if (methodCode != MethodOther)
            return YES;
        if (strcasecmp(method, req->method) == 0) {
            return YES;
        }
        return NO;
    }
}

mhReqMatcherBldr_t *
mhMatchMethodEqualTo(const MockHTTP *mh, const char *expected)
{
    apr_pool_t *pool = mh->pool;

    mhReqMatcherBldr_t *mp = createReqMatcherBldr(pool);
    mp->baton = apr_pstrdup(pool, expected);
    mp->ibaton = methodToCode(expected);
    mp->matcher = method_matcher;
    mp->describe_key = "Method equal to";
    mp->describe_value = expected;
    return mp;
}

/**
 * Takes a list of builders of type mhReqMatcherBldr_t *'s and stores them in
 * a new request matcher. The builders will be evaluated later when a request
 * arrives in the server.
 */
static mhRequestMatcher_t *
constructRequestMatcher(const MockHTTP *mh, va_list argp)
{
    apr_pool_t *pool = mh->pool;

    mhRequestMatcher_t *rm = apr_pcalloc(pool, sizeof(mhRequestMatcher_t));
    rm->pool = pool;
    rm->matchers = apr_array_make(pool, 5, sizeof(mhReqMatcherBldr_t *));

    while (1) {
        mhReqMatcherBldr_t *rmb;
        rmb = va_arg(argp, mhReqMatcherBldr_t *);
        if (rmb == NULL)
            break;
        if (rmb->builder.type == BuilderTypeNone)
            continue;
        if (rmb->builder.type != BuilderTypeReqMatcher) {
            _mhErrorUnexpectedBuilder(mh, rmb, BuilderTypeReqMatcher);
            break;
        }
        *((mhReqMatcherBldr_t **)apr_array_push(rm->matchers)) = rmb;
    }
    return rm;
}

mhRequestMatcher_t *mhGivenRequest(MockHTTP *mh, ...)
{
    va_list argp;
    mhRequestMatcher_t *rm;

    va_start(argp, mh);
    rm = constructRequestMatcher(mh, argp);
    va_end(argp);

    return rm;
}

bool
_mhRequestMatcherMatch(const mhRequestMatcher_t *rm, const mhRequest_t *req)
{
    int i;

    for (i = 0 ; i < rm->matchers->nelts; i++) {
        const mhReqMatcherBldr_t *mp;

        mp = APR_ARRAY_IDX(rm->matchers, i, mhReqMatcherBldr_t *);
        if (mp->matcher(mp, req) == NO)
            return NO;
    }

    return YES;
}

/******************************************************************************/
/* Connection-level matchers: define criteria to match different aspects of a */
/* HTTP or HTTPS connection.                                                  */
/******************************************************************************/

static mhConnMatcherBldr_t *createConnMatcherBldr(apr_pool_t *pool)
{
    mhConnMatcherBldr_t *mp = apr_pcalloc(pool, sizeof(mhConnMatcherBldr_t));
    mp->builder.magic = MagicKey;
    mp->builder.type = BuilderTypeConnMatcher;
    return mp;
}

/* Stores a mhConnMatcherBldr_t * in the MockHTTP context */
void mhGivenConnSetup(MockHTTP *mh, ...)
{
    va_list argp;
    mhConnMatcherBldr_t *cmb;

    mh->connMatchers = apr_array_make(mh->pool, 5,
                                      sizeof(mhConnMatcherBldr_t *));

    va_start(argp, mh);
    while (1) {
        cmb = va_arg(argp, mhConnMatcherBldr_t *);
        if (cmb == NULL)
            break;
        if (cmb->builder.type == BuilderTypeNone)
            continue;
        if (cmb->builder.type != BuilderTypeConnMatcher) {
            _mhErrorUnexpectedBuilder(mh, cmb, BuilderTypeConnMatcher);
            break;
        }
        *((mhConnMatcherBldr_t **)apr_array_push(mh->connMatchers)) = cmb;
    }
    va_end(argp);
}

mhConnMatcherBldr_t *
mhMatchClientCertCNEqualTo(const MockHTTP *mh, const char *expected)
{
    apr_pool_t *pool = mh->pool;

    mhConnMatcherBldr_t *mp = createConnMatcherBldr(pool);
    mp->baton = apr_pstrdup(pool, expected);
    mp->connmatcher = _mhClientcertcn_matcher;
    mp->describe_key = "Client Certificate CN equal to";
    mp->describe_value = expected;
    return mp;
}

mhConnMatcherBldr_t *mhMatchClientCertValid(const MockHTTP *mh)
{
    apr_pool_t *pool = mh->pool;

    mhConnMatcherBldr_t *mp = createConnMatcherBldr(pool);
    mp->connmatcher = _mhClientcert_valid_matcher;
    mp->describe_key = "Client Certificate";
    mp->describe_value = "valid";
    return mp;
}

/******************************************************************************/
/* Response                                                                   */
/******************************************************************************/
static mhResponse_t *initResponse(MockHTTP *mh)
{
    apr_pool_t *pool;

    apr_pool_create(&pool, mh->pool);

    mhResponse_t *resp = apr_pcalloc(pool, sizeof(mhResponse_t));
    resp->pool = pool;
    resp->mh = mh;
    resp->code = 200;
    resp->body = apr_array_make(pool, 5, sizeof(struct iovec));
    resp->hdrs = apr_table_make(pool, 5);
    resp->builders = apr_array_make(pool, 5, sizeof(mhResponseBldr_t *));
    return resp;
}

mhResponse_t *mhNewResponseForRequest(MockHTTP *mh, mhServCtx_t *ctx,
                                      mhRequestMatcher_t *rm)
{
    apr_array_header_t *matchers;
    int i;

    mhResponse_t *resp = initResponse(mh);

    if (ctx)
        matchers = rm->incomplete ? ctx->incompleteReqMatchers : ctx->reqMatchers;
    else
        matchers = rm->incomplete ? mh->incompleteReqMatchers : mh->reqMatchers;

    /* TODO: how can this not be the last element?? */
    for (i = matchers->nelts - 1 ; i >= 0; i--) {
        ReqMatcherRespPair_t *pair;

        pair = APR_ARRAY_IDX(matchers, i, ReqMatcherRespPair_t *);
        if (rm == pair->rm) {
            pair->resp = resp;
            break;
        }
    }

    return resp;
}

void mhNewActionForRequest(MockHTTP *mh, mhServCtx_t *ctx,
                           mhRequestMatcher_t *rm, mhAction_t action)
{
    apr_array_header_t *matchers;
    int i;

    if (ctx)
        matchers = rm->incomplete ? ctx->incompleteReqMatchers : ctx->reqMatchers;
    else
        matchers = rm->incomplete ? mh->incompleteReqMatchers : mh->reqMatchers;
    for (i = matchers->nelts - 1 ; i >= 0; i--) {
        ReqMatcherRespPair_t *pair;

        pair = APR_ARRAY_IDX(matchers, i, ReqMatcherRespPair_t *);
        if (rm == pair->rm) {
            pair->action = action;
            break;
        }
    }
}

mhResponse_t *mhNewDefaultResponse(MockHTTP *mh)
{
    mh->defResponse = initResponse(mh);
    return mh->defResponse;
}

void mhConfigResponse(mhResponse_t *resp, ...)
{
    va_list argp;
    /* This is only needed for values that are only known when the request
       is received, e.g. WithRequestBody. */
    va_start(argp, resp);
    while (1) {
        mhResponseBldr_t *rb;
        rb = va_arg(argp, mhResponseBldr_t *);
        if (rb == NULL)
            break;
        if (rb->builder.type == BuilderTypeNone)
            continue;
        if (rb->builder.type != BuilderTypeResponse) {
            _mhErrorUnexpectedBuilder(resp->mh, rb, BuilderTypeResponse);
            break;
        }

        *((mhResponseBldr_t **)apr_array_push(resp->builders)) = rb;
    }
    va_end(argp);
}

static mhResponseBldr_t *createResponseBldr(apr_pool_t *pool)
{
    mhResponseBldr_t *rb = apr_pcalloc(pool, sizeof(mhResponseBldr_t));
    rb->builder.magic = MagicKey;
    rb->builder.type = BuilderTypeResponse;
    return rb;
}

static bool resp_set_code(const mhResponseBldr_t *rb, mhResponse_t *resp)
{
    resp->code = rb->ibaton;
    return YES;
}

mhResponseBldr_t *mhRespSetCode(mhResponse_t *resp, unsigned int code)
{
    apr_pool_t *pool = resp->pool;
    mhResponseBldr_t *rb = createResponseBldr(pool);
    rb->respbuilder = resp_set_code;
    rb->ibaton = code;
    return rb;
}

static bool resp_set_body(const mhResponseBldr_t *rb, mhResponse_t *resp)
{
    struct iovec vec;
    const char *body = rb->baton;

    vec.iov_base = (void *)body;
    vec.iov_len = strlen(body);
    *((struct iovec *)apr_array_push(resp->body)) = vec;
    resp->bodyLen = vec.iov_len;
    resp->chunked = NO;
    setHeader(resp->hdrs, "Content-Length",
              apr_itoa(resp->pool, resp->bodyLen));
    return YES;
}

mhResponseBldr_t *mhRespSetBody(mhResponse_t *resp, const char *body)
{
    apr_pool_t *pool = resp->pool;
    mhResponseBldr_t *rb = createResponseBldr(pool);
    rb->respbuilder = resp_set_body;
    rb->baton = apr_pstrdup(pool, body);
    return rb;
}


static bool
resp_set_chunked_body(const mhResponseBldr_t *rb, mhResponse_t *resp)
{
    resp->chunks = rb->baton;
    setHeader(resp->hdrs, "Transfer-Encoding", "chunked");
    resp->chunked = YES;
    return YES;
}

mhResponseBldr_t *mhRespSetChunkedBody(mhResponse_t *resp, ...)
{
    apr_array_header_t *chunks;
    va_list argp;

    apr_pool_t *pool = resp->pool;
    mhResponseBldr_t *rb = createResponseBldr(pool);

    chunks = apr_array_make(resp->pool, 5, sizeof(struct iovec));
    va_start(argp, resp);
    while (1) {
        struct iovec vec;
        vec.iov_base = (void *)va_arg(argp, const char *);
        if (vec.iov_base == NULL)
            break;
        vec.iov_len = strlen(vec.iov_base);
        *((struct iovec *)apr_array_push(chunks)) = vec;
    }
    va_end(argp);

    rb->baton = chunks;
    rb->respbuilder = resp_set_chunked_body;
    return rb;
}

static bool
resp_add_header(const mhResponseBldr_t *rb, mhResponse_t *resp)
{
    apr_hash_index_t *hi;
    apr_hash_t *hdrs;
    apr_pool_t *tmppool;

    apr_pool_create(&tmppool, resp->pool);
    /* get rid of const for call to apr_hash_first */
    hdrs = apr_hash_copy(tmppool, rb->baton);
    for (hi = apr_hash_first(tmppool, hdrs); hi; hi = apr_hash_next(hi)) {
        void *val;
        const void *key;
        apr_ssize_t klen;
        apr_hash_this(hi, &key, &klen, &val);

        setHeader(resp->hdrs, (const char *)key, (const char *)val);
    }
    apr_pool_destroy(tmppool);

    return YES;
}

mhResponseBldr_t *mhRespAddHeader(mhResponse_t *resp, const char *header,
                                  const char *value)
{
    apr_pool_t *pool = resp->pool;
    mhResponseBldr_t *rb = createResponseBldr(pool);
    apr_hash_t *hdrs = apr_hash_make(resp->pool);
    apr_hash_set(hdrs, header, APR_HASH_KEY_STRING, value);
    rb->baton = hdrs;
    rb->respbuilder = resp_add_header;
    return rb;
}

static bool
resp_set_close_conn_header(const mhResponseBldr_t *rb, mhResponse_t *resp)
{
    setHeader(resp->hdrs, "Connection", "close");
    resp->closeConn = YES;
    return YES;
}

mhResponseBldr_t *mhRespSetConnCloseHdr(mhResponse_t *resp)
{
    apr_pool_t *pool = resp->pool;
    mhResponseBldr_t *rb = createResponseBldr(pool);
    rb->respbuilder = resp_set_close_conn_header;
    return rb;
}


static bool
resp_use_request_header(const mhResponseBldr_t *rb, mhResponse_t *resp)
{
    mhRequest_t *req = resp->req;
    const char *value = getHeader(req->hdrs, rb->baton);
    if (value)
        setHeader(resp->hdrs, rb->baton, value);
    return YES;
}

mhResponseBldr_t *
mhRespSetUseRequestHeader(mhResponse_t *resp, const char *header)
{
    apr_pool_t *pool = resp->pool;
    mhResponseBldr_t *rb = createResponseBldr(pool);
    rb->respbuilder = resp_use_request_header;
    rb->baton = header;
    return rb;
}

static bool
resp_use_request_body(const mhResponseBldr_t *rb, mhResponse_t *resp)
{
    mhRequest_t *req = resp->req;
    if (req->chunked) {
        resp->chunks = req->chunks;
        resp->chunked = YES;
        setHeader(resp->hdrs, "Transfer-Encoding", "chunked");
    } else {
        resp->body  = req->body;
        resp->bodyLen = req->bodyLen;
        resp->chunked = NO;
        setHeader(resp->hdrs, "Content-Length",
                  apr_itoa(resp->pool, resp->bodyLen));
    }
    return YES;
}

mhResponseBldr_t *mhRespSetUseRequestBody(mhResponse_t *resp)
{
    apr_pool_t *pool = resp->pool;
    mhResponseBldr_t *rb = createResponseBldr(pool);
    rb->respbuilder = resp_use_request_body;
    return rb;
}

static bool resp_set_raw_data(const mhResponseBldr_t *rb, mhResponse_t *resp)
{
    resp->raw_data = rb->baton;
    resp->raw_data_length = rb->ibaton;
    return YES;
}

mhResponseBldr_t *
mhRespSetRawData(mhResponse_t *resp, const char *raw_data, size_t length)
{
    apr_pool_t *pool = resp->pool;
    mhResponseBldr_t *rb = createResponseBldr(pool);
    rb->respbuilder = resp_set_raw_data;
    rb->baton = apr_pstrdup(pool, raw_data);
    rb->ibaton = length;
    return rb;
}

static bool
resp_set_repeat_pattern(const mhResponseBldr_t *rb, mhResponse_t *resp)
{
    unsigned int i, n = rb->ibaton;
    const char *pattern = rb->baton;
    apr_size_t len = strlen(pattern);
    apr_pool_t *tmppool;
    struct iovec *vecs;

    /* TODO: the whole reponse body should be converted to buckets so that
       we can generate the body on the fly. */
    apr_pool_create(&tmppool, resp->pool);
    vecs = apr_pcalloc(tmppool, sizeof(struct iovec) * n);

    for (i = 0; i < n; i++) {
        vecs[i].iov_base = (void *)pattern;
        vecs[i].iov_len = len;
    }
    resp->raw_data = apr_pstrcatv(resp->pool, vecs, n, &resp->raw_data_length);

    return YES;
}

mhResponseBldr_t *mhRespSetBodyPattern(mhResponse_t *resp, const char *pattern,
                                       unsigned int n)
{
    apr_pool_t *pool = resp->pool;
    mhResponseBldr_t *rb = createResponseBldr(pool);
    rb->respbuilder = resp_set_repeat_pattern;
    rb->baton = apr_pstrdup(pool, pattern);
    rb->ibaton = n;
    return rb;
}

void _mhBuildResponse(mhResponse_t *resp)
{
    int i;
    if (resp->built == YES)
        return;
    resp->built = YES;
    for (i = 0 ; i < resp->builders->nelts; i++) {
        mhResponseBldr_t *rb;

        rb = APR_ARRAY_IDX(resp->builders, i, mhResponseBldr_t *);
        rb->respbuilder(rb, resp);
    }
}

/******************************************************************************/
/* Expectations                                                               */
/******************************************************************************/
void mhExpectAllRequestsReceivedOnce(MockHTTP *mh)
{
    mh->expectations |= RequestsReceivedOnce;
}

void mhExpectAllRequestsReceivedInOrder(MockHTTP *mh)
{
    mh->expectations |= RequestsReceivedInOrder;
}

/******************************************************************************/
/* Verify results                                                             */
/******************************************************************************/
static const char *serializeHeaders(apr_pool_t *pool, const mhRequest_t *req,
                                    const char *indent)
{
    const apr_table_entry_t *elts;
    const apr_array_header_t *arr;
    const char *hdrs = "";
    bool first = YES;
    int i;

    arr = apr_table_elts(req->hdrs);
    elts = (const apr_table_entry_t *)arr->elts;

    for (i = 0; i < arr->nelts; ++i) {
        hdrs = apr_psprintf(pool, "%s%s%s: %s\n", hdrs, first ? "" : indent,
                            elts[i].key, elts[i].val);
        first = NO;
    }
    return hdrs;
}

static char *serializeArrayOfIovecs(apr_pool_t *pool,
                                    apr_array_header_t *blocks)
{
    int i;
    char *str = "";
    for (i = 0 ; i < blocks->nelts; i++) {
        struct iovec vec = APR_ARRAY_IDX(blocks, i, struct iovec);
        str = apr_pstrcat(pool, str, vec.iov_base, NULL);
    }
    return str;
}

static const char *formatBody(apr_pool_t *outpool, int indent, const char *body)
{
    const char *newbody = "";
    char *nextkv, *line, *tmpbody;
    apr_pool_t *tmppool;

    /* Need a copy cuz we're going to write NUL characters into the string.  */
    apr_pool_create(&tmppool, outpool);
    tmpbody = apr_pstrdup(tmppool, body);

    for ( ; (line = apr_strtok(tmpbody, "\n", &nextkv)) != NULL; tmpbody = NULL)
    {
        newbody = apr_psprintf(outpool, "%s%s\n%*s", newbody, line,
                               indent, *nextkv != '\0' ? "|" : "");
    }
    apr_pool_destroy(tmppool);

    return newbody;
}

static const char *
serializeRawBody(apr_pool_t *pool, int indent, const mhRequest_t *req)
{
    char *body = serializeArrayOfIovecs(pool, req->body);
    return formatBody(pool, indent, body);
}

static const char *serializeRequest(apr_pool_t *pool, const mhRequest_t *req)
{
    const char *str;
    str = apr_psprintf(pool, "         Method: %s\n"
                             "            URL: %s\n"
                             "        Version: HTTP/%d.%d\n"
                             "        Headers: %s"
                             "  Raw body size: %ld\n"
                             "   %s:|%s\n",
                       req->method, req->url,
                       req->version / 10, req->version % 10,
                       serializeHeaders(pool, req, "                 "),
                       req->bodyLen,
                       req->chunked ? "Chunked Body" : "        Body",
                       serializeRawBody(pool, 17, req));
    return str;
}

static const char *
serializeRequestMatcher(apr_pool_t *pool, const mhRequestMatcher_t *rm,
                        const mhRequest_t *req)
{
    const char *str = "";
    int i;

    for (i = 0 ; i < rm->matchers->nelts; i++) {
        const mhReqMatcherBldr_t *mp;
        bool matches;

        mp = APR_ARRAY_IDX(rm->matchers, i, mhReqMatcherBldr_t *);
        matches = mp->matcher(mp, req);

        if (strstr(mp->describe_key, "body") != NULL) {
            /* format the expected request body */
            str = apr_psprintf(pool, "%s%25s:|%s%s\n", str,
                               mp->describe_key,
                               formatBody(pool, 27, mp->describe_value),
                               matches ? "" : "   <--- rule failed!");

        } else {
            str = apr_psprintf(pool, "%s%25s: %s%s\n", str,
                               mp->describe_key, mp->describe_value,
                               matches ? "" : "   <--- rule failed!");
        }
    }
    return str;
}

static int verifyAllRequestsReceivedInOrder(const MockHTTP *mh,
                                            const mhServCtx_t *ctx)
{
    int i;

    /* TODO: improve error message */
    if (ctx->reqsReceived->nelts > ctx->reqMatchers->nelts) {
        appendErrMessage(mh, "More requests received than expected!\n");
        return NO;
    } else if (ctx->reqsReceived->nelts < ctx->reqMatchers->nelts) {
        appendErrMessage(mh, "Less requests received than expected!\n");
        return NO;
    }

    for (i = 0; i < ctx->reqsReceived->nelts; i++)
    {
        const ReqMatcherRespPair_t *pair;
        const mhRequest_t *req;

        pair = APR_ARRAY_IDX(ctx->reqMatchers, i, ReqMatcherRespPair_t *);
        req  = APR_ARRAY_IDX(ctx->reqsReceived, i, mhRequest_t *);

        if (_mhRequestMatcherMatch(pair->rm, req) == NO) {
            apr_pool_t *tmppool;
            apr_pool_create(&tmppool, mh->pool);
            appendErrMessage(mh, "ERROR: Request wasn't expected!\n");
            appendErrMessage(mh, "=================================\n");
            appendErrMessage(mh, "Expected request with:\n");
            appendErrMessage(mh, serializeRequestMatcher(tmppool, pair->rm, req));
            appendErrMessage(mh, "---------------------------------\n");
            appendErrMessage(mh, "Actual request:\n");
            appendErrMessage(mh, serializeRequest(tmppool, req));
            appendErrMessage(mh, "=================================\n");
            apr_pool_destroy(tmppool);
            return NO;
        }
    }
    return YES;
}

int mhVerifyAllRequestsReceivedInOrder(const MockHTTP *mh)
{
    bool result = YES;

    if (mh->servCtx)
        result &= verifyAllRequestsReceivedInOrder(mh, mh->servCtx);
    if (mh->proxyCtx)
        result &= verifyAllRequestsReceivedInOrder(mh, mh->proxyCtx);
    return result;
}

static bool
isArrayElement(apr_array_header_t *ary, const ReqMatcherRespPair_t *element)
{
    int i;
    for (i = 0; i < ary->nelts; i++) {
        const ReqMatcherRespPair_t *pair;
        pair = APR_ARRAY_IDX(ary, i, ReqMatcherRespPair_t *);
        if (pair == element)
            return YES;
    }
    return NO;
}

static int verifyAllRequestsReceived(const MockHTTP *mh, const mhServCtx_t *ctx,
                                     bool breakOnNotOnce)
{
    int i;
    apr_array_header_t *used;
    apr_pool_t *pool;
    bool result = YES;

    /* TODO: improve error message */
    if (breakOnNotOnce && ctx->reqsReceived->nelts > ctx->reqMatchers->nelts) {
        appendErrMessage(mh, "More requests received than expected!\n");
        return NO;
    } else if (ctx->reqsReceived->nelts < ctx->reqMatchers->nelts) {
        appendErrMessage(mh, "Less requests received than expected!\n");
        return NO;
    }

    apr_pool_create(&pool, mh->pool);
    used = apr_array_make(mh->pool, ctx->reqsReceived->nelts,
                          sizeof(ReqMatcherRespPair_t *));;

    for (i = 0; i < ctx->reqsReceived->nelts; i++)
    {
        mhRequest_t *req = APR_ARRAY_IDX(ctx->reqsReceived, i, mhRequest_t *);
        int j;
        bool matched = NO;

        for (j = 0 ; j < ctx->reqMatchers->nelts; j++) {
            const ReqMatcherRespPair_t *pair;

            pair = APR_ARRAY_IDX(ctx->reqMatchers, j, ReqMatcherRespPair_t *);

            if (breakOnNotOnce && isArrayElement(used, pair))
                continue; /* skip this match if request matched before */

            if (_mhRequestMatcherMatch(pair->rm, req) == YES) {
                *((const ReqMatcherRespPair_t **)apr_array_push(used)) = pair;
                matched = YES;
                break;
            }
        }

        if (matched == NO) {
            apr_pool_t *tmppool;
            apr_pool_create(&tmppool, mh->pool);
            appendErrMessage(mh, "ERROR: No rule matched this request!\n");
            appendErrMessage(mh, "====================================\n");
            /* log all rules (yes this can be a long list) */
            for (j = 0 ; j < ctx->reqMatchers->nelts; j++) {
                const ReqMatcherRespPair_t *pair;

                pair = APR_ARRAY_IDX(ctx->reqMatchers, j, ReqMatcherRespPair_t *);

                if (breakOnNotOnce && isArrayElement(used, pair))
                    continue; /* skip this match if request matched before */
                appendErrMessage(mh, "Expected request(s) with:\n");
                appendErrMessage(mh, serializeRequestMatcher(tmppool, pair->rm, req));
                if (j + 1 < ctx->reqMatchers->nelts)
                    appendErrMessage(mh, "        ------------------------\n");
            }
            appendErrMessage(mh, "---------------------------------\n");
            appendErrMessage(mh, "Actual request:\n");
            appendErrMessage(mh, serializeRequest(tmppool, req));
            appendErrMessage(mh, "=================================\n");
            apr_pool_destroy(tmppool);

            result = NO;
            break;
        }
    }

    apr_pool_destroy(pool);

    return result;
}

int mhVerifyAllRequestsReceived(const MockHTTP *mh)
{
    bool result = YES;

    if (mh->servCtx)
        result &= verifyAllRequestsReceived(mh, mh->servCtx, NO);
    if (mh->proxyCtx)
        result &= verifyAllRequestsReceived(mh, mh->proxyCtx, NO);
    return result;
}

int mhVerifyAllRequestsReceivedOnce(const MockHTTP *mh)
{
    bool result = YES;

    if (mh->servCtx)
        result &= verifyAllRequestsReceived(mh, mh->servCtx, YES);
    if (mh->proxyCtx)
        result &= verifyAllRequestsReceived(mh, mh->proxyCtx, YES);
    return result;
}

const char *mhGetLastErrorString(const MockHTTP *mh)
{
    return mh->errmsg;
}

mhStats_t *mhVerifyStatistics(const MockHTTP *mh)
{
    return mh->verifyStats;
}



int mhVerifyAllExpectationsOk(const MockHTTP *mh)
{
    if (mh->expectations & RequestsReceivedInOrder)
        return mhVerifyAllRequestsReceivedInOrder(mh);
    if (mh->expectations & RequestsReceivedOnce)
        return mhVerifyAllRequestsReceivedOnce(mh);

    /* No expectations set. Consider this an error to avoid false positives */
    return NO;
}


int mhVerifyConnectionSetupOk(const MockHTTP *mh)
{
    int i;
    bool result = NO;
    apr_pool_t *match_pool;
    apr_array_header_t *clients = mh->servCtx->clients;

    apr_pool_create(&match_pool, mh->pool);
    for (i = 0; i < clients->nelts; i++) {
        _mhClientCtx_t *cctx = APR_ARRAY_IDX(clients, i, _mhClientCtx_t *);

        for (i = 0 ; i < mh->connMatchers->nelts; i++) {
            const mhConnMatcherBldr_t *cmb;

            cmb = APR_ARRAY_IDX(mh->connMatchers, i, mhConnMatcherBldr_t *);
            if (cmb->connmatcher(cmb, cctx) == NO) {
                result = NO;
                goto cleanup;
            }
        }
    }
    result = YES;

cleanup:
    apr_pool_destroy(match_pool);

    return result;
}

static const char *buildertype_to_string(builderType_t type)
{
    switch (type) {
        case BuilderTypeReqMatcher:
            return "Request Matcher";
        case BuilderTypeConnMatcher:
            return "Connection Matcher";
        case BuilderTypeResponse:
            return "Response Builder";
        case BuilderTypeServerSetup:
            return "Server Setup";
        default:
            break;
    }
    return "<unknown type>";
}

void _mhErrorUnexpectedBuilder(const MockHTTP *mh, void *actual,
                               builderType_t expected)
{
    builder_t *builder = actual;
    appendErrMessage(mh, "A builder of type %s was provided, where a builder of "
                         " type %s was expected!",
                     buildertype_to_string(builder->type),
                     buildertype_to_string(expected));
}

static void log_time(void)
{
    apr_time_exp_t tm;

    apr_time_exp_lt(&tm, apr_time_now());
    fprintf(stderr, "%d-%02d-%02dT%02d:%02d:%02d.%06d%+03d ",
            1900 + tm.tm_year, 1 + tm.tm_mon, tm.tm_mday,
            tm.tm_hour, tm.tm_min, tm.tm_sec, tm.tm_usec,
            tm.tm_gmtoff/3600);
}

void _mhLog(int verbose_flag, apr_socket_t *skt, const char *fmt, ...)
{
    va_list argp;

    if (verbose_flag) {
        log_time();

        if (skt) {
            apr_sockaddr_t *sa;
            apr_port_t lp = 0, rp = 0;

            /* Log client (remote) and server (local) port */
            if (apr_socket_addr_get(&sa, APR_LOCAL, skt) == APR_SUCCESS)
                lp = sa->port;
            if (apr_socket_addr_get(&sa, APR_REMOTE, skt) == APR_SUCCESS)
                rp = sa->port;
            fprintf(stderr, "[cp:%u sp:%u] ", rp, lp);
        }

        va_start(argp, fmt);
        vfprintf(stderr, fmt, argp);
        va_end(argp);
    }
}
