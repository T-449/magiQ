/*
C wrapper around the liboqs XMSS stateful-signature API.

Exposes a handle-based interface so Python can drive XMSS keygen, sign and
verify through ctypes without managing the OQS_SIG_STFL_SECRET_KEY lifecycle.

Built by setup.sh:
    cc -shared -fPIC -O2 -o libxmss_helper.so xmss_helper.c -loqs
*/

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <oqs/oqs.h>

#define MAX_HANDLES 64

typedef struct {
    int                        active;
    char                       algo[64];
    OQS_SIG_STFL              *sig;
    OQS_SIG_STFL_SECRET_KEY   *sk;
    uint8_t                   *pk;
    size_t                     pk_len;
    size_t                     sig_len;
    /* serialised SK captured by the store callback */
    uint8_t                   *sk_buf;
    size_t                     sk_buf_len;
} XMSSHandle;

static XMSSHandle handles[MAX_HANDLES];
static int initialised = 0;

static OQS_STATUS store_cb(uint8_t *key_buf, size_t key_len, void *ctx) {
    XMSSHandle *h = (XMSSHandle *)ctx;
    if (h->sk_buf) { free(h->sk_buf); h->sk_buf = NULL; }
    h->sk_buf = malloc(key_len);
    if (!h->sk_buf) return OQS_ERROR;
    memcpy(h->sk_buf, key_buf, key_len);
    h->sk_buf_len = key_len;
    return OQS_SUCCESS;
}

static OQS_STATUS dummy_lock(void *m)   { (void)m; return OQS_SUCCESS; }
static OQS_STATUS dummy_unlock(void *m) { (void)m; return OQS_SUCCESS; }

int xmss_init(void) {
    if (!initialised) {
        memset(handles, 0, sizeof(handles));
        initialised = 1;
    }
    return 0;
}

size_t xmss_pk_length(const char *algo) {
    OQS_SIG_STFL *s = OQS_SIG_STFL_new(algo);
    if (!s) return 0;
    size_t len = s->length_public_key;
    OQS_SIG_STFL_free(s);
    return len;
}

size_t xmss_sig_length(const char *algo) {
    OQS_SIG_STFL *s = OQS_SIG_STFL_new(algo);
    if (!s) return 0;
    size_t len = s->length_signature;
    OQS_SIG_STFL_free(s);
    return len;
}

int xmss_keygen(const char *algo) {
    xmss_init();

    int idx = -1;
    for (int i = 0; i < MAX_HANDLES; i++) {
        if (!handles[i].active) { idx = i; break; }
    }
    if (idx < 0) {
        fprintf(stderr, "[xmss_helper] no free handles\n");
        return -1;
    }

    XMSSHandle *h = &handles[idx];
    memset(h, 0, sizeof(XMSSHandle));
    strncpy(h->algo, algo, sizeof(h->algo) - 1);

    h->sig = OQS_SIG_STFL_new(algo);
    if (!h->sig) {
        fprintf(stderr, "[xmss_helper] algorithm '%s' not available\n", algo);
        return -1;
    }
    h->pk_len  = h->sig->length_public_key;
    h->sig_len = h->sig->length_signature;

    h->pk = malloc(h->pk_len);
    if (!h->pk) goto fail;

    h->sk = OQS_SIG_STFL_SECRET_KEY_new(algo);
    if (!h->sk) goto fail;

    /* Set callbacks BEFORE keypair generation */
    OQS_SIG_STFL_SECRET_KEY_SET_store_cb(h->sk, store_cb, (void *)h);
    OQS_SIG_STFL_SECRET_KEY_SET_lock(h->sk, dummy_lock);
    OQS_SIG_STFL_SECRET_KEY_SET_unlock(h->sk, dummy_unlock);

    fprintf(stderr, "[xmss_helper] keygen '%s' starting (handle %d) ...\n", algo, idx);
    fflush(stderr);

    if (OQS_SIG_STFL_keypair(h->sig, h->pk, h->sk) != OQS_SUCCESS) {
        fprintf(stderr, "[xmss_helper] keypair generation failed\n");
        goto fail;
    }

    fprintf(stderr, "[xmss_helper] keygen done (handle %d, pk=%zu bytes)\n",
            idx, h->pk_len);

    /* If store_cb did not fire during keygen, serialise the secret key
       explicitly through the function pointer on the key struct. */
    if (!h->sk_buf || h->sk_buf_len == 0) {
        fprintf(stderr, "[xmss_helper] store_cb did not fire, "
                "trying explicit serialize ...\n");
        if (h->sk->serialize_key) {
            uint8_t *buf = NULL;
            size_t   len = 0;
            OQS_STATUS rc = h->sk->serialize_key(&buf, &len, h->sk);
            if (rc == OQS_SUCCESS && buf && len > 0) {
                h->sk_buf     = buf;
                h->sk_buf_len = len;
                fprintf(stderr, "[xmss_helper] explicit serialize OK "
                        "(%zu bytes)\n", len);
            } else {
                fprintf(stderr, "[xmss_helper] WARNING: serialize_key "
                        "failed, export_sk will not work\n");
                if (buf) free(buf);
            }
        } else {
            fprintf(stderr, "[xmss_helper] WARNING: no serialize_key "
                    "function, export_sk will not work\n");
        }
    }

    h->active = 1;
    return idx;

fail:
    if (h->pk)  { free(h->pk);  h->pk  = NULL; }
    if (h->sk)  { OQS_SIG_STFL_SECRET_KEY_free(h->sk); h->sk = NULL; }
    if (h->sig) { OQS_SIG_STFL_free(h->sig); h->sig = NULL; }
    return -1;
}

int xmss_get_pk(int handle, uint8_t *pk_out, size_t *pk_len_out) {
    if (handle < 0 || handle >= MAX_HANDLES || !handles[handle].active) return -1;
    XMSSHandle *h = &handles[handle];
    memcpy(pk_out, h->pk, h->pk_len);
    *pk_len_out = h->pk_len;
    return 0;
}

int xmss_sign(int handle,
              const uint8_t *msg, size_t msg_len,
              uint8_t *sig_out, size_t *sig_len_out) {
    if (handle < 0 || handle >= MAX_HANDLES || !handles[handle].active) return -1;
    XMSSHandle *h = &handles[handle];

    if (OQS_SIG_STFL_sign(h->sig, sig_out, sig_len_out,
                           msg, msg_len, h->sk) != OQS_SUCCESS) {
        fprintf(stderr, "[xmss_helper] sign failed (handle %d)\n", handle);
        return -1;
    }
    return 0;
}

int xmss_verify(const char *algo,
                const uint8_t *msg, size_t msg_len,
                const uint8_t *sig, size_t sig_len,
                const uint8_t *pk, size_t pk_len) {
    (void)pk_len;
    OQS_SIG_STFL *s = OQS_SIG_STFL_new(algo);
    if (!s) return -1;
    OQS_STATUS rc = OQS_SIG_STFL_verify(s, msg, msg_len, sig, sig_len, pk);
    OQS_SIG_STFL_free(s);
    return (rc == OQS_SUCCESS) ? 0 : -1;
}


void xmss_free_handle(int handle) {
    if (handle < 0 || handle >= MAX_HANDLES || !handles[handle].active) return;
    XMSSHandle *h = &handles[handle];
    if (h->pk)      free(h->pk);
    if (h->sk_buf)  free(h->sk_buf);
    if (h->sk)      OQS_SIG_STFL_SECRET_KEY_free(h->sk);
    if (h->sig)     OQS_SIG_STFL_free(h->sig);
    memset(h, 0, sizeof(XMSSHandle));
}

void xmss_cleanup(void) {
    for (int i = 0; i < MAX_HANDLES; i++) {
        if (handles[i].active) xmss_free_handle(i);
    }
    initialised = 0;
}