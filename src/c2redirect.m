// ==============================================================================
// XoaInfo C2 Redirect Tweak for RootHide / Dopamine
// Intercepts and redirects all C2 network communications to a researcher-controlled server.
// Hooks: Network.framework, libSystem DNS, Security.framework TLS, and Foundation ObjC.
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

// C library declarations
extern size_t  strlen(const char *s);
extern int     strcmp(const char *s1, const char *s2);
extern int     strncmp(const char *s1, const char *s2, size_t n);
extern char   *strstr(const char *haystack, const char *needle);
extern char   *strcpy(char *dest, const char *src);
extern char   *strncpy(char *dest, const char *src, size_t n);
extern int     snprintf(char *str, size_t size, const char *fmt, ...);
extern ssize_t write(int fd, const void *buf, size_t count);
extern int     open(const char *pathname, int flags, ...);
extern int     close(int fd);
extern void   *dlsym(void *handle, const char *symbol);
extern void   *dlopen(const char *filename, int flag);

// ObjC runtime types & functions
typedef struct objc_class  *Class;
typedef struct objc_object { Class isa; } *id;
typedef struct objc_selector *SEL;
typedef id (*IMP)(id, SEL, ...);
typedef struct objc_method_t *Method;

extern Class  objc_getClass(const char *name);
extern SEL    sel_registerName(const char *str);
extern Method class_getInstanceMethod(Class cls, SEL name);
extern Method class_getClassMethod(Class cls, SEL name);
extern IMP    method_getImplementation(Method m);
extern void   method_setImplementation(Method m, IMP imp);
extern id     objc_msgSend(id self, SEL op, ...);
extern void   NSLog(id format, ...);

// Target configuration
static const char REDIRECT_HOST[] = "xf.meomeo.social";

// Safe logging
static void c2log_raw(const char *msg) {
    if (!msg) return;
    // 1. write to stderr (fd 2)
    size_t len = strlen(msg);
    write(2, msg, len);
    write(2, "\n", 1);

    // 2. write to file in /tmp/c2redirect.log
    int fd = open("/tmp/c2redirect.log", 0x0001 | 0x0008 | 0x0200, 0666); // O_WRONLY | O_APPEND | O_CREAT
    if (fd >= 0) {
        write(fd, msg, len);
        write(fd, "\n", 1);
        close(fd);
    }

    // 3. NSLog
    Class nss = objc_getClass("NSString");
    if (nss) {
        id str = ((id(*)(id,SEL,const char*))objc_msgSend)(
            (id)nss, sel_registerName("stringWithUTF8String:"), msg);
        if (str) {
            NSLog(str);
        }
    }
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

static int is_xoainfo(const char *s) {
    if (!s) return 0;
    if (strstr(s, "xoainfo") || strstr(s, "XoaInfo") || strstr(s, "XOAINFO")) {
        return 1;
    }
    return 0;
}

// ==============================================================================
// 1. Network.framework Interception
// ==============================================================================
extern void *nw_endpoint_create_host(const char *hostname, const char *port);
extern void  sec_protocol_options_set_tls_server_name(void *options, const char *server_name);
extern void  sec_protocol_options_set_verify_block(void *options, void *verify_block, void *verify_queue);
extern void *sec_trust_copy_ref(void *trust);

static void *my_nw_endpoint_create_host(const char *hostname, const char *port) {
    if (is_xoainfo(hostname)) {
        c2log("nw_endpoint_create_host REDIRECT", hostname, REDIRECT_HOST);
        hostname = REDIRECT_HOST;
    } else if (hostname) {
        c2log("nw_endpoint_create_host PASS", hostname, port);
    }
    return nw_endpoint_create_host(hostname, port);
}

static void my_sec_protocol_options_set_tls_server_name(void *options, const char *server_name) {
    if (is_xoainfo(server_name)) {
        c2log("sec_protocol_options_set_tls_server_name REDIRECT", server_name, REDIRECT_HOST);
        server_name = REDIRECT_HOST;
    }
    sec_protocol_options_set_tls_server_name(options, server_name);
}

// Custom verify block to bypass SSL pinning in Network.framework
typedef void (^sec_protocol_verify_complete_t)(int verified);
typedef void (^sec_protocol_verify_t)(void *metadata, void *trust, sec_protocol_verify_complete_t complete);

static void my_sec_protocol_options_set_verify_block(void *options, void *block, void *queue) {
    c2log("sec_protocol_options_set_verify_block HOOKED (bypassing SSL pinning)", NULL, NULL);
    sec_protocol_verify_t bypass_block = ^(void *metadata, void *trust, sec_protocol_verify_complete_t complete) {
        c2log("TLS Verification Block called -> forced verify SUCCESS (1)", NULL, NULL);
        if (complete) {
            complete(1); // 1 = verified
        }
    };
    sec_protocol_options_set_verify_block(options, (void*)bypass_block, queue);
}

// ==============================================================================
// 2. libSystem DNS & Hostname Interception
// ==============================================================================
struct addrinfo;
extern int   getaddrinfo(const char *hostname, const char *servname, const struct addrinfo *hints, struct addrinfo **res);
extern void *gethostbyname(const char *name);

static int my_getaddrinfo(const char *hostname, const char *servname, const struct addrinfo *hints, struct addrinfo **res) {
    if (is_xoainfo(hostname)) {
        c2log("getaddrinfo REDIRECT", hostname, REDIRECT_HOST);
        hostname = REDIRECT_HOST;
    }
    return getaddrinfo(hostname, servname, hints, res);
}

static void *my_gethostbyname(const char *name) {
    if (is_xoainfo(name)) {
        c2log("gethostbyname REDIRECT", name, REDIRECT_HOST);
        name = REDIRECT_HOST;
    }
    return gethostbyname(name);
}

// ==============================================================================
// 3. Security.framework SSL Pinning Bypass
// ==============================================================================
extern int SecTrustEvaluateWithError(void *trust, void **error);

static int my_SecTrustEvaluateWithError(void *trust, void **error) {
    c2log("SecTrustEvaluateWithError called -> returned TRUE", NULL, NULL);
    if (error) *error = (void*)0;
    return 1; // Success
}

// ==============================================================================
// DYLD_INTERPOSE Macro
// ==============================================================================
#define DYLD_INTERPOSE(_repl, _orig) \
  __attribute__((used)) \
  static struct { const void *repl; const void *orig; } \
  _interpose_##_orig \
  __attribute__((section("__DATA,__interpose"))) = { \
      (const void *)(unsigned long)&_repl, \
      (const void *)(unsigned long)&_orig \
  };

DYLD_INTERPOSE(my_nw_endpoint_create_host, nw_endpoint_create_host);
DYLD_INTERPOSE(my_sec_protocol_options_set_tls_server_name, sec_protocol_options_set_tls_server_name);
DYLD_INTERPOSE(my_sec_protocol_options_set_verify_block, sec_protocol_options_set_verify_block);
DYLD_INTERPOSE(my_getaddrinfo, getaddrinfo);
DYLD_INTERPOSE(my_gethostbyname, gethostbyname);
DYLD_INTERPOSE(my_SecTrustEvaluateWithError, SecTrustEvaluateWithError);

// ==============================================================================
// 4. ObjC Foundation / NSURLRequest / NSURLSession Swizzles
// ==============================================================================
static id redirectURL(id url) {
    if (!url) return url;
    Class nsu = objc_getClass("NSURL");
    Class nss = objc_getClass("NSString");
    if (!nsu || !nss) return url;

    id urlStr = ((id(*)(id,SEL))objc_msgSend)(url, sel_registerName("absoluteString"));
    if (!urlStr) return url;

    id needle = ((id(*)(id,SEL,const char*))objc_msgSend)(
        (id)nss, sel_registerName("stringWithUTF8String:"), "xoainfo");
    int found = (int)(long)((id(*)(id,SEL,id))objc_msgSend)(
        urlStr, sel_registerName("containsString:"), needle);
    if (!found) return url;

    const char *orig_c = ((const char*(*)(id,SEL))objc_msgSend)(urlStr, sel_registerName("UTF8String"));
    c2log("ObjC NSURL Intercepted", orig_c, NULL);

    SEL replSel = sel_registerName("stringByReplacingOccurrencesOfString:withString:");
    id comStr   = ((id(*)(id,SEL,const char*))objc_msgSend)((id)nss, sel_registerName("stringWithUTF8String:"), "xoainfo.com");
    id netStr   = ((id(*)(id,SEL,const char*))objc_msgSend)((id)nss, sel_registerName("stringWithUTF8String:"), "xoainfo.net");
    id redirStr = ((id(*)(id,SEL,const char*))objc_msgSend)((id)nss, sel_registerName("stringWithUTF8String:"), REDIRECT_HOST);

    id newStr = ((id(*)(id,SEL,id,id))objc_msgSend)(urlStr, replSel, comStr, redirStr);
    newStr    = ((id(*)(id,SEL,id,id))objc_msgSend)(newStr,  replSel, netStr, redirStr);

    id newURL = ((id(*)(id,SEL,id))objc_msgSend)((id)nsu, sel_registerName("URLWithString:"), newStr);
    const char *new_c = ((const char*(*)(id,SEL))objc_msgSend)(newStr, sel_registerName("UTF8String"));
    c2log("ObjC NSURL Redirected", orig_c, new_c);

    return newURL ? newURL : url;
}

static void redirectRequest(id req) {
    if (!req) return;
    id url = ((id(*)(id,SEL))objc_msgSend)(req, sel_registerName("URL"));
    id newURL = redirectURL(url);
    if (newURL && newURL != url) {
        ((void(*)(id,SEL,id))objc_msgSend)(req, sel_registerName("setURL:"), newURL);
    }
}

// Saved IMPs
static id (*orig_req_initWithURL)(id, SEL, id);
static id (*orig_req_initWithURLFull)(id, SEL, id, long, double);
static id (*orig_mreq_initWithURL)(id, SEL, id);
static id (*orig_mreq_initWithURLFull)(id, SEL, id, long, double);
static void (*orig_mreq_setURL)(id, SEL, id);
static id (*orig_sess_dataTaskWithURL)(id, SEL, id);
static id (*orig_sess_dataTaskWithURLCompletion)(id, SEL, id, id);
static id (*orig_sess_dataTaskWithRequest)(id, SEL, id);
static id (*orig_sess_dataTaskWithRequestCompletion)(id, SEL, id, id);

static id hook_req_initWithURL(id self, SEL _cmd, id url) {
    return orig_req_initWithURL(self, _cmd, redirectURL(url));
}

static id hook_req_initWithURLFull(id self, SEL _cmd, id url, long policy, double timeout) {
    return orig_req_initWithURLFull(self, _cmd, redirectURL(url), policy, timeout);
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
    redirectRequest(req);
    return orig_sess_dataTaskWithRequest(self, _cmd, req);
}

static id hook_sess_dataTaskWithRequestCompletion(id self, SEL _cmd, id req, id block) {
    redirectRequest(req);
    return orig_sess_dataTaskWithRequestCompletion(self, _cmd, req, block);
}

static void hookMethod(Class cls, const char *selName, IMP newIMP, IMP *origIMP) {
    if (!cls) return;
    SEL sel = sel_registerName(selName);
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return;
    *origIMP = method_getImplementation(m);
    method_setImplementation(m, newIMP);
}

// ==============================================================================
// 5. Dynamic Substrate / ElleKit Function Hook Fallback
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
            static void *orig_nw_host = (void*)0;
            msHook(fn_nw_host, (void*)my_nw_endpoint_create_host, &orig_nw_host);
        }
        void *fn_tls_sni = dlsym((void*)-2, "sec_protocol_options_set_tls_server_name");
        if (fn_tls_sni) {
            static void *orig_tls_sni = (void*)0;
            msHook(fn_tls_sni, (void*)my_sec_protocol_options_set_tls_server_name, &orig_tls_sni);
        }
        void *fn_tls_verify = dlsym((void*)-2, "sec_protocol_options_set_verify_block");
        if (fn_tls_verify) {
            static void *orig_tls_verify = (void*)0;
            msHook(fn_tls_verify, (void*)my_sec_protocol_options_set_verify_block, &orig_tls_verify);
        }
        void *fn_gai = dlsym((void*)-2, "getaddrinfo");
        if (fn_gai) {
            static void *orig_gai = (void*)0;
            msHook(fn_gai, (void*)my_getaddrinfo, &orig_gai);
        }
    }
}

// ==============================================================================
// 6. Constructor (Runs on injection)
// ==============================================================================
__attribute__((constructor))
static void C2RedirectInit(void) {
    c2log_raw("=================================================");
    c2log_raw("[C2Redirect] ACTIVE - Initializing hooks for RootHide");
    c2log("Redirect target", REDIRECT_HOST, NULL);
    c2log_raw("=================================================");

    // 1. Dynamic function hooks (ElleKit / Substrate)
    install_dynamic_c_hooks();

    // 2. Foundation ObjC Hooks
    Class reqCls  = objc_getClass("NSURLRequest");
    Class mreqCls = objc_getClass("NSMutableURLRequest");
    Class sessCls = objc_getClass("NSURLSession");

    if (reqCls) {
        hookMethod(reqCls, "initWithURL:", (IMP)hook_req_initWithURL, (IMP*)&orig_req_initWithURL);
        hookMethod(reqCls, "initWithURL:cachePolicy:timeoutInterval:", (IMP)hook_req_initWithURLFull, (IMP*)&orig_req_initWithURLFull);
    }
    if (mreqCls) {
        hookMethod(mreqCls, "initWithURL:", (IMP)hook_mreq_initWithURL, (IMP*)&orig_mreq_initWithURL);
        hookMethod(mreqCls, "initWithURL:cachePolicy:timeoutInterval:", (IMP)hook_mreq_initWithURLFull, (IMP*)&orig_mreq_initWithURLFull);
        hookMethod(mreqCls, "setURL:", (IMP)hook_mreq_setURL, (IMP*)&orig_mreq_setURL);
    }
    if (sessCls) {
        hookMethod(sessCls, "dataTaskWithURL:", (IMP)hook_sess_dataTaskWithURL, (IMP*)&orig_sess_dataTaskWithURL);
        hookMethod(sessCls, "dataTaskWithURL:completionHandler:", (IMP)hook_sess_dataTaskWithURLCompletion, (IMP*)&orig_sess_dataTaskWithURLCompletion);
        hookMethod(sessCls, "dataTaskWithRequest:", (IMP)hook_sess_dataTaskWithRequest, (IMP*)&orig_sess_dataTaskWithRequest);
        hookMethod(sessCls, "dataTaskWithRequest:completionHandler:", (IMP)hook_sess_dataTaskWithRequestCompletion, (IMP*)&orig_sess_dataTaskWithRequestCompletion);
    }

    c2log_raw("[C2Redirect] All hooks initialized successfully.");
}
