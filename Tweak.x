/*
 * lockdown — JSC Security Hardening Tweak for WebContent Process
 *
 * Hardens JavaScriptCore against exploit primitives (addrof/fakeobj,
 * JIT type confusion, GC UAF) by enforcing security-relevant JSC
 * Options and runtime state before the first VM is created.
 *
 * Three enforcement layers:
 *   1. Environment variables (JSC_*) — set before JSC reads them
 *   2. Hook Options::initialize() — programmatic setOption() after init
 *   3. Hook JSGlobalObject::init() — force haveABadTime() at runtime
 *
 * Security Levels (plist or default):
 *   0 — Disabled
 *   1 — Balanced: GC hardened, DoubleShape eliminated
 *   2 — Strict:   + DFG disabled, FTL disabled, generational GC disabled
 *   3 — Maximum:  + all JIT disabled, IC disabled
 */

#import <Foundation/Foundation.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <sys/time.h>
#include <mach-o/dyld.h>
#include <substrate.h>
#include <roothide.h>

// ============================================================
// Configuration
// ============================================================

static int g_WKWebView_level = 2;
static int g_WebContent_level = 1;

// ============================================================
// Logging (file-based; WebContent has no usable stdout/stderr)
// ============================================================

#if DEBUG
static void _log_write(const char *msg) {
    int fd = open(jbroot("/var/tmp/lockdown.log"),
                  O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) return;
    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm tm;
    localtime_r(&tv.tv_sec, &tm);
    char ts[64];
    int n = snprintf(ts, sizeof(ts), "%04d-%02d-%02d %02d:%02d:%02d.%03d ",
                     tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday,
                     tm.tm_hour, tm.tm_min, tm.tm_sec,
                     (int)(tv.tv_usec / 1000));
    write(fd, ts, n);
    write(fd, msg, strlen(msg));
    write(fd, "\n", 1);
    close(fd);
}
#define LOG(fmt, ...) do { \
    char _b[512]; \
    snprintf(_b, sizeof(_b), "[lockdown] " fmt, ##__VA_ARGS__); \
    _log_write(_b); \
} while (0)
#else
#define LOG(...) ((void)0)
#endif

// ============================================================
// Unified options table (single source of truth)
// ============================================================
// Each entry is {name, value, min_level}.
// Phase 1 sets env var  "JSC_<name>" = "<value>"
// Phase 2 calls setOption("<name>=<value>")
//
// NOTE: some options (alwaysHaveABadTime, ...) doesn't
// exist on old JSC — they are NOT in this table. DoubleShape elimination
// is achieved via direct haveABadTime() hook in Phase 3.

typedef struct { const char *name; const char *value; int min_level; } opt_entry;

static const opt_entry kOptions[] = {
    // Level 1: core hardening
	// { "alwaysHaveABadTime", "true",  1 },  // eliminate DoubleShape → no addrof/fakeobj
    { "forceGCSlowPaths",  "true",  1 },   // GC slow path → more safety checks
    { "useConcurrentGC",   "false", 1 },   // no GC races (CVE-2025-43529)
    // useAccessInlining = false
    // usePolymorphicAccessInlining = false
    // forcePolyProto = true
    // useArrayAllocationProfiling = false
    // Level 2: disable JIT speculation
    { "useDFGJIT",         "false", 2 },   // no speculative opt (CVE-2025-31277)
    { "useFTLJIT",         "false", 2 },   // disable most aggressive JIT tier
    { "useGenerationalGC", "false", 2 },   // simplify GC
    // Level 3: full JIT lockdown
    { "useLLInt",          "true",  3 },
    { "useLLIntICs",       "false", 3 },    // no interpreter inline caches
    { "useBaselineJIT",    "false", 3 },
    { "useBBQJIT",         "false", 3 },
    { "useOMGJIT",         "false", 3 },
    { "useDOMJIT",         "false", 3 },
    { "useRegExpJIT",      "false", 3 },
    { "useJITCage",        "false", 3 },
    { "useConcurrentJIT",  "false", 3 },
    { NULL, NULL, 0 }
};

// ============================================================
// Phase 1: Set JSC_* environment variables
// ============================================================

static void setJSCEnvVars(void) {
    char envname[64];
    for (const opt_entry *o = kOptions; o->name; o++) {
        if (o->min_level > g_WebContent_level) continue;
        snprintf(envname, sizeof(envname), "JSC_%s", o->name);
        setenv(envname, o->value, 1);
    }
	LOG("JSC_* env vars set");
}

// ============================================================
// Phase 2: Hook Options::initialize()
// ============================================================

static bool (*JSC_Options_setOption1)(const char *) = NULL;
static bool (*JSC_Options_setOption2)(const char *, bool) = NULL;
static void (*JSC_Options_notifyOptionsChanged)(void) = NULL;

static bool JSC_Options_setOption(const char *arg) {
	if (JSC_Options_setOption2)
		return JSC_Options_setOption2(arg, false);
	else if (JSC_Options_setOption1)
		return JSC_Options_setOption1(arg);
	else
		return false;
}

static void applyOptions(const char *tag) {
    char buf[128];
    for (const opt_entry *o = kOptions; o->name; o++) {
        if (o->min_level > g_WebContent_level) continue;
        snprintf(buf, sizeof(buf), "%s=%s", o->name, o->value);
        bool ok = JSC_Options_setOption(buf);
        LOG("  %s setOption(\"%s\") -> %s", tag, buf, ok ? "OK" : "FAIL");
    }
}

static void (*orig_JSC_Options_initialize)(void) = NULL;
static void hookd_JSC_Options_initialize(void) {

    orig_JSC_Options_initialize();
    LOG("Options::initialize() returned (level %d)", g_WebContent_level);

	if (g_WebContent_level <= 0) return;

    // Post-init: reinforce via setOption (env vars already applied by init)
    applyOptions("post-init");
	
    if (JSC_Options_notifyOptionsChanged) 
		JSC_Options_notifyOptionsChanged();
}

// ============================================================
// Phase 3: Hook JSGlobalObject::init() → haveABadTime()
// ============================================================
// alwaysHaveABadTime doesn't exist in old JSC. We call
// haveABadTime(VM&) directly after each JSGlobalObject::init()
// to eliminate DoubleShape → blocks addrof/fakeobj primitives.
// C++ ABI (ARM64): this=x0, vm=x1

static void (*orig_JSC_JSGlobalObject_init)(void *this, void *vm) = NULL;
static void (*JSC_JSGlobalObject_haveABadTime)(void *this, void *vm) = NULL;

static void hooked_JSC_JSGlobalObject_init(void *this, void *vm) {
    orig_JSC_JSGlobalObject_init(this, vm);
    if (JSC_JSGlobalObject_haveABadTime && g_WebContent_level >= 1) {
        JSC_JSGlobalObject_haveABadTime(this, vm);
		static int g_haveBadTime_count = 0;
        if (++g_haveBadTime_count <= 5)
            LOG("haveABadTime() on globalObj=%p (#%d)", this, g_haveBadTime_count);
    }
}

#include <xpc/xpc.h>

%group RootHideBootstrap

//new WebKit
%hookf(void, xpc_connection_send_message_with_reply, xpc_connection_t connection, xpc_object_t message, dispatch_queue_t replyq, xpc_handler_t handler)
{
    // const char* desc = NULL;
    // NSLog(@"[lockdown] msg: %s", (desc=xpc_copy_description(message)));
    // if(desc) free((void*)desc);

    const char* name = xpc_dictionary_get_string(message, "message-name");
    if (name && strcmp(name, "bootstrap")==0)
    {
        const char* service = xpc_dictionary_get_string(message, "service-name");
        NSLog(@"[lockdown] Intercepted bootstrap message to %s", service);
        if(service && strcmp(service, "com.apple.WebKit.WebContent")==0)
        {
            xpc_object_t containerEnvVars = xpc_dictionary_get_value(message, "ContainerEnvironmentVariables");
            if (containerEnvVars) {
                NSLog(@"[lockdown] Original ContainerEnvironmentVariables: %p", containerEnvVars);

                char envname[64];
                for (const opt_entry *o = kOptions; o->name; o++) {
                    if (o->min_level > g_WKWebView_level) continue;
                    snprintf(envname, sizeof(envname), "JSC_%s", o->name);
                    xpc_dictionary_set_string(containerEnvVars, envname, o->value);
                }

                const char* desc = NULL;
                NSLog(@"[lockdown] Modified ContainerEnvironmentVariables: %s", (desc=xpc_copy_description(containerEnvVars)));
                if(desc) free((void*)desc);
            }
        }
    }
    %orig;
}

//old WebKit
%hookf(void, xpc_connection_set_bootstrap, xpc_connection_t connection, xpc_object_t message)
{
    xpc_object_t containerEnvVars = xpc_dictionary_get_value(message, "ContainerEnvironmentVariables");
    if (containerEnvVars)
    {
        const char* desc = NULL;
        NSLog(@"[lockdown] Original ContainerEnvironmentVariables: %s", (desc=xpc_copy_description(containerEnvVars)));
        if(desc) free((void*)desc);
        
        char envname[64];
        for (const opt_entry *o = kOptions; o->name; o++) {
            if (o->min_level > g_WKWebView_level) continue;
            snprintf(envname, sizeof(envname), "JSC_%s", o->name);
            xpc_dictionary_set_string(containerEnvVars, envname, o->value);
        }

        desc = NULL;
        NSLog(@"[lockdown] Modified ContainerEnvironmentVariables: %s", (desc=xpc_copy_description(containerEnvVars)));
        if(desc) free((void*)desc);
    }

    return %orig;
}

%end

//Bootstrap global support
__attribute__ ((visibility ("default"))) const char** webcontent_environs()
{
    int maxcount = sizeof(kOptions)/sizeof(kOptions[0]) + 1;
    const char** envs = calloc(maxcount, sizeof(char*));
    int i = 0;
    for (const opt_entry *o = kOptions; o->name; o++) {
        if (o->min_level > g_WKWebView_level) continue;
        static char buf[128];
        snprintf(buf, sizeof(buf), "JSC_%s=%s", o->name, o->value);
        envs[i++] = strdup(buf);
    }
    return envs;
}

// ============================================================
// Constructor
// ============================================================

/*
libhooker's MSFindSymbol doesn't sign function pointers at all, 
while rootless/ellekit's MSFindSymbol signs only all exported symbols(even data pointers). 
the new roothide/ellekit implements signing only all code pointers (whether exported or private).
this helper function is compatible with all of these.
*/
void* FindAndSignFunction(MSImageRef image, const char *symbol) {
	void *sym = MSFindSymbol(image, symbol);
	if (!sym) {
		LOG("Symbol not found: %s", symbol);
		return NULL;
	}
	return ptrauth_sign_unauthenticated(ptrauth_strip(sym, ptrauth_key_function_pointer), ptrauth_key_function_pointer, 0);
}

%ctor {

    char executablePath[PATH_MAX]={0};
    uint32_t size = sizeof(executablePath);
    _NSGetExecutablePath(executablePath, &size);
    
    if(strcmp(basename(executablePath), "xpcproxy") == 0)
    {
        return;
    }

    if(access(jbroot("/.thebootstrapped"), F_OK) == 0)
    {
        NSLog(@"Starting in Bootstrap - level %d", g_WKWebView_level);
        %init(RootHideBootstrap);
        LOG("Init complete");
        return;
    }

    if(strcmp(basename(executablePath), "com.apple.WebKit.WebContent") != 0)
    {
        return;
    }

    if (g_WebContent_level <= 0) { LOG("Disabled (level 0)"); return; }
    LOG("Starting — level %d", g_WebContent_level);

    // Phase 1: env vars (read by Options::initialize)
    setJSCEnvVars();

    MSImageRef JavaScriptCore = MSGetImageByName("/System/Library/Frameworks/JavaScriptCore.framework/JavaScriptCore");
    if(!JavaScriptCore) {
        LOG("JavaScriptCore framework not found");
        abort();
    }

    // Phase 2: hook Options::initialize()
    JSC_Options_setOption1 = FindAndSignFunction(JavaScriptCore, "__ZN3JSC7Options9setOptionEPKc"); // ios15.1
    JSC_Options_setOption2 = FindAndSignFunction(JavaScriptCore, "__ZN3JSC7Options9setOptionEPKcb"); // ios16.4
    JSC_Options_notifyOptionsChanged = FindAndSignFunction(JavaScriptCore, "__ZN3JSC7Options20notifyOptionsChangedEv"); // ios16.4
    if(!JSC_Options_setOption1 && !JSC_Options_setOption2) {
        abort();
    }
    void* JSC_Options_initialize = FindAndSignFunction(JavaScriptCore, "__ZN3JSC7Options10initializeEv");
    if (JSC_Options_initialize) {
        MSHookFunction(JSC_Options_initialize, (void *)hookd_JSC_Options_initialize, (void **)&orig_JSC_Options_initialize);
        LOG("Hooked Options::initialize()");
    } else {
        LOG("Options::initialize() not found; env-vars-only fallback");
        abort();
    }

    // Phase 3: hook JSGlobalObject::init → haveABadTime
    void* JSC_JSGlobalObject_init = FindAndSignFunction(JavaScriptCore, "__ZN3JSC14JSGlobalObject4initERNS_2VME");
    JSC_JSGlobalObject_haveABadTime = FindAndSignFunction(JavaScriptCore, "__ZN3JSC14JSGlobalObject12haveABadTimeERNS_2VME");
    LOG("JSC_JSGlobalObject_haveABadTime = %p", JSC_JSGlobalObject_haveABadTime);
    if (JSC_JSGlobalObject_init && JSC_JSGlobalObject_haveABadTime) {
        MSHookFunction(JSC_JSGlobalObject_init, (void *)hooked_JSC_JSGlobalObject_init, (void **)&orig_JSC_JSGlobalObject_init);
        LOG("Hooked JSGlobalObject::init() -> haveABadTime()");
    } else {
        abort();
    }

    LOG("Init complete");
}
