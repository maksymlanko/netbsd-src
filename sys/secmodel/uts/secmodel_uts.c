#include <secmodel/secmodel.h>
#include <sys/module.h>
#include <sys/kauth.h>
#include <sys/sysctl.h>

#if defined(_KERNEL_OPT)
#include "opt_ns.h"
#include "opt_ns_uts.h"
#endif

#if defined(NAMESPACES) && defined(UTS_NS)
#include <sys/uts.h>
#endif

#include <sys/malloc.h> // for unshare_uts
#include <sys/kmem.h>

MODULE(MODULE_CLASS_SECMODEL, secmodel_uts, NULL);

kauth_key_t uts_key; // key to get uts data

secmodel_t uts_sm; // description of uts secmodel

static struct sysctllog *sysctl_uts_log; // saves sysctl nodes information

// listener for credentials scope of secmodel_uts
static kauth_listener_t l_cred;

static int secmodel_uts_cred_cb(kauth_cred_t, kauth_action_t, void *,
    void *, void *, void *, void *);

void secmodel_uts_init(void);
void secmodel_uts_start(void);
void secmodel_uts_stop(void);
struct uts_ns *get_uts(void);
struct uts_ns *get_cred_uts(kauth_cred_t *);
void unshare_uts(void);

#define DBG_SECMODEL
#ifdef DBG_SECMODEL
    #define dbg(fmt, ...) do { printf(fmt, ##__VA_ARGS__); } while (0)
#else
    #define dbg(fmt, ...) do { } while (0)
#endif /* DBG_SECMODEL */


// TODO: move to sys/sys/ns.c and rename get_ns()
struct uts_ns *
get_uts(void)
{
    kauth_cred_t cred = kauth_cred_get();
    struct uts_ns *ns = kauth_cred_getdata(cred, uts_key);

    if (ns)
        return ns;

    return &new_ns;
}

void
unshare_uts(void)
{
    struct uts_ns *unshared_ns, *cur_ns;
    kauth_cred_t cur_cred, new_cred;

    // get credentials of current process
    cur_cred = kauth_cred_get();
    dbg("UNSHARE_SYSCALL: AFTER_GET cred: %p cr_refcnt: %u\n",
           cur_cred, kauth_cred_getrefcnt(cur_cred));

    // certifies that cred_t has 1 reference to get unshare lifecycle correctly
    new_cred = kauth_cred_copy(cur_cred);
    dbg("UNSHARE_SYSCALL: NEW_CRED cred: %p cr_refcnt: %u\n",
           new_cred, kauth_cred_getrefcnt(new_cred));

    // get uts namespace of current process
    cur_ns = get_uts();

    // allocate new memory for unshared ns
    unshared_ns                 = kmem_zalloc(sizeof(struct uts_ns), KM_SLEEP);
    unshared_ns->hostname       = kmem_zalloc(MAXHOSTNAMELEN, KM_SLEEP);
    unshared_ns->domainname     = kmem_zalloc(MAXHOSTNAMELEN, KM_SLEEP);
    unshared_ns->hostnamelen    = kmem_zalloc(sizeof(int), KM_SLEEP);
    unshared_ns->domainnamelen  = kmem_zalloc(sizeof(int), KM_SLEEP);

    // copy values of current ns into unshared ns
    strlcpy(unshared_ns->hostname, cur_ns->hostname, MAXHOSTNAMELEN);
    strlcpy(unshared_ns->domainname, cur_ns->domainname, MAXHOSTNAMELEN);
    *unshared_ns->hostnamelen = *cur_ns->hostnamelen;
    *unshared_ns->domainnamelen = *cur_ns->domainnamelen;
    // the unshared ns will start with a count of 1
    unshared_ns->ns_refcnt = 1;

    // modify cred_t of the current process
    proc_crmod_enter();
    // decrement current ns_refcnt to cancel KAUTH_CRED_COPY incrementing it
    cur_ns->ns_refcnt--;
    // TODO: check if setting to cur_cred makes leave automatic
    proc_crmod_leave(new_cred, NULL, false);

    // set unshared_ns as uts namespace of current process
    kauth_cred_setdata(new_cred, uts_key, unshared_ns);
    dbg("UNSHARE_SYSCALL: new AFTER cred: %p ns_refcnt: %u\n",
           new_cred, unshared_ns->ns_refcnt);
    dbg("UNSHARE_SYSCALL: old AFTER cred: %p ns_refcnt: %u\n",
           cur_cred, cur_ns->ns_refcnt);
}

static void
sysctl_security_uts_setup(struct sysctllog **clog)
{
        const struct sysctlnode *rnode;

        sysctl_createv(clog, 0, NULL, &rnode,
                       CTLFLAG_PERMANENT,
                       CTLTYPE_NODE, "security", NULL,
                       NULL, 0, NULL, 0,
                       CTL_CREATE, CTL_EOL);

        sysctl_createv(clog, 0, &rnode, &rnode,
                       CTLFLAG_PERMANENT,
                       CTLTYPE_NODE, "models", NULL,
                       NULL, 0, NULL, 0,
                       CTL_CREATE, CTL_EOL);

        sysctl_createv(clog, 0, &rnode, &rnode,
                       CTLFLAG_PERMANENT,
                       CTLTYPE_NODE, "uts",
                       SYSCTL_DESCR("uts security model"),
                       NULL, 0, NULL, 0,
                       CTL_CREATE, CTL_EOL);

        sysctl_createv(clog, 0, &rnode, NULL,
                       CTLFLAG_PERMANENT,
                       CTLTYPE_STRING, "name", NULL,
                       NULL, 0, __UNCONST("UTS security model"), 0,
                       CTL_CREATE, CTL_EOL);
}

void
secmodel_uts_init(void)
{
    dbg("Entering init\n");
}

void
secmodel_uts_start(void)
{
    l_cred = kauth_listen_scope(KAUTH_SCOPE_CRED,
        secmodel_uts_cred_cb, NULL);

    dbg("REGISTERED KEY!!!\n\n\n");
}

void
secmodel_uts_stop(void)
{
        kauth_unlisten_scope(l_cred);
        kauth_deregister_key(uts_key);
}

static int
secmodel_uts_modcmd(modcmd_t cmd, void *arg)
{
        int error = 0;

        switch (cmd) {
        case MODULE_CMD_INIT:
                secmodel_uts_init();
                secmodel_uts_start();
                sysctl_security_uts_setup(&sysctl_uts_log);

                error = secmodel_register(&uts_sm, "org.netbsd.secmodel.uts",
                    "NetBSD Security Model: UTS", NULL, NULL, NULL);

                if (error != 0)
                    dbg("secmodel_uts_modcmd::init: "
                    "secmodel_register returned %d\n", error);

                error = kauth_register_key(uts_sm, &uts_key);

                if (error != 0)
                    dbg("secmodel_uts_modcmd::init: "
                    "kauth_register_key returned %d\n", error);

                break;

        case MODULE_CMD_FINI:
                error = secmodel_deregister(uts_sm);
                if (error != 0)
                        dbg("secmodel_uts_modcmd::fini: "
                            "secmodel_deregister returned %d\n", error);

                sysctl_teardown(&sysctl_uts_log);
                secmodel_uts_stop();
                break;

        default:
                error = ENOTTY;
                break;
        }

        return error;
}

struct uts_ns *
get_cred_uts(kauth_cred_t *cred)
{
    struct uts_ns *parent_uts = kauth_cred_getdata(*cred, uts_key);

    if (parent_uts) {
        return parent_uts;
    }

    return &new_ns;
}

static int
secmodel_uts_cred_cb(kauth_cred_t cred, kauth_action_t action,
    void *cookie, void *arg0, void *arg1, void *arg2, void *arg3)
{
    kauth_cred_t parent_cred;
    struct proc *child;
    int result = KAUTH_RESULT_ALLOW;

    switch (action) {
    case KAUTH_CRED_INIT:
        dbg("CRED_INIT with cred: %p\n", cred);
        break;

    case KAUTH_CRED_COPY:
        {
            dbg("CRED_COPY\n");
            // arg0 = destination cred, cred = source cred
            struct uts_ns *source_ns = kauth_cred_getdata(cred, uts_key);

            if (source_ns) {
                dbg("COPY before ++ and setdata: source cred=%p dest cred=%p ns_refcnt=%u\n",
                       cred, arg0, source_ns->ns_refcnt);
                source_ns->ns_refcnt++;
                kauth_cred_setdata((kauth_cred_t)arg0, uts_key, source_ns);
                dbg("COPY: source cred=%p dest cred=%p ns_refcnt=%u\n",
                       cred, arg0, source_ns->ns_refcnt);

                struct uts_ns *notupdated = kauth_cred_getdata(cred, uts_key);
                dbg("COPY: notupdated cred=%p dest cred=%p ns_refcnt=%u\n",
                       cred, arg0, notupdated->ns_refcnt);

            }
        }
        break;

    case KAUTH_CRED_FORK:
        // arg0 = parent proc, arg1 = child proc
        dbg("CRED_FORK\n");
        if (arg0 && arg1) {
            struct proc *parent = (struct proc *) arg0;
            child = (struct proc *) arg1;

            parent_cred = parent->p_cred;
            struct uts_ns *parent_ns = kauth_cred_getdata(parent_cred, uts_key);

            if (parent_ns) {
                // TODO: should we fork cred_t like secmodel_sandbox?
                // parent_ns->ns_refcnt++;
                kauth_cred_setdata(child->p_cred, uts_key, parent_ns);
                dbg("FORK: child cred: %p, cr_refcnt: %u ns_refcnt: %u\n",
                       child->p_cred, kauth_cred_getrefcnt(child->p_cred),
                       parent_ns->ns_refcnt);
            } else {
                dbg("FORK: child cred: %p, cr_refcnt: %u (using global ns)\n",
                       child->p_cred, kauth_cred_getrefcnt(child->p_cred));
            }
        }
        break;

    case KAUTH_CRED_FREE:
        {
            dbg("FREE of cred: %p\n", cred);
            struct uts_ns *ns = kauth_cred_getdata(cred, uts_key);

            if (ns) {
                ns->ns_refcnt--;
                dbg("FREE: cred=%p, ns_refcnt=%u\n", cred, ns->ns_refcnt);

                if (ns->ns_refcnt == 0) {
                    dbg("CLEANUP: freeing namespace %p\n", ns);
                    if (ns->hostname) kmem_free(ns->hostname, MAXHOSTNAMELEN);
                    if (ns->domainname) kmem_free(ns->domainname, MAXHOSTNAMELEN);
                    if (ns->hostnamelen) kmem_free(ns->hostnamelen, sizeof(int));
                    if (ns->domainnamelen) kmem_free(ns->domainnamelen, sizeof(int));
                    kmem_free(ns, sizeof(struct uts_ns));
                }
            }
        }
        break;

    case KAUTH_CRED_CHROOT:
        // TODO: does this affect uts_ns in any way?
        break;
    }
    return result;
}