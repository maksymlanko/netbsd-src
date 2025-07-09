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

// TODO: move to sys/sys/ns.c and rename get_ns()
struct uts_ns *
get_uts(void)
{
    kauth_cred_t temp_cred = kauth_cred_get();
    struct uts_ns *ns = kauth_cred_getdata(temp_cred, uts_key);

    if (ns) {
        return ns;
    }

    return &new_ns;
}

void
unshare_uts(void)
{
    struct uts_ns *unshared_ns = kmem_zalloc(sizeof(struct uts_ns), KM_SLEEP);

    kauth_cred_t prev_cred = kauth_cred_get();
    printf("UNSHARE_SYSCALL: AFTER_GET cred: %p cr_refcnt: %u\n",
           prev_cred, kauth_cred_getrefcnt(prev_cred));

    // certifies that cred_t has 1 reference to get unshare lifecycle correctly
    kauth_cred_t new_cred = kauth_cred_copy(prev_cred);
    printf("UNSHARE_SYSCALL: NEW_CRED cred: %p cr_refcnt: %u\n",
           new_cred, kauth_cred_getrefcnt(new_cred));

    struct uts_ns *prev_ns = kauth_cred_getdata(prev_cred, uts_key);
    if (!prev_ns) {
        prev_ns = &new_ns;
    }

    // allocate new memory for unshared ns
    unshared_ns->hostname = kmem_alloc(MAXHOSTNAMELEN, KM_SLEEP);
    unshared_ns->domainname = kmem_alloc(MAXHOSTNAMELEN, KM_SLEEP);
    unshared_ns->hostnamelen = kmem_alloc(sizeof(int), KM_SLEEP);
    unshared_ns->domainnamelen = kmem_alloc(sizeof(int), KM_SLEEP);

    // copy values of old ns into unshared ns
    strlcpy(unshared_ns->hostname, prev_ns->hostname, MAXHOSTNAMELEN);
    strlcpy(unshared_ns->domainname, prev_ns->domainname, MAXHOSTNAMELEN);
    *unshared_ns->hostnamelen = *prev_ns->hostnamelen;
    *unshared_ns->domainnamelen = *prev_ns->domainnamelen;
    unshared_ns->ns_refcnt = 1;

    // modify cred_t of the process
    proc_crmod_enter();
    proc_crmod_leave(new_cred, NULL, false);

    // decrement parent's ns_refcnt to cancel KAUTH_CRED_COPY increasing it
    prev_ns->ns_refcnt--;

    // save new ns into kauth private data
    kauth_cred_setdata(new_cred, uts_key, unshared_ns);
    printf("UNSHARE_SYSCALL: new AFTER cred: %p ns_refcnt: %u\n",
           new_cred, unshared_ns->ns_refcnt);
    printf("UNSHARE_SYSCALL: old AFTER cred: %p ns_refcnt: %u\n",
           prev_cred, prev_ns->ns_refcnt);
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
    printf("Entering init\n");
}

void
secmodel_uts_start(void)
{
    l_cred = kauth_listen_scope(KAUTH_SCOPE_CRED,
        secmodel_uts_cred_cb, NULL);

    printf("REGISTERED KEY!!!\n\n\n");
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
                    printf("secmodel_uts_modcmd::init: "
                    "secmodel_register returned %d\n", error);

                error = kauth_register_key(uts_sm, &uts_key);

                if (error != 0)
                    printf("secmodel_uts_modcmd::init: "
                    "kauth_register_key returned %d\n", error);

                break;

        case MODULE_CMD_FINI:
                error = secmodel_deregister(uts_sm);
                if (error != 0)
                        printf("secmodel_uts_modcmd::fini: "
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
        printf("CRED_INIT with cred: %p\n", cred);
        break;

    case KAUTH_CRED_COPY:
        {
            printf("CRED_COPY\n");
            // arg0 = destination cred, cred = source cred
            struct uts_ns *source_ns = kauth_cred_getdata(cred, uts_key);

            if (source_ns) {
                printf("COPY before ++ and setdata: source cred=%p dest cred=%p ns_refcnt=%u\n",
                       cred, arg0, source_ns->ns_refcnt);
                source_ns->ns_refcnt++;
                kauth_cred_setdata((kauth_cred_t)arg0, uts_key, source_ns);
                printf("COPY: source cred=%p dest cred=%p ns_refcnt=%u\n",
                       cred, arg0, source_ns->ns_refcnt);

                struct uts_ns *notupdated = kauth_cred_getdata(cred, uts_key);
                printf("COPY: notupdated cred=%p dest cred=%p ns_refcnt=%u\n",
                       cred, arg0, notupdated->ns_refcnt);

            }
        }
        break;

    case KAUTH_CRED_FORK:
        // arg0 = parent proc, arg1 = child proc
        printf("CRED_FORK\n");
        if (arg0 && arg1) {
            struct proc *parent = (struct proc *) arg0;
            child = (struct proc *) arg1;

            parent_cred = parent->p_cred;
            struct uts_ns *parent_ns = kauth_cred_getdata(parent_cred, uts_key);

            if (parent_ns) {
                // TODO: should we fork cred_t like secmodel_sandbox?
                // parent_ns->ns_refcnt++;
                kauth_cred_setdata(child->p_cred, uts_key, parent_ns);
                printf("FORK: child cred: %p, cr_refcnt: %u ns_refcnt: %u\n",
                       child->p_cred, kauth_cred_getrefcnt(child->p_cred),
                       parent_ns->ns_refcnt);
            } else {
                printf("FORK: child cred: %p, cr_refcnt: %u (using global ns)\n",
                       child->p_cred, kauth_cred_getrefcnt(child->p_cred));
            }
        }
        break;

    case KAUTH_CRED_FREE:
        {
            printf("FREE of cred: %p\n", cred);
            struct uts_ns *ns = kauth_cred_getdata(cred, uts_key);

            if (ns) {
                ns->ns_refcnt--;
                printf("FREE: cred=%p, ns_refcnt=%u\n", cred, ns->ns_refcnt);

                if (ns->ns_refcnt == 0) {
                    printf("CLEANUP: freeing namespace %p\n", ns);
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