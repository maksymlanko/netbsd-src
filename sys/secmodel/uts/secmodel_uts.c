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

// remove system?
static kauth_listener_t l_system, l_cred;

static int secmodel_uts_system_cb(kauth_cred_t, kauth_action_t, void *,
    void *, void *, void *, void *);
static int secmodel_uts_cred_cb(kauth_cred_t, kauth_action_t, void *,
    void *, void *, void *, void *);

void secmodel_uts_init(void);
void secmodel_uts_start(void);
void secmodel_uts_stop(void);
struct uts_ns *get_uts(void);
void unshare_uts(void);

// TODO: move to sys/sys/ns.c and rename get_ns()
struct uts_ns *
get_uts(void)
{
    // return p->nsproxy->uts;

    kauth_cred_t temp_cred = kauth_cred_get();
    struct uts_ns *example = kauth_cred_getdata(temp_cred, uts_key);

    if (example) {
        // printf("get_uts got hostname = %s\n", example->hostname);
        return example;
    }
    // printf("Returning ns0\n");
    return &new_ns;
}

void
unshare_uts(void)
{
    // TODO: do we use 'malloc' in kernel?
    struct uts_ns *unshared_ns = kmem_zalloc(sizeof(struct uts_ns), KM_SLEEP);

    // get old ns before unshare()
    // TODO: simplify into helper function
    kauth_cred_t prev_cred = kauth_cred_get();
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

    // save new ns into kauth private data
    kauth_cred_setdata(prev_cred, uts_key, unshared_ns);
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
    l_system = kauth_listen_scope(KAUTH_SCOPE_SYSTEM,
        secmodel_uts_system_cb, NULL);
    l_cred = kauth_listen_scope(KAUTH_SCOPE_CRED,
        secmodel_uts_cred_cb, NULL);

    printf("REGISTERED KEY!!!\n\n\n");
}

void
secmodel_uts_stop(void)
{
        kauth_unlisten_scope(l_system);
        kauth_unlisten_scope(l_cred);
        kauth_deregister_key(uts_key);
}

static int
secmodel_uts_system_cb(kauth_cred_t cred, kauth_action_t action,
    void *cookie, void *arg0, void *arg1, void *arg2, void *arg3)
{
	// TODO: implement

	int result = KAUTH_RESULT_DEFER;
    // printf("DEFERING!!!\n\n\n");

    return result;
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

static int
secmodel_uts_cred_cb(kauth_cred_t cred, kauth_action_t action,
    void *cookie, void *arg0, void *arg1, void *arg2, void *arg3)
{
    int result = KAUTH_RESULT_ALLOW;
    switch (action) {
    case KAUTH_CRED_INIT:
        // printf("CRED_INIT\n");
        // kauth_cred_setdata(cred, uts_key, &new_ns);
        break;

    case KAUTH_CRED_COPY:
        // printf("CRED_COPY\n");
        break;

    case KAUTH_CRED_FORK:
        // printf("CRED_FORK\n");
        // arg0 = parent proc, arg1 = child proc
        if (arg0 && arg1) {
            struct proc *parent = (struct proc *) arg0;
            struct proc *child = (struct proc *) arg1;
            struct uts_ns *parent_uts;

            // Get parent's UTS namespace and copy to child
            parent_uts = kauth_cred_getdata(parent->p_cred, uts_key);
            if (parent_uts) {
                kauth_cred_setdata(child_proc->p_cred, uts_key, parent_uts);
            }
        }
        break;

    case KAUTH_CRED_FREE:
        // printf("CRED_FREE\n");
        break;
    }
    return result;
}