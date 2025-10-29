#include <secmodel/secmodel.h>
#include <sys/module.h>
#include <sys/kauth.h>
#include <sys/sysctl.h>
#include <sys/malloc.h>
#include <sys/kmem.h>

// #if defined(_KERNEL_OPT)
// #include "opt_ns.h"
// #include "opt_ns_uts.h"
// #endif

// TODO: FIX!!!
// #if defined(NAMESPACES) && defined(NS_UTS)
// #include <secmodel/mnt/mnt.h>
// #endif
#include <secmodel/mnt/mnt.h>

MODULE(MODULE_CLASS_SECMODEL, secmodel_mnt, NULL);

kauth_key_t mnt_key; /* key to get mnt data */
secmodel_t mnt_sm; /* description of mnt secmodel */
static struct sysctllog *sysctl_mnt_log; /* saves sysctl nodes information */
static kauth_listener_t l_cred; /* listener for credentials scope of secmodel_mnt */

static int secmodel_mnt_cred_cb(kauth_cred_t, kauth_action_t, void *,
    void *, void *, void *, void *);
void secmodel_mnt_init(void);
void secmodel_mnt_start(void);
void secmodel_mnt_stop(void);
struct mnt_ns *get_mnt(kauth_cred_t *);
struct mnt_ns *get_cred_mnt(kauth_cred_t *);
void unshare_mnt(void);
void clone_mnt(struct proc *, struct proc *);
kauth_cred_t unshare_cred_mnt(kauth_cred_t);

// #define mnt_DEBUG
#ifdef MNT_DEBUG
    #define DPRINTF(fmt, ...) do { printf(fmt, ##__VA_ARGS__); } while (0)
#else
    #define DPRINTF(fmt, ...) do { } while (0)
#endif /* MNT_DEBUG */

struct mnt_ns root_mnt;
// struct mnt_ns root_mnt = {
//     .hostname = hostname,
//     .hostnamelen = &hostnamelen,
//     .domainname = domainname,
//     .domainnamelen = &domainnamelen,
//     .ns_refcnt = 1,
// };

struct mnt_ns *
get_mnt(kauth_cred_t *cred)
{
    KASSERT(cred != NULL);
    struct mnt_ns *ns = kauth_cred_getdata(*cred, mnt_key);

    if (ns)
        return ns;

    return &root_mnt;
}

void
unshare_mnt(void)
{
    kauth_cred_t cur_cred, new_cred;
    struct mnt_ns *cur_ns;

    /* get credentials of current process */
    cur_cred = kauth_cred_get();

    /* get cred with unshared mnt */
    new_cred = unshare_cred_mnt(cur_cred);

    /* decrement current ns_refcnt to cancel KAUTH_CRED_COPY incrementing it */
    cur_ns = get_mnt(&cur_cred);
    cur_ns->ns_refcnt--;

    /* modify cred_t of the current process */
    proc_crmod_enter();
    proc_crmod_leave(new_cred, cur_cred, false);
}

void
clone_mnt(struct proc *child, struct proc *parent)
{
    kauth_cred_t parent_cred, new_cred;

    /* get credentials of parent process */
    parent_cred = parent->p_cred;

    /* get cred with unshared mnt */
    new_cred = unshare_cred_mnt(parent_cred);

    /* set child process to use cred with new uts */
    // TODO: this does NOT use kauth API, seems... wrong?
    child->p_cred = new_cred;
}

// Copy (mount) old into (vnode) mnt_point
// struct mount *
// clone_mnt(struct vnode *source, struct vnode *target)
// {
//     // TODO: this should be unshare_cred_mnt, and clone_mnt a wrapper to call it, like clone_uts
//     printf("Cloning mnt!\n");
//     // TODO: if file, do bind-mount through namespace
//     // if directory, we can wrap null-mount since it already bind-mounts directories
//     if(source->v_type == VREG) {
//         printf("Cloning file!\n");
//         mountlist_table_append(source, target);
//         // TODO: how do we know if it failed? Should it return?
//         return NULL;
//     } else {
//         struct mount *mp;
//         mp = create_null_mount(source, target);

//         if (mp == NULL) {
//             printf("Failed creating null_mount!\n");
//             return NULL;
//         }

//         // might need it for bind-mounting files?
//         // target->v_mountedhere = source->v_mount;

//         // TODO: make return void
//         printf("Finished cloning mnt!\n");
//         return target->v_mount;     
//         // TODO: should we use vfs_getnewfsid() somewhere?
//     }
// }


kauth_cred_t
unshare_cred_mnt(kauth_cred_t parent_cred) {
    // TODO: remove NULL
    kauth_cred_t new_cred = NULL;
    // struct mnt_ns *unshared_ns, *cur_ns;

    // DPRINTF("CLONE_MNT: AFTER_GET parent cred: %p cr_refcnt: %u\n",
    //        parent_cred, kauth_cred_getrefcnt(parent_cred));

    // /* certifies that cred_t has 1 reference to get unshare lifecycle correctly */
    // new_cred = kauth_cred_dup(parent_cred);

    // DPRINTF("CLONE_MNT: AFTER DUP parent cred: %p cr_refcnt: %u\n",
    //        parent_cred, kauth_cred_getrefcnt(parent_cred));
    // DPRINTF("CLONE_MNT: NEW_CRED cred: %p cr_refcnt: %u\n",
    //        new_cred, kauth_cred_getrefcnt(new_cred));

    // /* allocate new memory for unshared ns */
    // unshared_ns                 = kmem_zalloc(sizeof(struct uts_ns), KM_SLEEP);
    // unshared_ns->hostname       = kmem_zalloc(MAXHOSTNAMELEN, KM_SLEEP);
    // unshared_ns->domainname     = kmem_zalloc(MAXHOSTNAMELEN, KM_SLEEP);
    // unshared_ns->hostnamelen    = kmem_zalloc(sizeof(int), KM_SLEEP);
    // unshared_ns->domainnamelen  = kmem_zalloc(sizeof(int), KM_SLEEP);

    // /* get uts namespace of current process */
    // cur_ns = get_uts(&parent_cred);

    // /* copy values of current ns into unshared ns */
    // strlcpy(unshared_ns->hostname, cur_ns->hostname, MAXHOSTNAMELEN);
    // strlcpy(unshared_ns->domainname, cur_ns->domainname, MAXHOSTNAMELEN);
    // *unshared_ns->hostnamelen = *cur_ns->hostnamelen;
    // *unshared_ns->domainnamelen = *cur_ns->domainnamelen;
    // /* the unshared ns will start with a count of 1 */
    // unshared_ns->ns_refcnt = 1;

    // /* set unshared_ns as uts namespace of current process */
    // kauth_cred_setdata(new_cred, uts_key, unshared_ns);
    // DPRINTF("CLONE_UTS: new AFTER cred: %p ns_refcnt: %u\n",
    //        new_cred, unshared_ns->ns_refcnt);
    // DPRINTF("CLONE_UTS: old AFTER cred: %p ns_refcnt: %u\n",
    //        parent_cred, cur_ns->ns_refcnt);

    return new_cred;
}

static void
sysctl_security_mnt_setup(struct sysctllog **clog)
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
                       CTLTYPE_NODE, "mnt",
                       SYSCTL_DESCR("mnt security model"),
                       NULL, 0, NULL, 0,
                       CTL_CREATE, CTL_EOL);

        sysctl_createv(clog, 0, &rnode, NULL,
                       CTLFLAG_PERMANENT,
                       CTLTYPE_STRING, "name", NULL,
                       NULL, 0, __UNCONST("MNT security model"), 0,
                       CTL_CREATE, CTL_EOL);
}

void
secmodel_mnt_init(void)
{
    DPRINTF("Entering init\n");
}

void
secmodel_mnt_start(void)
{
    l_cred = kauth_listen_scope(KAUTH_SCOPE_CRED,
        secmodel_mnt_cred_cb, NULL);

    DPRINTF("Registered key\n");
}

void
secmodel_mnt_stop(void)
{
    kauth_unlisten_scope(l_cred);
    kauth_deregister_key(mnt_key);
}

static void
mnt_cred_init(kauth_cred_t cred)
{
    DPRINTF("CRED_INIT with cred: %p\n", cred);
}

static void
mnt_cred_copy(kauth_cred_t src_cred, kauth_cred_t dst_cred)
{
    DPRINTF("CRED_COPY\n");

    struct mnt_ns *src_ns = get_mnt(&src_cred);
    src_ns->ns_refcnt++;
    kauth_cred_setdata(dst_cred, mnt_key, src_ns);

    DPRINTF("COPY: source cred=%p dest cred=%p ns_refcnt=%u\n",
           src_cred, dst_cred, src_ns->ns_refcnt);
}

static void
mnt_cred_fork(struct proc *parent, struct proc *child)
{
    DPRINTF("CRED_FORK\n");

    kauth_cred_t parent_cred = parent->p_cred;
    struct mnt_ns *parent_ns = get_mnt(&parent_cred);

    /* don't increase ns_refcnt because KAUTH_CRED_COPY is called next */
    kauth_cred_setdata(child->p_cred, mnt_key, parent_ns);

    DPRINTF("FORK: child cred: %p, cr_refcnt: %u ns_refcnt: %u\n",
           child->p_cred, kauth_cred_getrefcnt(child->p_cred),
           parent_ns->ns_refcnt);
}

static void
mnt_cred_free(kauth_cred_t cred)
{
    DPRINTF("CRED_FREE\n");

    struct mnt_ns *ns = get_mnt(&cred);
    ns->ns_refcnt--;
    DPRINTF("FREE: cred=%p, ns_refcnt=%u\n", cred, ns->ns_refcnt);

    if (ns->ns_refcnt == 0 && ns != &root_mnt) {
        DPRINTF("CLEANUP: freeing namespace %p\n", ns);
        // kmem_free(ns->hostname, MAXHOSTNAMELEN);
        // kmem_free(ns->domainname, MAXHOSTNAMELEN);
        // kmem_free(ns->hostnamelen, sizeof(int));
        // kmem_free(ns->domainnamelen, sizeof(int));
        // kmem_free(ns, sizeof(struct mnt_ns));
    }
}

static int
secmodel_mnt_modcmd(modcmd_t cmd, void *arg)
{
        int error = 0;

        switch (cmd) {
        case MODULE_CMD_INIT:
                secmodel_mnt_init();
                secmodel_mnt_start();
                sysctl_security_mnt_setup(&sysctl_mnt_log);

                error = secmodel_register(&mnt_sm, "org.netbsd.secmodel.mnt",
                    "NetBSD Security Model: MNT", NULL, NULL, NULL);

                if (error != 0)
                    DPRINTF("secmodel_mnt_modcmd::init: "
                    "secmodel_register returned %d\n", error);

                error = kauth_register_key(mnt_sm, &mnt_key);

                if (error != 0)
                    DPRINTF("secmodel_mnt_modcmd::init: "
                    "kauth_register_key returned %d\n", error);

                break;

        case MODULE_CMD_FINI:
                error = secmodel_deregister(mnt_sm);
                if (error != 0)
                    DPRINTF("secmodel_mnt_modcmd::fini: "
                        "secmodel_deregister returned %d\n", error);

                sysctl_teardown(&sysctl_mnt_log);
                secmodel_mnt_stop();
                break;

        default:
                error = ENOTTY;
                break;
        }

        return error;
}

static int
secmodel_mnt_cred_cb(kauth_cred_t cred, kauth_action_t action,
    void *cookie, void *arg0, void *arg1, void *arg2, void *arg3)
{
    /* credentials scope is safe to always allow requests */
    int result = KAUTH_RESULT_ALLOW;

    switch (action) {
    case KAUTH_CRED_INIT:
        mnt_cred_init(cred);
        break;

    case KAUTH_CRED_COPY:
        /* kauth_cred_t arg0 = destination cred, kauth_cred_t cred = source cred */
        mnt_cred_copy(cred, arg0);
        break;

    case KAUTH_CRED_FORK:
        /* struct proc* arg0 = parent, struct proc* arg1 = child */
        mnt_cred_fork(arg0, arg1);
        break;

    case KAUTH_CRED_FREE:
        mnt_cred_free(cred);
        break;
    }

    return result;
}
