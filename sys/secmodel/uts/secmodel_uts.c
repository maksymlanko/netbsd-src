#include <secmodel/secmodel.h>

kauth_key_t uts_key; // key to get uts data

secmodel_t uts_sm; // description of uts secmodel

// hostname is a node, but we also want system notifs?
static kauth_listener_t l_system;

static int secmodel_uts_system_cb(kauth_cred_t, kauth_action_t, void *,
    void *, void *, void *, void *);

void
secmodel_uts_init(void)
{
	int error;

	// LIST_INIT(&allprison);
	error = kauth_register_key("uts", &uts_key);
	KASSERT(error == 0);

    // int error = secmodel_register(&uts_sm, "org.netbsd.secmodel.keylock",
    //     "NetBSD Security Model: Keylock", NULL, NULL, NULL);
}

void
secmodel_uts_start(void)
{
        l_system = kauth_listen_scope(KAUTH_SCOPE_SYSTEM,
            secmodel_uts_system_cb, NULL);
}

void
secmodel_keylock_stop(void)
{
        int error;

        kauth_unlisten_scope(l_system);
        kauth_deregister_key(&uts_key);

        // error = secmodel_deregister(keylock_sm);
        // if (error != 0)
        //         printf("secmodel_keylock_stop: secmodel_deregister "
        //             "returned %d\n", error);

}

static int
secmodel_uts_system_cb(kauth_cred_t cred, kauth_action_t action,
    void *cookie, void *arg0, void *arg1, void *arg2, void *arg3)
{
	// TODO: implement
	int result = KAUTH_RESULT_DEFER;
    return result;
}