#include <secmodel/secmodel.h>
#include <sys/module.h>
#include <sys/kauth.h>
#include <sys/sysctl.h>

MODULE(MODULE_CLASS_SECMODEL, secmodel_uts, NULL);

kauth_key_t uts_key; // key to get uts data

secmodel_t uts_sm; // description of uts secmodel

// hostname is a node, but we also want system notifs?
static kauth_listener_t l_system;

static int secmodel_uts_system_cb(kauth_cred_t, kauth_action_t, void *,
    void *, void *, void *, void *);
void secmodel_uts_init(void);
void secmodel_uts_start(void);
void secmodel_uts_stop(void);

void
secmodel_uts_init(void)
{
    printf("Entering init\n");
}

void
secmodel_uts_start(void)
{
    kauth_register_key(uts_sm, &uts_key);
    l_system = kauth_listen_scope(KAUTH_SCOPE_SYSTEM,
        secmodel_uts_system_cb, NULL);

    printf("REGISTERED KEY!!!\n\n\n");
}

void
secmodel_uts_stop(void)
{
        kauth_unlisten_scope(l_system);
        kauth_deregister_key(uts_key);
}

static int
secmodel_uts_system_cb(kauth_cred_t cred, kauth_action_t action,
    void *cookie, void *arg0, void *arg1, void *arg2, void *arg3)
{
	// TODO: implement

	int result = KAUTH_RESULT_DEFER;
    printf("DEFERING!!!\n\n\n");

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
                // TODO: build node;
                // sysctl_security_example_setup(&sysctl_example_log);

                // error = secmodel_register(&uts_sm,
                //     SECMODEL_EXAMPLE_ID, SECMODEL_EXAMPLE_NAME,
                //     NULL, secmodel_example_eval, NULL);

                error = secmodel_register(&uts_sm, "org.netbsd.secmodel.uts",
                    "NetBSD Security Model: UTS", NULL, NULL, NULL);

                if (error != 0)
                        printf("secmodel_uts_modcmd::init: "
                            "secmodel_register returned %d\n", error);
                break;

        case MODULE_CMD_FINI:
                error = secmodel_deregister(uts_sm);
                if (error != 0)
                        printf("secmodel_uts_modcmd::fini: "
                            "secmodel_deregister returned %d\n", error);

                // TODO: teardown node;
                // sysctl_teardown(&sysctl_example_log);
                secmodel_uts_stop();
                break;

        default:
                error = ENOTTY;
                break;
        }

        return error;
}