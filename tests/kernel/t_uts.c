#include <sys/types.h>
#include <sys/utsname.h>
#include <atf-c.h>
#include <errno.h>
#include <string.h>
#include <sys/wait.h>
#include <stdlib.h>

#include <stdio.h>

#define CLONE_NEWUTS 0x04000000

ATF_TC(basic_uts_namespace);
ATF_TC_HEAD(basic_uts_namespace, tc)
{
    atf_tc_set_md_var(tc, "descr", "Test unshare system call for uts namespace");
}
ATF_TC_BODY(basic_uts_namespace, tc)
{

    pid_t pid;
    char original_hostname[256];
    ATF_REQUIRE(gethostname(original_hostname, sizeof(original_hostname)) == 0);
    printf("original: %s\n", original_hostname);

    pid = fork();
    if (pid == 0) {
        char modified_hostname[256];

        ATF_REQUIRE(syscall(507, CLONE_NEWUTS) == 0);
       
        ATF_REQUIRE(sethostname("new_hostname", strlen("new_hostname")) == 0);
        ATF_REQUIRE(gethostname(modified_hostname, sizeof(modified_hostname)) == 0);
        ATF_CHECK(strcmp(modified_hostname, "new_hostname") == 0);
        printf("modified: %s\n", modified_hostname);

        exit(0);

    } else {
        char parent_hostname[256];
        int status;
        waitpid(pid, &status, 0);
        // needed to fail test if child doesn't know unshare syscall
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            atf_tc_fail("Child process failed");
        }

        ATF_REQUIRE(gethostname(parent_hostname, sizeof(parent_hostname)) == 0);
        ATF_CHECK(strcmp(parent_hostname, original_hostname) == 0);
        printf("parent: %s\n", parent_hostname);

    }
}

ATF_TC(nested_uts_namespace);
ATF_TC_HEAD(nested_uts_namespace, tc)
{
    atf_tc_set_md_var(tc, "descr", "Test nested unshare system call for uts namespace");
}
ATF_TC_BODY(nested_uts_namespace, tc)
{
    // TODO: nested
    char original_hostname[256];
    ATF_REQUIRE(gethostname(original_hostname, sizeof(original_hostname)) == 0);
}

ATF_TP_ADD_TCS(tp)
{
    ATF_TP_ADD_TC(tp, basic_uts_namespace);
    ATF_TP_ADD_TC(tp, nested_uts_namespace);
    
    return atf_no_error();
}