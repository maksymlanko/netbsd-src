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
    // TODO:  Please do not use this unless absolutely necessary!
    // You can most likely make your tests run as a regular user if you use puffs and rump.
    atf_tc_set_md_var(tc, "require.user", "root");
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
    // TODO:  Please do not use this unless absolutely necessary!
    // You can most likely make your tests run as a regular user if you use puffs and rump.
    atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(nested_uts_namespace, tc)
{
    pid_t pid1, pid2;
    char original_hostname[256];
    ATF_REQUIRE(gethostname(original_hostname, sizeof(original_hostname)) == 0);

    pid1 = fork();
    if (pid1 == 0) {
        char modified_hostname[256];

        ATF_REQUIRE(syscall(507, CLONE_NEWUTS) == 0);

        ATF_REQUIRE(sethostname("new_hostname", strlen("new_hostname")) == 0);
        ATF_REQUIRE(gethostname(modified_hostname, sizeof(modified_hostname)) == 0);
        ATF_CHECK(strcmp(modified_hostname, "new_hostname") == 0);
        printf("modified: %s\n", modified_hostname);

        pid2 = fork();
        if (pid2 == 0) {
            char second_hostname[256];

            ATF_REQUIRE(syscall(507, CLONE_NEWUTS) == 0);

            ATF_REQUIRE(sethostname("second_hostname", strlen("second_hostname")) == 0);
            ATF_REQUIRE(gethostname(second_hostname, sizeof(second_hostname)) == 0);
            ATF_CHECK(strcmp(second_hostname, "second_hostname") == 0);
            printf("second: %s\n", modified_hostname);

            exit(0);

        } else {
            char middle_hostname[256];
            int status2;
            waitpid(pid2, &status2, 0);
            // needed to fail test if child doesn't know unshare syscall
            if (!WIFEXITED(status2) || WEXITSTATUS(status2) != 0) {
                atf_tc_fail("Nested child process failed");
            }
            ATF_REQUIRE(gethostname(middle_hostname, sizeof(middle_hostname)) == 0);
            ATF_CHECK(strcmp(middle_hostname, modified_hostname) == 0);
            printf("middle: %s\n", middle_hostname);

            exit(0);
        }

    } else {
        char parent_hostname[256];
        int status1;
        waitpid(pid1, &status1, 0);
        // needed to fail test if child doesn't know unshare syscall
        if (!WIFEXITED(status1) || WEXITSTATUS(status1) != 0) {
            atf_tc_fail("Child process failed");
        }

        ATF_REQUIRE(gethostname(parent_hostname, sizeof(parent_hostname)) == 0);
        ATF_CHECK(strcmp(parent_hostname, original_hostname) == 0);
        printf("parent: %s\n", parent_hostname);

    }

}

ATF_TP_ADD_TCS(tp)
{
    ATF_TP_ADD_TC(tp, basic_uts_namespace);
    ATF_TP_ADD_TC(tp, nested_uts_namespace);
    
    return atf_no_error();
}