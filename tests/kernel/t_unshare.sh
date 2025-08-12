atf_test_case supports_uts
supports_uts_head() {
    atf_set "descr" "This test case ensures the kernel has namespace support"
}
supports_uts_body() {
    atf_check -s eq:0 -e empty unshare -u true
}

atf_test_case isolates_uts
isolates_uts_head() {
    atf_set "descr" "This test case ensures that unshare command isolates \
    the uts namespace"
}
isolates_uts_body() {
    ORIGINAL_HOST="$(hostname)"
    NEW_HOST=$(unshare -u /bin/ksh -c 'hostname new_host; hostname')
    FINAL_HOST="$(hostname)"

    atf_check_equal $NEW_HOST "new_host"
    atf_check_equal $ORIGINAL_HOST $FINAL_HOST
}

atf_init_test_cases() {
    atf_add_test_case supports_uts
    atf_add_test_case isolates_uts
}