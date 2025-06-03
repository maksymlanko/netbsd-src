# $NetBSD$
#
# Copyright (c) 2025 The NetBSD Foundation, Inc.
# All rights reserved.
#
# This code is derived from software contributed to The NetBSD Foundation
# by Christoph Badura.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
# ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
# TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#

atf_test_case uts_basic
uts_basic_head() {
	atf_set "descr" "Test that uname(1) can create UTS namespaces"
}
uts_basic_body() {
	if unshare -u true 2>&1 | grep -q 'no.*support'; then
		atf_skip "no (UTS) namespace support in kernel"
	fi

	# check that we can create a new UTS namespace
	atf_check unshare -u true

	local hn=$(hostname)	# save global hostname

	# check that the hostname stays the same in new namespace
	atf_check -o "inline:$hn\n" \
		  unshare -u hostname

	# check that we can set the hostname
	atf_check -o "inline:new$hn\n" \
		  unshare -u sh -c "hostname new$hn; hostname"

	local dn=$(domainnname)	# save global domainname

	# check that domainname stays the same in new namespace
	atf_check -o "inline:$dn\n" \
		  unshare -u domainname

	# check that we can set the domainnname
	atf_check -o "inline:new$dn\n" \
		  unshare -u sh -c "domainname new$dn; domainname"
}

atf_init_test_cases() {
	atf_add_test_case uts_basic
}
