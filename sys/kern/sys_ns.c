/*	$NetBSD$	*/

/*-
 * Copyright (c) 2025 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Christoph Badura.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Linux compatible namespaces: system calls.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#ifdef _KERNEL_OPT
#include "opt_ns.h"
#endif

#include <sys/types.h>
#include <sys/param.h>

#include <sys/sched.h>
#include <sys/syscallargs.h>
#include <secmodel/uts/uts.h>

/* Note that retval is unused as this syscall only returns success/failure. */
int
sys_unshare(struct lwp *l, const struct sys_unshare_args *uap,
    register_t *retval)
{
	/* {
		syscallarg(int) 	flags;
	} */
	int flags = SCARG(uap, flags);
	int error;

	/* Validate the flags.  */
	/* XXX Sync with Linux: CLONE_FILES|CLONE_FS|CLONE_SYSVSEM|
	 *     CLONE_THREAD|CLONE_SIGHAND|CLONE_VM|CLONE_NEWTIME
	 */
	if (flags & ~CLONE_NSMASK) {
		/* Unknown flags.  */
		return EINVAL;
	}

    if (flags & CLONE_NEWUTS) {
        unshare_uts();
    }

	// TODO: proper return 'name'
	error = 0;

	return error;
}