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

#include <sys/cdefs.h>

#ifndef lint
__RCSID("$NetBSD$");
#endif /* not lint */

#define _NETBSD_SOURCE	/* expose unshare(2) */
#include <sys/wait.h>
#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <paths.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h> // TODO: remove after using unshare(2)

#define VERSION "0.1"

static void
help(void)
{
	fputs("usage: unshare [-hV]"
	    " [-u|--uts[=file]]"
	    " [program [args...]]\n",
	    stderr);
	exit(EXIT_FAILURE);
	/* NORETURN */
}

static void
version(void)
{
	fputs(VERSION "\n", stderr);
	exit(0);
	/* NORETURN */
}

extern char *optarg;
extern int optind;

static struct option longopts[] = {
	{ "uts", 	optional_argument,	NULL, 	'u' },
	{ NULL,  	0, 			NULL, 	0 }
};

int
main(int argc, char *argv[])
{
	int rv, flags, opt, pid, status;
	const char *cmd;

	setprogname(argv[0]);

	flags = 0;
	// while ((opt = getopt_long(argc, argv, "hVu:", longopts, NULL)))
	while ((opt = getopt_long(argc, argv, "hVu::", longopts, NULL)) != -1)
	{
		switch (opt) {
		case 'u':
			flags |= CLONE_NEWUTS;
			/* XXX should handle optarg */
			break;
		case 'V':
			version();
			break;
		case 'h':
		case '?':
		default:
			help();
		}
	}
	argc -= optind;
	argv += optind;

	/* init cmd from argv, $SHELL or _PATH_BSHELL */
	if (argc > 0)
		cmd = *argv++;
	else if ((cmd = getenv("SHELL")) == NULL)
		cmd = _PATH_BSHELL;

	// if ((rv = unshare(flags)) == -1) {
	if ((rv = syscall(507, flags)) == -1) {
		if (rv == ENOSYS)
			err(EXIT_FAILURE, "no namespace support in the kernel");
		else
			err(EXIT_FAILURE, "unshare");
	}

	if ((pid = fork()) == 0) {
		/* child */
		execvp(cmd, argv);
		err(EXIT_FAILURE, "cannot exec \"%s\"", cmd);
	}
	/* parent */
	/* XXX need to loop? */
	if ((rv = waitpid(pid, &status, 0)) == -1)
		err(EXIT_FAILURE, "waitpid");
	exit(status);
}
