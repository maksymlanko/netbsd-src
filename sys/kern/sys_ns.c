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

#include <sys/vnode.h> // for vfs_mount_print_all
#include <sys/mount.h>
#include <sys/syscallargs.h>

void print_all_mounts(void);
int unmount_from_kernel(void);
struct mount *get_tmp(void);
struct vnode *get_mnt_test(void);
struct vnode *get_tmp_vnode(void);
struct vnode *get_vnode_from_path(const char*);

int unmount_from_kernel(void)
{
    struct mount *mp;
    mount_iterator_t *iter;
    int error;

    mountlist_iterator_init(&iter);
    while ((mp = mountlist_iterator_next(iter)) != NULL) {
        if (strcmp(mp->mnt_stat.f_mntonname, "/tmp") == 0) {
            printf("found /tmp\n");

            // dounmount() asks us to have reference to mount point if unmounting
            vfs_ref(mp);
            mountlist_iterator_destroy(iter);

            error = dounmount(mp, MNT_FORCE, curlwp);
            if (error) {
                printf("dounmount failed: error %d\n", error);
                return error;
            }
            return 0;
        }
    }
    mountlist_iterator_destroy(iter);
    printf("didn't find /tmp!\n");
    return -1;
}

struct mount *get_tmp(void)
{
    struct mount *mp;
    mount_iterator_t *iter;

    mountlist_iterator_init(&iter);
    while ((mp = mountlist_iterator_next(iter)) != NULL) {
        if (strcmp(mp->mnt_stat.f_mntonname, "/tmp") == 0) {
            printf("found /tmp\n");
            mountlist_iterator_destroy(iter);

            return mp;
        }
    }
    mountlist_iterator_destroy(iter);
    printf("didn't find /tmp!\n");
    return NULL;
}

struct vnode *get_tmp_vnode(void)
{
    struct vnode *vp;
    int error;

    error = namei_simple_kernel("/tmp", NSM_FOLLOW_NOEMULROOT, &vp);
    if (error) {
        printf("Failed to get vnode for %s: %d\n", "/tmp", error);
        return NULL;
    }

    return vp;
}

struct vnode *get_mnt_test(void)
{
    struct vnode *vp;
    int error;

    error = namei_simple_kernel("/home/maksym/mnt_test", NSM_FOLLOW_NOEMULROOT, &vp);
    if (error) {
        printf("Failed to get vnode for %s: %d\n", "mnt_test", error);
        return NULL;
    }

    return vp;
}

struct vnode *get_vnode_from_path(const char* path)
{
    struct vnode *vp;
    int error;

    if (!path){
        printf("Can't get vnode for empty path!\n");
        return NULL;
    }

    error = namei_simple_kernel(path, NSM_FOLLOW_NOEMULROOT, &vp);
    if (error) {
        printf("Failed to get vnode for %s: %d\n", path, error);
        return NULL;
    }

    return vp;
}

void
print_all_mounts(void)
{
    mount_iterator_t *iter;
    struct mount *mp;

    printf("Current mounts:\n");

    mountlist_iterator_init(&iter);
    while ((mp = mountlist_iterator_next(iter)) != NULL) {
        printf("Mount: %s on %s (fstype: %s)\n",
               mp->mnt_stat.f_mntfromname,  // device
               mp->mnt_stat.f_mntonname,    // mounted on
               mp->mnt_stat.f_fstypename);  // FS type
    }
    mountlist_iterator_destroy(iter);
}

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

    if (flags & CLONE_NEWNS) {
        printf("inside CLONE_NEWNS unshare!!\n");
        print_all_mounts();
        enter_mount_ns();
        printf("entered namespace\n");
        print_all_mounts();

        // printf("cloning /tmp to /home/maksym/mnt_test\n");
        // struct vnode *tmp = get_vnode_from_path("/tmp");
        // struct vnode *vp = get_vnode_from_path("/home/maksym/clone_mnt");
        // clone_mnt(tmp, vp);
        // printf("cloned /tmp into /home/maksym/mnt_test!\n");

        printf("cloning to_bind to original\n");
        struct vnode *original = get_vnode_from_path("/home/maksym/file-mount-test/original");
        struct vnode *to_bind = get_vnode_from_path("/home/maksym/file-mount-test/to_bind");
        struct vnode *dir = get_vnode_from_path("/home/maksym/file-mount-test");

        struct vattr va_orig, va_bind, va_dir;
        VOP_GETATTR(original, &va_orig, NOCRED);
        VOP_GETATTR(to_bind, &va_bind, NOCRED);
        VOP_GETATTR(dir, &va_dir, NOCRED);
        printf("original vnode: inode %ld\n", va_orig.va_fileid);
        printf("to_bind vnode: inode %ld\n", va_bind.va_fileid);
        printf("dir vnode: inode %ld\n", va_dir.va_fileid);

        clone_mnt(to_bind, original);
        printf("cloned to_bind into original!\n");

        print_all_mounts();


        // printf("unmounting /tmp\n");
        // unmount_from_kernel();
        // printf("unmounted!\n");
        // print_all_mounts();

        // leave_mount_ns();
        // printf("left namespace back to global\n");
        // print_all_mounts();

        // vfs_mount_print_all(0, printf); // WAY too verbose
    }

	error = 0;

	return error;
}
