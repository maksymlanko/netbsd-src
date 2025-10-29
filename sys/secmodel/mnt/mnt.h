/* sys/secmodel/mnt/secmodel_mnt.h */
#ifndef _SECMODEL_MNT_H_
#define _SECMODEL_MNT_H_

#include <sys/types.h>
#include <sys/mount.h> // for struct mountlist

#ifdef _KERNEL

struct mountlist * get_mount(void);
void enter_mount_ns(void);
void leave_mount_ns(void);
// struct mount *clone_mnt(struct vnode *old, struct vnode *mnt_point);
void clone_mnt(struct proc *, struct proc *);
int inside_namespace(void);
struct vnode *lookup_namespace(struct vnode *mountpoint);

struct mount_pair {
	TAILQ_ENTRY(mount_pair) mpair_list;	/* Mount list. */
	ino_t source_fileid;
	dev_t source_fsid;
	ino_t target_fileid;
	dev_t target_fsid;
	struct mount *source_mp; // needed to call VFS_VGET()
};

struct mnt_ns {
	struct mountlist *ns_mountlist;
	u_int ns_refcnt;
};

// extern struct uts_ns root_uts;

#endif /* _KERNEL */
#endif /* _SECMODEL_MNT_H_ */
