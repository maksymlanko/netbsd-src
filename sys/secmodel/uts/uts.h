/* sys/secmodel/uts/secmodel_uts.h */
#ifndef _SECMODEL_UTS_H_
#define _SECMODEL_UTS_H_

#include <sys/types.h>

#ifdef _KERNEL

struct uts_ns *get_uts(kauth_cred_t *);
void unshare_uts(void);
void clone_uts(struct proc *, struct proc *);

struct uts_ns {
	char* hostname;
	int* hostnamelen;
	char* domainname;
	int* domainnamelen;
	u_int ns_refcnt;
};

extern struct uts_ns new_ns;

#endif /* _KERNEL */
#endif /* _SECMODEL_UTS_H_ */
