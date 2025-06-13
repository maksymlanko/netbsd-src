#ifndef _SYS_UTS_NS_H_
#define _SYS_UTS_NS_H_

#ifdef _KERNEL
// I've seen this in sys/sys/rnd.h, do we need it? why?

#include <sys/param.h>
// TODO: move to kernel.h..? no, this is temporary and will be done in get_ns()
extern struct uts_ns new_ns;

struct uts_ns {
	char* hostname;
	int* hostnamelen;
	char* domainname;
	int* domainnamelen;
	long* hostid;
};

// TODO: move to sys/sys/ns.c and rename get_ns()
static __inline struct uts_ns *
get_uts(struct proc *p)
{
	// TODO: p->ns_proxy ->uts_ns
	return &new_ns;
}

#endif /* _KERNEL */

#endif /* !_SYS_UTS_NS_H_ */
