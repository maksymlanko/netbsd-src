#ifndef _SYS_UTS_NS_H_
#define _SYS_UTS_NS_H_

#ifdef _KERNEL

#include <sys/param.h>
#include <sys/proc.h>
#include <secmodel/uts/uts.h>

// TODO: move to kernel.h..? no, this is temporary and will be done in get_ns()
extern struct uts_ns new_ns;

struct uts_ns {
	char* hostname;
	int* hostnamelen;
	char* domainname;
	int* domainnamelen;
	u_int ns_refcnt;
};

#endif /* _KERNEL */

#endif /* !_SYS_UTS_NS_H_ */
