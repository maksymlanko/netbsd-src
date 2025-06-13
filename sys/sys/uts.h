#ifndef _SYS_UTS_NS_H_
#define _SYS_UTS_NS_H_

#ifdef _KERNEL
// I've seen this in sys/sys/rnd.h, do we need it? why?

#include <sys/param.h>

struct uts_ns {
	char* hostname;
	int* hostnamelen;
	char* domainname;
	int* domainnamelen;
	long* hostid;
};

#endif /* _KERNEL */

#endif /* !_SYS_UTS_NS_H_ */
