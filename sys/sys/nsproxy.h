// TODO: fix this define.. it's for uts
#ifndef _SYS_UTS_NSPROXY_H
#define _SYS_UTS_NSPROXY_H

#ifdef _KERNEL

struct nsproxy {
	struct uts_ns* uts;
	// TODO: add other namespaces;
};

#endif /* _KERNEL */

#endif /* !_SYS_UTS_NSPROXY_H */
