/* sys/secmodel/uts/secmodel_uts.h */
#ifndef _SECMODEL_UTS_H_
#define _SECMODEL_UTS_H_

#include <sys/types.h>

#ifdef _KERNEL

struct uts_ns *get_uts(void);
void unshare_uts(void);

// Do we need this?
// void secmodel_uts_init(void);
// void secmodel_uts_start(void);
// void secmodel_uts_stop(void);

#endif /* _KERNEL */
#endif /* _SECMODEL_UTS_H_ */
