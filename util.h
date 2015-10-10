#ifndef _HAVE_UTIL_H
#define __HAVE_UTIL_H

#include "types.h"

u64 get_cur_time(void);
u64 get_cur_time_us(void);
u8* DF(double val);
u8* DMS(u64 val);
u8* DTD(u64 cur_ms, u64 event_ms);


u8* DI(u64 val);
inline u32 UR(struct g* G, u32 limit);
u32 next_p2(u32 val);

#define AREP4(_sym)   (_sym), (_sym), (_sym), (_sym)
#define AREP8(_sym)   AREP4(_sym), AREP4(_sym)
#define AREP16(_sym)  AREP8(_sym), AREP8(_sym)
#define AREP32(_sym)  AREP16(_sym), AREP16(_sym)
#define AREP64(_sym)  AREP32(_sym), AREP32(_sym)
#define AREP128(_sym) AREP64(_sym), AREP64(_sym)

#define CHK_FORMAT(_divisor, _limit_mult, _fmt, _cast) do { \
    if (val < (_divisor) * (_limit_mult)) { \
      sprintf(tmp[cur], _fmt, ((_cast)val) / (_divisor)); \
      return tmp[cur]; \
    } \
  } while (0)

#endif
