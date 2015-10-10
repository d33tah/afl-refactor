#ifndef _HAVE_UTIL_H
#define __HAVE_UTIL_H

#include "types.h"

u64 get_cur_time(void);
u64 get_cur_time_us(void);
u8* DF(double val);
u8* DMS(u64 val);
u8* DTD(u64 cur_ms, u64 event_ms);
u32 count_bits(const u8* mem);
u32 count_bytes(const u8* mem);
u32 count_non_255_bytes(const u8* mem);
double get_runnable_processes(void);
void get_core_count(u32 *cpu_core_count, const u8 *doc_path);

u8* DI(u64 val);
inline u32 UR(struct g* G, u32 limit);
u32 next_p2(u32 val);

#define FFL(_b) (0xffULL << ((_b) << 3))
#define FF(_b)  (0xff << ((_b) << 3))

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
