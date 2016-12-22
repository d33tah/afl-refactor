#ifndef _HAVE_SHM_INSTR_H
#define _HAVE_SHM_INSTR_H

#include "afl-fuzz.h"
#define FFL(_b) (0xffULL << ((_b) << 3))

void update_bitmap_score(const u8 *trace_bits, struct queue_entry* q,
                         struct queue_entry* top_rated[MAP_SIZE],
                         u8 *score_changed);
void simplify_trace(u64* mem);
void setup_shm(struct g* G);
u8 run_target(const struct g* G, char** argv, u8 *kill_signal,
              u64 *total_execs, volatile u8* stop_soon,
              volatile u8* child_timed_out, s32 *child_pid, u8 *trace_bits);

/* Check if the current execution path brings anything new to the table.
   Update virgin bits to reflect the finds. Returns 1 if the only change is
   the hit-count for a particular tuple; 2 if there are new tuples seen. 
   Updates the map, so subsequent calls will always return 0.

   This function is called after every exec() on a fairly large buffer, so
   it needs to be fast. We do this in 32-bit and 64-bit flavors. */

inline u8 has_new_bits(const struct g* G, u8* virgin_map, u8* trace_bits,
                       const u8* virgin_bits, u8 *bitmap_changed) {

#ifdef __x86_64__

  u64* current = (u64*)trace_bits;
  u64* virgin  = (u64*)virgin_map;

  u32  i = (MAP_SIZE >> 3);

#else

  u32* current = (u32*)trace_bits;
  u32* virgin  = (u32*)virgin_map;

  u32  i = (MAP_SIZE >> 2);

#endif /* ^__x86_64__ */

  u8   ret = 0;

  while (i--) {

#ifdef __x86_64__

    u64 cur = *current;
    u64 vir = *virgin;

#else

    u32 cur = *current;
    u32 vir = *virgin;

#endif /* ^__x86_64__ */

    /* Optimize for *current == ~*virgin, since this will almost always be the
       case. */

    if (cur & vir) {

      if (ret < 2) {

        /* This trace did not have any new bytes yet; see if there's any
           current[] byte that is non-zero when virgin[] is 0xff. */

#ifdef __x86_64__

        if (((cur & FFL(0)) && (vir & FFL(0)) == FFL(0)) ||
            ((cur & FFL(1)) && (vir & FFL(1)) == FFL(1)) ||
            ((cur & FFL(2)) && (vir & FFL(2)) == FFL(2)) ||
            ((cur & FFL(3)) && (vir & FFL(3)) == FFL(3)) ||
            ((cur & FFL(4)) && (vir & FFL(4)) == FFL(4)) ||
            ((cur & FFL(5)) && (vir & FFL(5)) == FFL(5)) ||
            ((cur & FFL(6)) && (vir & FFL(6)) == FFL(6)) ||
            ((cur & FFL(7)) && (vir & FFL(7)) == FFL(7))) ret = 2;
        else ret = 1;

#else

        if (((cur & FF(0)) && (vir & FF(0)) == FF(0)) ||
            ((cur & FF(1)) && (vir & FF(1)) == FF(1)) ||
            ((cur & FF(2)) && (vir & FF(2)) == FF(2)) ||
            ((cur & FF(3)) && (vir & FF(3)) == FF(3))) ret = 2;
        else ret = 1;

#endif /* ^__x86_64__ */

      }

      *virgin = vir & ~cur;

    }

    current++;
    virgin++;

  }

  if (ret && virgin_map == virgin_bits) *bitmap_changed = 1;

  return ret;

}

#endif
