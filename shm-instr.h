#ifndef _HAVE_SHM_INSTR_H
#define _HAVE_SHM_INSTR_H

#include "afl-fuzz.h"

void update_bitmap_score(const u8 *trace_bits, struct queue_entry* q,
                         struct queue_entry* top_rated[MAP_SIZE],
                         u8 *score_changed);
void simplify_trace(u64* mem);
void setup_shm(struct g* G);
u8 run_target(const struct g* G, char** argv, u8 *kill_signal,
              u64 *total_execs, volatile u8* stop_soon,
              volatile u8* child_timed_out, s32 *child_pid, u8 *trace_bits);
inline u8 has_new_bits(const struct g* G, u8* virgin_map, u8* trace_bits,
                       const u8* virgin_bits, u8 *bitmap_changed);

#endif
