#ifndef _HAVE_SHM_INSTR_H
#define _HAVE_SHM_INSTR_H

#include "afl-fuzz.h"

u8 run_target(const struct g* G, char** argv, u8 *kill_signal,
              u64 *total_execs, volatile u8* stop_soon,
              volatile u8* child_timed_out, s32 *child_pid, u8 *trace_bits);

#endif