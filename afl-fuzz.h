#ifndef _HAVE_AFL_FUZZ_H
#define _HAVE_AFL_FUZZ_H

#ifndef VERSION
#define VERSION "(not set)"
#endif

#ifndef DOC_PATH
#define DOC_PATH "(not set)"
#endif

#ifndef BIN_PATH
#define BIN_PATH "(not set)"
#endif

#include "types.h"
#include "stdio.h"
#include "enums.h"
#include "config.h"

/* Lots of globals, but mostly for the status UI and other things where it
   really makes no sense to haul them around as function parameters. */

struct queue_entry {

  u8* fname;                          /* File name for the test case      */
  u32 len;                            /* Input length                     */

  u8  cal_failed,                     /* Calibration failed?              */
      trim_done,                      /* Trimmed?                         */
      was_fuzzed,                     /* Had any fuzzing done yet?        */
      passed_det,                     /* Deterministic stages passed?     */
      has_new_cov,                    /* Triggers new coverage?           */
      var_behavior,                   /* Variable behavior?               */
      favored,                        /* Currently favored?               */
      fs_redundant;                   /* Marked as redundant in the fs?   */

  u32 bitmap_size,                    /* Number of bits set in bitmap     */
      exec_cksum;                     /* Checksum of the execution trace  */

  u64 exec_us,                        /* Execution time (us)              */
      handicap,                       /* Number of queue cycles behind    */
      depth;                          /* Path depth                       */

  u8* trace_mini;                     /* Trace bytes, if kept             */
  u32 tc_ref;                         /* Trace bytes ref count            */

  struct queue_entry *next,           /* Next element, if any             */
                     *next_100;       /* 100 elements ahead               */

};

struct extra_data {
  u8* data;                           /* Dictionary token data            */
  u32 len;                            /* Dictionary token length          */
  u32 hit_cnt;                        /* Use count in the corpus          */
};

typedef u8* (*post_handler_t)(u8* buf, u32* len);

struct g {

         u8 *in_dir,                    /* Input directory with test cases  */
            *out_file,                  /* File to fuzz, if any             */
            *out_dir,                   /* Working & output directory       */
            *sync_dir,                  /* Synchronization directory        */
            *sync_id,                   /* Fuzzer ID                        */
            *use_banner,                /* Display banner                   */
            *in_bitmap,                 /* Input bitmap                     */
            *doc_path,                  /* Path to documentation dir        */
            *target_path,               /* Path to target binary            */
            *orig_cmdline;              /* Original command line            */
  
         u32 exec_tmout;                /* Configurable exec timeout (ms)   */
         u64 mem_limit;                 /* Memory cap for child (MB)        */
  
         u32 stats_update_freq;         /* Stats update frequency (execs)   */
  
         u8  skip_deterministic,        /* Skip deterministic stages?       */
             force_deterministic,       /* Force deterministic stages?      */
             use_splicing,              /* Recombine input files?           */
             dumb_mode,                 /* Run in non-instrumented mode?    */
             score_changed,             /* Scoring for favorites changed?   */
             kill_signal,               /* Signal that killed the child     */
             resuming_fuzz,             /* Resuming an older fuzzing job?   */
             timeout_given,             /* Specific timeout given?          */
             not_on_tty,                /* stdout is not a tty              */
             term_too_small,            /* terminal dimensions too small    */
             uses_asan,                 /* Target uses ASAN?                */
             no_forkserver,             /* Disable forkserver?              */
             crash_mode,                /* Crash mode! Yeah!                */
             in_place_resume,           /* Attempt in-place resume?         */
             auto_changed,              /* Auto-generated tokens changed?   */
             no_cpu_meter_red,          /* Feng shui on the status screen   */
             no_var_check,              /* Don't detect variable behavior   */
             bitmap_changed,            /* Time to update bitmap?           */
             qemu_mode,                 /* Running in QEMU mode?            */
             skip_requested,            /* Skip request, via SIGUSR1        */
             run_over10m;               /* Run time over 10 minutes?        */
  
         s32 out_fd,                    /* Persistent fd for out_file       */
             dev_urandom_fd,            /* Persistent fd for /dev/urandom   */
             dev_null_fd,               /* Persistent fd for /dev/null      */
             fsrv_ctl_fd,               /* Fork server control pipe (write) */
             fsrv_st_fd;                /* Fork server status pipe (read)   */
  
         s32 forksrv_pid,               /* PID of the fork server           */
             child_pid,                 /* PID of the fuzzed program        */
             out_dir_fd;                /* FD of the lock file              */
  
         u8* trace_bits;                /* SHM with instrumentation bitmap  */
  
         u8  virgin_bits[MAP_SIZE],     /* Regions yet untouched by fuzzing */
             virgin_hang[MAP_SIZE],     /* Bits we haven't seen in hangs    */
             virgin_crash[MAP_SIZE];    /* Bits we haven't seen in crashes  */
  
         s32 shm_id;                    /* ID of the SHM region             */
  
         volatile u8 stop_soon,         /* Ctrl-C pressed?                  */
                     clear_screen,      /* Window resized?                  */
                     child_timed_out;   /* Traced process timed out?        */
  
         u32 queued_paths,              /* Total number of queued testcases */
             queued_variable,           /* Testcases with variable behavior */
             queued_at_start,           /* Total number of initial inputs   */
             queued_discovered,         /* Items discovered during this run */
             queued_imported,           /* Items imported via -S            */
             queued_favored,            /* Paths deemed favorable           */
             queued_with_cov,           /* Paths with new coverage bytes    */
             pending_not_fuzzed,        /* Queued but not done yet          */
             pending_favored,           /* Pending favored paths            */
             cur_skipped_paths,         /* Abandoned inputs in cur cycle    */
             cur_depth,                 /* Current path depth               */
             max_depth,                 /* Max path depth                   */
             useless_at_start,          /* Number of useless starting paths */
             current_entry,             /* Current queue entry ID           */
             havoc_div;                 /* Cycle count divisor for havoc    */
  
         u64 total_crashes,             /* Total number of crashes          */
             unique_crashes,            /* Crashes with unique signatures   */
             total_hangs,               /* Total number of hangs            */
             unique_hangs,              /* Hangs with unique signatures     */
             total_execs,               /* Total execve() calls             */
             start_time,                /* Unix start time (ms)             */
             last_path_time,            /* Time for most recent path (ms)   */
             last_crash_time,           /* Time for most recent crash (ms)  */
             last_hang_time,            /* Time for most recent hang (ms)   */
             queue_cycle,               /* Queue round counter              */
             cycles_wo_finds,           /* Cycles without any new paths     */
             trim_execs,                /* Execs done to trim input files   */
             bytes_trim_in,             /* Bytes coming into the trimmer    */
             bytes_trim_out,            /* Bytes coming outa the trimmer    */
             blocks_eff_total,          /* Blocks subject to effector maps  */
             blocks_eff_select;         /* Blocks selected as fuzzable      */
  
         u32 subseq_hangs;              /* Number of hangs in a row         */
  
         u8 *stage_name,                /* Name of the current fuzz stage   */
            *stage_short,               /* Short stage name                 */
            *syncing_party;             /* Currently syncing with...        */
  
         s32 stage_cur, stage_max;      /* Stage progression                */
         s32 splicing_with;             /* Splicing with which test case?   */
  
         u32 syncing_case;              /* Syncing with case #...           */
  
         s32 stage_cur_byte,            /* Byte offset of current stage op  */
             stage_cur_val;             /* Value used for stage op          */
  
         u8  stage_val_type;            /* Value type (STAGE_VAL_*)         */
  
         u64 stage_finds[32],           /* Patterns found per fuzz stage    */
             stage_cycles[32];          /* Execs per fuzz stage             */
  
         u32 rand_cnt;                  /* Random number counter            */
  
         u64 total_cal_us,              /* Total calibration time (us)      */
             total_cal_cycles;          /* Total calibration cycles         */
  
         u64 total_bitmap_size,         /* Total bit count for all bitmaps  */
             total_bitmap_entries;      /* Number of bitmaps counted        */
  
         u32 cpu_core_count;            /* CPU core count                   */
  
         FILE* plot_file;               /* Gnuplot output file              */
  
         struct queue_entry *queue,     /* Fuzzing queue (linked list)      */
                            *queue_cur, /* Current offset within the queue  */
                            *queue_top, /* Top of the list                  */
                            *q_prev100; /* Previous 100 marker              */
  
         struct queue_entry*
    top_rated[MAP_SIZE];                /* Top entries for bitmap bytes     */
  
         struct extra_data* extras;     /* Extra tokens to fuzz with        */
         u32 extras_cnt;                /* Total number of tokens read      */
  
         struct extra_data* a_extras;   /* Automatically selected extras    */
         u32 a_extras_cnt;              /* Total number of tokens available */
  
         post_handler_t post_handler;
  
  /* Interesting values, as per config.h */
  
};

void write_to_testcase(const struct g* G, void* mem, u32 len);
void show_stats(const struct g* G, u8 *term_too_small,
                volatile u8 *clear_screen, u8 *bitmap_changed,
                u8 *auto_changed, volatile u8 *stop_soon,
                u32 *stats_update_freq, u8 *run_over10m);
u8 save_if_interesting(struct g* G, char** argv, void* mem, u32 len, u8 fault);
void mark_as_det_done(const struct g* G, struct queue_entry* q);
void mark_as_variable(const struct g* G, struct queue_entry* q);
int compare_extras_len(const void* p1, const void* p2);

#endif
