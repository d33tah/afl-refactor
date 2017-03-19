/*
   american fuzzy lop - fuzzer code
   --------------------------------

   Written and maintained by Michal Zalewski <lcamtuf@google.com>

   Copyright 2013 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This is the real deal: the program takes an instrumented binary and
   attempts a variety of basic fuzzing tricks, paying close attention to
   how they affect the execution path.

 */

#define AFL_MAIN

#include "config.h"
#include "types.h"
#include "debug.h"
#include "alloc-inl.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <dirent.h>

#include <sys/fcntl.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/resource.h>


static u8 *in_dir,                    /* Directory with initial testcases */
          *out_file,                  /* File to fuzz, if any             */
          *out_dir;                   /* Working & output directory       */

static u32 exec_tmout = EXEC_TIMEOUT, /* Configurable exec timeout (ms)   */
           mem_limit = MEM_LIMIT;     /* Memory cap for the child process */

static u8  keep_testcases,            /* Keep testcases?                  */
           skip_deterministic,        /* Skip deterministic stages?       */
           dumb_mode,                 /* Allow non-instrumented code?     */
           kill_signal;               /* Signal that killed the child     */

static s32 out_fd,                    /* Persistent fd for out_file       */
           dev_null;                  /* Persistent fd for /dev/null      */

static s32 child_pid;                 /* PID of the fuzzed program        */

static u8* trace_bits;                /* SHM with instrumentation bitmap  */
static u8  virgin_bits[65536];         /* Regions yet untouched by fuzzing */

static s32 shm_id;                    /* ID of the SHM region             */

static volatile u8 stop_soon,         /* Ctrl-C pressed?                  */
                   clear_screen,      /* Window resized?                  */
                   child_timed_out;   /* Traced process timed out?        */

static u64 unique_queued,             /* Total number of queued testcases */
           unique_processed,          /* Number of finished queue entries */
           total_crashes,             /* Total number of crashes          */
           total_hangs,               /* Total number of hangs            */
           queued_later,              /* Items queued after 1st cycle     */
           abandoned_inputs,          /* Number of abandoned inputs       */
           total_execs,               /* Total execvp() calls             */
           start_time,                /* Unix start time (ms)             */
           queue_cycle;               /* Queue round counter              */

static u32 queue_len;                 /* Current length of the queue      */
static u32 subseq_hangs;              /* Number of hangs in a row         */

static u8* stage_name;                /* Name of the current fuzz stage   */
static s32 stage_cur, stage_max;      /* Stage progression                */

static u64 stage_finds[10],           /* Patterns found per fuzz stage    */
           stage_cycles[10];          /* Execs per fuzz stage             */


struct queue_entry {
  u8* fname;                          /* File name for the test case      */
  u32 len;                            /* Input length                     */
  u8  keep;                           /* Do not delete this test case     */
  u8  det_done;                       /* Deterministic stage done?        */
  struct queue_entry* next;           /* Next element, if any             */
};

static struct queue_entry *queue,     /* Fuzzing queue (linked list)      */
                          *queue_cur, /* Current offset within the queue  */
                          *queue_top; /* Top of the list                  */


/* Interesting values, as per config.h */

static u8  interesting_8[]  = { INTERESTING_8 };
static u16 interesting_16[] = { INTERESTING_8, INTERESTING_16 };
static u32 interesting_32[] = { INTERESTING_8, INTERESTING_16, INTERESTING_32 };


/* Append new test case to the queue. */

static void add_to_queue(u8* fname, u32 len, u8 keep) {

  struct queue_entry* q = ck_alloc(sizeof(struct queue_entry));

  q->fname = fname;
  q->len   = len;
  q->keep  = keep;

  if (queue_top) {

    queue_top->next = q;
    queue_top = q;

  } else queue = queue_top = q;

  queue_len++;
  unique_queued++;

  if (queue_cycle > 1) queued_later++;

}


/* Destroy the entire queue. */

static void destroy_queue(void) {

  struct queue_entry *q = queue, *n;

  while (q) {

    n = q->next;

    if (!q->keep && !keep_testcases)
      unlink(q->fname); /* Ignore errors */

    ck_free(q->fname);
    ck_free(q);
    q = n;

  }

}


/* Check if the current execution path brings anything new to the table.
   Update virgin bits to reflect the finds. */

static inline u8 has_new_bits(void) {

  u32* current = (u32*)trace_bits;
  u32* virgin  = (u32*)virgin_bits;

  u32  i = (65536 >> 2);
  u8   ret = 0;

  while (i--) {

    if (*current & *virgin) {
      *virgin &= ~*current;
      ret = 1;
    }

    current++;
    virgin++;

  }

  return ret;

}


/* Count the number of bits set in the provided bitmap. */

static inline u32 count_bits(u8* mem) {

  u32* ptr = (u32*)mem;
  u32  i   = (65536 >> 2);
  u32  ret = 0;

  while (i--) {

    u32 v = *(ptr++);

    v -= ((v >> 1) & 0x55555555);
    v = (v & 0x33333333) + ((v >> 2) & 0x33333333);
    ret += (((v + (v >> 4)) & 0xF0F0F0F) * 0x1010101) >> 24;

  }

  return ret;

}


/* Get rid of shared memory (atexit handler). */

static void remove_shm(void) {
  shmctl(shm_id, IPC_RMID, NULL);
}


/* Configure shared memory. */

static void setup_shm(void) {

  u8* shm_str;

  memset(virgin_bits, 255, 65536);

  shm_id = shmget(IPC_PRIVATE, 65536, IPC_CREAT | IPC_EXCL | 0600);

  if (shm_id < 0) PFATAL("shmget() failed");

  atexit(remove_shm);

  shm_str = alloc_printf("%d", shm_id);

  setenv(SHM_ENV_VAR, shm_str, 1);

  ck_free(shm_str);

  trace_bits = shmat(shm_id, NULL, 0);
  
  if (!trace_bits) PFATAL("shmat() failed");

}


/* Read all testcases from the input directory, then queue them for testing. */

static void read_testcases(void) {

  DIR* d = opendir(in_dir);
  struct dirent* de;

  if (!d) PFATAL("Unable to open '%s'", in_dir);

  while ((de = readdir(d))) {

    struct stat st;
    u8* fn = alloc_printf("%s/%s", in_dir, de->d_name);
 
    if (stat(fn, &st) || access(fn, R_OK))
      PFATAL("Unable to access '%s'", fn);

    if (!S_ISREG(st.st_mode) || !st.st_size) {

      ck_free(fn);
      continue;

    }

    if (st.st_size > MAX_FILE) 
      FATAL("Test case '%s' is too big", fn);

    add_to_queue(fn, st.st_size, 1);

  }

  if (!unique_queued) FATAL("No usable test cases in '%s'", in_dir);

}


/* Execute target application, monitoring for timeouts. Return status
   information. The called program will update trace_bits[]. */

#define FAULT_NONE   0
#define FAULT_HANG   1
#define FAULT_CRASH  2
#define FAULT_ERROR  3

static u8 run_target(char** argv) {

  static struct itimerval it;
  int status;

  child_timed_out = 0;

  memset(trace_bits, 0, 65536);

  child_pid = fork();

  if (child_pid < 0) PFATAL("fork() failed");

  if (!child_pid) {

    struct rlimit r;

    r.rlim_max = r.rlim_cur = ((rlim_t)mem_limit) << 20;

    setrlimit(RLIMIT_AS, &r); /* Ignore errors */

    /* Isolate the process and configure standard descriptors. If out_file is
       specified, stdin is /dev/null; otherwise, out_fd is cloned instead. */

    setsid();

    dup2(dev_null, 1);
    dup2(dev_null, 2);

    if (out_file) {

      dup2(dev_null, 0);

    } else {

      dup2(out_fd, 0);
      close(out_fd);

    }

    close(dev_null);

    execvp(argv[0], argv);

    /* Use a distinctive return value to tell the parent about execvp()
       falling through. */

    exit(EXEC_FAIL);

  }

  /* Configure timeout, as requested by user, then wait for child to terminate. */

  it.it_value.tv_sec = (exec_tmout / 1000);
  it.it_value.tv_usec = (exec_tmout % 1000) * 1000;

  setitimer(ITIMER_REAL, &it, NULL);

  if (waitpid(child_pid, &status, WUNTRACED) <= 0) PFATAL("waitpid() failed");

  child_pid = 0;
  it.it_value.tv_sec = 0;
  it.it_value.tv_usec = 0;

  setitimer(ITIMER_REAL, &it, NULL);

  total_execs++;

  /* Report outcome to caller. */

  if (child_timed_out) return FAULT_HANG;

  if (WIFSIGNALED(status) && !stop_soon) {
    kill_signal = WTERMSIG(status);
    return FAULT_CRASH;
  }

  if (WEXITSTATUS(status) == EXEC_FAIL) return FAULT_ERROR;

  return 0;

}


/* Perform dry run of all test cases to confirm that the app is working as
   expected. */

static void perform_dry_run(char** argv) {

  struct queue_entry* q = queue;

  while (q) {

    u8  fault;
    u32 i;

    ACTF("Verifying test case '%s'...", q->fname);

    if (!out_file) {

      out_fd = open(q->fname, O_RDONLY);
      if (out_fd < 0) PFATAL("Unable to open '%s'", q->fname);

    } else {

      unlink(out_file); /* Ignore errors. */
      if (link(q->fname, out_file)) PFATAL("link() failed");

    }

    fault = run_target(argv);
    if (stop_soon) return;

    switch (fault) {

      case FAULT_HANG:  FATAL("Test case '%s' results in a hang (adjusting -t "
                              "may help)", q->fname);

      case FAULT_CRASH: FATAL("Test case '%s' results in a crash", q->fname);

      case FAULT_ERROR: FATAL("Unable to execute target application ('%s')",
                              argv[0]);

    }

    if (!has_new_bits() && !dumb_mode)
      FATAL("No instrumentation detected (you can always try -n)");

    /* Wait long enough for any time(0)-based randomness to change. */

    for (i = 0; (i < 15) && !stop_soon; i++) usleep(100000);
    if (stop_soon) return;

    for (i = 0; i < CAL_CYCLES; i++) {

      if (!out_file) lseek(out_fd, 0, SEEK_SET);
      fault = run_target(argv);

      if (stop_soon) return;

      switch (fault) {

        case FAULT_HANG:  FATAL("Test case '%s' results in intermittent hangs "
                                "(adjusting -t may help)", q->fname);

        case FAULT_CRASH: FATAL("Test case '%s' results in intermittent "
                                "crashes", q->fname);

        case FAULT_ERROR: FATAL("Unable to execute target application (huh)");

      }

      if (has_new_bits())
        FATAL("Inconsistent instrumentation output for test case '%s'",
              q->fname);

    }

    if (!out_file) close(out_fd);

    OKF("Done: %u bits set, %u remaining in the bitmap.\n", 
         count_bits(trace_bits), count_bits(virgin_bits));

    q = q->next;

  }

}


/* Write modified data to file for testing. If out_file is set, the old file
   is unlinked and a new one is created. Otherwise, out_fd is rewound and
   truncated. */

static void write_to_testcase(void* mem, u32 len) {

  s32 fd = out_fd;

  if (out_file) {

    unlink(out_file); /* Ignore errors. */

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif /* !O_NOFOLLOW */

    fd = open(out_file, O_WRONLY | O_CREAT | O_EXCL, 0600);

    if (fd < 0) PFATAL("Unable to create '%s'", out_file);

  } else lseek(fd, 0, SEEK_SET);

  if (write(fd, mem, len) != len) 
    PFATAL("Short write to output file");

  if (!out_file) {

    if (ftruncate(fd, len)) PFATAL("ftruncate() failed");
    lseek(fd, 0, SEEK_SET);

  } else close(fd);

}


/* Check if the result of a test run is interesting, save or queue the input
   test case for further analysis if so. */

static void save_if_interesting(void* mem, u32 len, u8 fault) {

  u8* fn = "";
  s32 fd;

  switch (fault) {

    case FAULT_NONE:

      if (!has_new_bits()) return;
      fn = alloc_printf("%s/queue/%llu", out_dir, unique_queued);
      add_to_queue(fn, len, 0);
      break;

    case FAULT_HANG:
      fn = alloc_printf("%s/hangs/%llu", out_dir, total_hangs);
      total_hangs++;
      break;

    case FAULT_CRASH:
      fn = alloc_printf("%s/crashes/%llu-signal%u", out_dir, total_crashes, 
                        kill_signal);
      total_crashes++;
      break;

    case FAULT_ERROR: FATAL("Unable to execute target application");

  }

  fd = open(fn, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);

  if (fd < 0) PFATAL("Unable to create '%s'\n", fn);

  if (write(fd, mem, len) != len) PFATAL("Short write to '%s'", fn);

  if (fault) ck_free(fn);

  close(fd);

}


/* Display some fuzzing stats. */

static void show_stats(void) {

  struct timeval tv;
  struct timezone tz;
  s64 run_time;

  u32 run_d, run_h, run_m;
  double run_s;

  u32 vbits = (65536 << 3) - count_bits(virgin_bits);

  gettimeofday(&tv, &tz);

  run_time = (tv.tv_sec * 1000L) + (tv.tv_usec / 1000) - start_time;

  if (!run_time) run_time = 1;

  run_d = run_time / 1000 / 60 / 60 / 24;
  run_h = (run_time / 1000 / 60 / 60) % 24;
  run_m = (run_time / 1000 / 60) % 60;
  run_s = ((double)(run_time % 60000)) / 1000;

  SAYF(TERM_HOME cCYA 
       "afl-fuzz " cBRI VERSION cYEL "\n--------------\n\n"

       cCYA "Queue cycle: " cBRI "%llu\n\n"

       cGRA 
       "    Overall run time : " cNOR "%u day%s, %u hr%s, %u min, %0.02f sec"
       "    \n", queue_cycle,
       run_d, (run_d == 1) ? "" : "s", run_h, (run_h == 1) ? "" : "s",
       run_m, run_s);

  SAYF(cGRA
       "     Execution paths : " cNOR "%llu+%llu/%llu done "
       "(%0.02f%%)        \n", unique_processed, abandoned_inputs, unique_queued,
       ((double)unique_processed + abandoned_inputs) * 100 / unique_queued);

  SAYF(cGRA
       "       Current stage : " cNOR "%s, %u/%u done (%0.02f%%)            \n",
       stage_name, stage_cur, stage_max, ((double)stage_cur) * 100 / stage_max);

  SAYF(cGRA
       "    Execution cycles : " cNOR "%llu (%0.02f per second)        \n",
       total_execs, ((double)total_execs) * 1000 / run_time);

  SAYF(cGRA
       "      Problems found : " cNOR "%llu crashes, %llu hangs    \n",
       total_crashes, total_hangs);

  SAYF(cGRA
       "      Bitmap density : " cNOR "%u tuples seen (%0.02f%%)    \n",
       vbits, ((double)vbits) * 100 / (65536 << 3));

  SAYF(cGRA
       "  Fuzzing efficiency : " cNOR "paths = %0.02f ppm, faults = %0.02f ppm"
       cRST "        \n\n", ((double)unique_queued) * 1000000 / total_execs,
       ((double)total_crashes + total_hangs) * 1000000 / total_execs);

  SAYF(cCYA "Per-stage yields:\n\n"
       cGRA
       "     Bit-level flips : " cNOR "%llu/%llu, %llu/%llu, %llu/%llu\n",
        stage_finds[0], stage_cycles[0], stage_finds[1], stage_cycles[1],
        stage_finds[2], stage_cycles[2]);

  SAYF(cGRA
       "    Byte-level flips : " cNOR "%llu/%llu, %llu/%llu, %llu/%llu\n",
        stage_finds[3], stage_cycles[3], stage_finds[4], stage_cycles[4],
        stage_finds[5], stage_cycles[5]);

  SAYF(cGRA
       "    Interesting ints : " cNOR "%llu/%llu, %llu/%llu, %llu/%llu\n",
        stage_finds[6], stage_cycles[6], stage_finds[7], stage_cycles[7],
        stage_finds[8], stage_cycles[8]);

  SAYF(cGRA
       "       Random tweaks : " cNOR "%llu/%llu (%llu latent paths)" cRST "\n\n",
        stage_finds[9], stage_cycles[9], queued_later);

}


/* Write a modified test case, run program, process results. Handle
   error conditions. */

static u8 common_fuzz_stuff(char** argv, u8* out_buf, u32 len) {

  u8 fault;

  write_to_testcase(out_buf, len);

  fault = run_target(argv);

  if (stop_soon) return 1;

  if (fault == FAULT_HANG && subseq_hangs++ > HANG_LIMIT) {

    abandoned_inputs++;
    return 1;

  } else subseq_hangs = 0;

  save_if_interesting(out_buf, len, fault);

  if (!(stage_cur % 100) || stage_cur + 1 == stage_max) show_stats();

  return 0;

}


/* Take the first entry from the queue, fuzz it for a while. This
   function is a tad too long... */

static void fuzz_one(char** argv) {

  s32 len, fd, temp_len;
  u8  *in_buf, *out_buf;
  s32 i, j;

  u64 orig_hit_cnt, new_hit_cnt;

  /* Read the test case into memory, remove file if appropriate. */

  fd = open(queue_cur->fname, O_RDONLY);

  if (fd < 0) PFATAL("Unable to open '%s'", queue_cur->fname);

  len = queue_cur->len;

  in_buf  = ck_alloc(len),
  out_buf = ck_alloc(len);

  if (read(fd, in_buf, len) != len)
    PFATAL("Short read from '%s'", queue_cur->fname);

  close(fd);

  memcpy(out_buf, in_buf, len);

  subseq_hangs = 0;

  if (skip_deterministic || queue_cur->det_done) goto havoc_stage;

  /******************
   * SIMPLE BITFLIP *
   ******************/

#define FLIP_BIT(_ar, _b) do { _ar[(_b) >> 3] ^= (1 << ((_b) & 7)); } while (0)

  stage_name = "bitflip 1/1";
  stage_max  = len << 3;

  orig_hit_cnt = unique_queued + total_hangs + total_crashes;

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    FLIP_BIT(out_buf, stage_cur);

    if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

    FLIP_BIT(out_buf, stage_cur);

  }

  new_hit_cnt = unique_queued + total_hangs + total_crashes;
  stage_finds[0]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[0] += stage_max;

  stage_name = "bitflip 2/1";
  stage_max  = (len << 3) - 1;

  orig_hit_cnt = new_hit_cnt;

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    FLIP_BIT(out_buf, stage_cur);
    FLIP_BIT(out_buf, stage_cur + 1);

    if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

    FLIP_BIT(out_buf, stage_cur);
    FLIP_BIT(out_buf, stage_cur + 1);

  }

  new_hit_cnt = unique_queued + total_hangs + total_crashes;
  stage_finds[1]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[1] += stage_max;

  stage_name = "bitflip 4/1";
  stage_max  = (len << 3) - 3;

  orig_hit_cnt = new_hit_cnt;

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    FLIP_BIT(out_buf, stage_cur);
    FLIP_BIT(out_buf, stage_cur + 1);
    FLIP_BIT(out_buf, stage_cur + 2);
    FLIP_BIT(out_buf, stage_cur + 3);

    if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

    FLIP_BIT(out_buf, stage_cur);
    FLIP_BIT(out_buf, stage_cur + 1);
    FLIP_BIT(out_buf, stage_cur + 2);
    FLIP_BIT(out_buf, stage_cur + 3);

  }

  new_hit_cnt = unique_queued + total_hangs + total_crashes;
  stage_finds[2]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[2] += stage_max;

  stage_name = "bitflip 8/8";
  stage_max  = len;

  orig_hit_cnt = new_hit_cnt;

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    out_buf[stage_cur] ^= 0xFF;

    if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

    out_buf[stage_cur] ^= 0xFF;

  }

  new_hit_cnt = unique_queued + total_hangs + total_crashes;
  stage_finds[3]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[3] += stage_max;

  stage_name = "bitflip 16/8";
  stage_max  = len - 1;

  orig_hit_cnt = new_hit_cnt;

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    *(u16*)(out_buf + stage_cur) ^= 0xFFFF;

    if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

    *(u16*)(out_buf + stage_cur) ^= 0xFFFF;

  }

  new_hit_cnt = unique_queued + total_hangs + total_crashes;
  stage_finds[4]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[4] += stage_max;

  stage_name = "bitflip 32/8";
  stage_max  = len - 3;

  orig_hit_cnt = new_hit_cnt;

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    *(u32*)(out_buf + stage_cur) ^= 0xFFFFFFFF;

    if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

    *(u32*)(out_buf + stage_cur) ^= 0xFFFFFFFF;

  }

  new_hit_cnt = unique_queued + total_hangs + total_crashes;
  stage_finds[5]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[5] += stage_max;

  /**********************
   * INTERESTING VALUES *
   **********************/

  stage_name = "interest 8/8";
  stage_cur  = 0;
  stage_max  = len * sizeof(interesting_8);

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len; i++) {

    u8 orig = out_buf[i];

    for (j = 0; j < sizeof(interesting_8); j++) {

      out_buf[i] = interesting_8[j];

      if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

      out_buf[i] = orig;
      stage_cur++;

    }

  }

  new_hit_cnt = unique_queued + total_hangs + total_crashes;
  stage_finds[6]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[6] += stage_max;

#define SWAP16(_x) (((_x) << 8) | ((_x) >> 8))

#define SWAP32(_x) (((_x) << 24) | ((_x) >> 24) | \
                    (((_x) << 8) & 0x00FF0000) | \
                    (((_x) >> 8) & 0x0000FF00))

  stage_name = "interest 16/8";
  stage_cur  = 0;
  stage_max  = len * sizeof(interesting_16);

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 1; i++) {

    u16 orig = *(u16*)(out_buf+i);

    for (j = 0; j < sizeof(interesting_16) / 2; j++) {

      *(u16*)(out_buf + i) = interesting_16[j];

      if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
      stage_cur++;

      if (SWAP16(interesting_16[j]) != interesting_16[j]) {

        *(u16*)(out_buf + i) = SWAP16(interesting_16[j]);
        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;


      *(u16*)(out_buf + i) = orig;

    }

  }

  new_hit_cnt = unique_queued + total_hangs + total_crashes;
  stage_finds[7]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[7] += stage_max;

  stage_name = "interest 32/8";
  stage_cur  = 0;
  stage_max  = len * sizeof(interesting_32) / 2;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 3; i++) {

    u32 orig = *(u32*)(out_buf + i);

    for (j = 0; j < sizeof(interesting_32) / 4; j++) {

      *(u32*)(out_buf + i) = interesting_32[j];

      if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
      stage_cur++;

      if (SWAP32(interesting_32[j]) != interesting_32[j]) {

        *(u32*)(out_buf + i) = SWAP32(interesting_32[j]);
        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      *(u32*)(out_buf + i) = orig;

    }

  }

  new_hit_cnt = unique_queued + total_hangs + total_crashes;
  stage_finds[8]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[8] += stage_max;

  /****************
   * RANDOM HAVOC *
   ****************/

havoc_stage:

  queue_cur->det_done = 1;

  stage_name = "havoc";
  stage_max = HAVOC_CYCLES;
  temp_len = len;

  orig_hit_cnt = unique_queued + total_hangs + total_crashes;
 
  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    u32 use_stacking = R(HAVOC_STACKING) + 1;
 
    for (i = 0; i < use_stacking; i++) {

      switch (R(7)) {

        case 0:

          /* Flip a single bit */

          FLIP_BIT(out_buf, R(temp_len << 3));
          break;

        case 1: 

          /* Set byte to interesting value */

          out_buf[R(temp_len)] = interesting_8[R(sizeof(interesting_8))];
          break;

        case 2:

          /* Set word to interesting value */

          if (temp_len < 2) break;

          if (R(2)) {

            *(u16*)(out_buf + R(temp_len - 1)) =
              interesting_16[R(sizeof(interesting_16) >> 1)];

          } else {

            *(u16*)(out_buf + R(temp_len - 1)) = htons(
              interesting_16[R(sizeof(interesting_16) >> 1)]);

          }

          break;

        case 3:

          /* Set dword to interesting value */

          if (temp_len < 4) break;

          if (R(2)) {
  
            *(u32*)(out_buf + R(temp_len - 3)) =
              interesting_32[R(sizeof(interesting_32) >> 2)];

          } else {

            *(u32*)(out_buf + R(temp_len - 3)) = htonl(
              interesting_32[R(sizeof(interesting_32) >> 2)]);

          }

          break;

        case 4:

          /* Just set a random byte to a random value */

          out_buf[R(temp_len)] = R(256);
          break;

        case 5: {

            /* Delete bytes */

            u32 del_from, del_len, max_chunk_len;

            if (temp_len == 1) break;

            /* Don't delete too much. */

            max_chunk_len = MIN((temp_len - 1) * HAVOC_MAX_PERCENT / 100,
                                HAVOC_MAX_BLOCK);

            del_len = 1 + R(max_chunk_len ? max_chunk_len : 1);

            del_from = R(temp_len - del_len + 1);

            memmove(out_buf + del_from, out_buf + del_from + del_len,
                    temp_len - del_from - del_len);

            temp_len -= del_len;
  
            break;

          }

        case 6: {

            /* Clone bytes */

            u32 clone_from, clone_to, clone_len, max_chunk_len;
            u8* new_buf;

            max_chunk_len = MIN(temp_len * HAVOC_MAX_PERCENT / 100,
                                HAVOC_MAX_BLOCK);

            clone_len  = 1 + R(max_chunk_len ? max_chunk_len : 1);

            clone_from = R(temp_len - clone_len + 1);
            clone_to   = R(temp_len);

            new_buf = ck_alloc(temp_len + clone_len);

            /* Head */
            memcpy(new_buf, out_buf, clone_to);

            /* Inserted part */
            memcpy(new_buf + clone_to, out_buf + clone_from, clone_len);

            /* Tail */
            memcpy(new_buf + clone_to + clone_len, out_buf + clone_to,
                   temp_len - clone_to);

            ck_free(out_buf);
            out_buf = new_buf;
            temp_len += clone_len;

            break;

          }

      }

    }

    if (common_fuzz_stuff(argv, out_buf, temp_len))
      goto abandon_entry;

    if (temp_len < len) out_buf = ck_realloc(out_buf, len);
    temp_len = len;
    memcpy(out_buf, in_buf, len);

  }

  new_hit_cnt = unique_queued + total_hangs + total_crashes;
  stage_finds[9]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[9] += stage_max;

  unique_processed++;

abandon_entry:

  ck_free(in_buf);
  ck_free(out_buf);

}


/* Handle stop signal (Ctrl-C, etc). */

static void handle_stop_sig(int sig) {

  stop_soon = 1; 
  if (child_pid > 0) kill(child_pid, SIGKILL);

}


/* Handle timeout. */

static void handle_timeout(int sig) {

  child_timed_out = 1; 
  if (child_pid > 0) kill(child_pid, SIGKILL);

}


/* Configure PRNG. */

static void setup_random(void) {

  u32 seed;
  struct timeval tv;
  struct timezone tz;

  gettimeofday(&tv, &tz);
  seed = tv.tv_sec ^ tv.tv_usec ^ getpid();

  srandom(seed);

  start_time = (tv.tv_sec * 1000L) + (tv.tv_usec / 1000);

}


/* Display usage hints. */

static void usage(u8* argv0) {

  SAYF("\n%s [ options ] -- /path/to/traced_app [ ... ]\n\n"

       "Required parameters:\n\n"

       "  -i dir        - input directory with test cases\n"
       "  -o dir        - output directory for captured crashes\n\n"

       "Execution control settings:\n\n"

       "  -f file       - input filed used by the traced application\n"
       "  -t msec       - timeout for each run (%u ms)\n"
       "  -m megs       - memory limit for child process (%u MB)\n"
      
       "Fuzzing behavior settings:\n\n"

       "  -d            - skip all deterministic fuzzing stages\n"
       "  -k            - keep all discovered test cases\n"
       "  -n            - fuzz non-instrumented binaries (dumb mode)\n\n"

       "For additional tips, please consult the provided documentation.\n\n",

       argv0, EXEC_TIMEOUT, MEM_LIMIT);

  exit(1);

}


/* Prepare output directories. */

static void setup_dirs(void) {

  u8* tmp;

  if (mkdir(out_dir, 0700) && errno != EEXIST)
    PFATAL("Unable to create '%s'", out_dir);

  tmp = alloc_printf("%s/queue", out_dir);

  if (mkdir(tmp, 0700))
    PFATAL("Unable to create '%s' (delete existing directories first)", tmp);

  ck_free(tmp);

  tmp = alloc_printf("%s/crashes", out_dir);

  if (mkdir(tmp, 0700))
    PFATAL("Unable to create '%s' (delete existing directories first)", tmp);

  ck_free(tmp);

  tmp = alloc_printf("%s/hangs", out_dir);

  if (mkdir(tmp, 0700))
    PFATAL("Unable to create '%s' (delete existing directories first)", tmp);

  ck_free(tmp);

}


/* Setup the output file for fuzzed data. */

static void setup_stdio_file(void) {

  u8* fn = alloc_printf("%s/.cur_input", out_dir);

  unlink(fn); /* Ignore errors */

  out_fd = open(fn, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);

  if (out_fd < 0) PFATAL("Unable to create '%s'", fn);

  ck_free(fn);

}


/* Handle screen resize. */

static void handle_resize(int sig) {
  clear_screen = 1;
}



/* Main entry point */

int main(int argc, char** argv) {

  s32 opt;

  SAYF(cCYA "afl-fuzz " cBRI VERSION cNOR " (" __DATE__ " " __TIME__ 
       ") by <lcamtuf@google.com>\n");

  signal(SIGHUP,   handle_stop_sig);
  signal(SIGINT,   handle_stop_sig);
  signal(SIGTERM,  handle_stop_sig);
  signal(SIGALRM,  handle_timeout);
  signal(SIGWINCH, handle_resize);

  signal(SIGTSTP, SIG_IGN);
  signal(SIGPIPE, SIG_IGN);

  while ((opt = getopt(argc,argv,"+i:o:f:m:t:kdn")) > 0)

    switch (opt) {

      case 'i':

        if (in_dir) FATAL("Multiple -i options not supported");
        in_dir = optarg;
        break;

      case 'o': /* output dir */

        if (out_dir) FATAL("Multiple -o options not supported");
        out_dir = optarg;
        break;

      case 'f': /* target file */

        if (out_file) FATAL("Multiple -f options not supported");
        out_file = optarg;
        break;

      case 't':

        exec_tmout = atoi(optarg);
        if (exec_tmout < 20) FATAL("Bad or dangerously low value of -t");
        break;

      case 'm':

        mem_limit = atoi(optarg);
        if (mem_limit < 10) FATAL("Bad or dangerously low value of -m");
        break;

      case 'k':

        keep_testcases = 1;
        break;

      case 'd':

        skip_deterministic = 1;
        break;

      case 'n':

        dumb_mode = 1;
        break;

      default:

        usage(argv[0]);

    }

  if (optind == argc || !in_dir || !out_dir) usage(argv[0]);

  dev_null = open("/dev/null", O_RDWR);
  if (dev_null < 0) PFATAL("Unable to open /dev/null");

  setup_shm();

  setup_dirs();

  read_testcases();

  perform_dry_run(argv + optind);

  if (!stop_soon) {

    setup_random();
    if (!out_file) setup_stdio_file();

  }

  SAYF(TERM_CLEAR);

  while (!stop_soon) {

    if (!queue_cur) {

      queue_cycle++;
      unique_processed  = 0;
      abandoned_inputs  = 0;
      queue_cur = queue;
      show_stats();

    }

    fuzz_one(argv + optind);
    queue_cur = queue_cur->next;

    if (clear_screen) {

      SAYF(TERM_CLEAR);
      show_stats();
      clear_screen = 0;

    }

  }

  show_stats();

  if (stop_soon) SAYF(cLRD "\n+++ Testing aborted by user +++\n" cRST);

  destroy_queue();
  alloc_report();

  OKF("We're done here. Have a nice day!");

  exit(0);

}

