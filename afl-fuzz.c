/*
   american fuzzy lop - fuzzer code
   --------------------------------

   Written and maintained by Michal Zalewski <lcamtuf@google.com>

   Forkserver design by Jann Horn <jannhorn@googlemail.com>

   Copyright 2013, 2014, 2015 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This is the real deal: the program takes an instrumented binary and
   attempts a variety of basic fuzzing tricks, paying close attention to
   how they affect the execution path.

 */

#define AFL_MAIN
#define MESSAGES_TO_STDOUT

#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64

#include "config.h"
#include "types.h"
#include "debug.h"
#include "alloc-inl.h"
#include "hash.h"
#include "enums.h"
#include "afl-fuzz.h"
#include "fuzzing-engine.h"
#include "shm-instr.h"
#include "util.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <dirent.h>
#include <ctype.h>
#include <fcntl.h>
#include <termios.h>
#include <dlfcn.h>

#include <sys/wait.h>
#include <sys/time.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/file.h>

#if defined(__APPLE__) || defined(__FreeBSD__) || defined (__OpenBSD__)
#  include <sys/sysctl.h>
#endif /* __APPLE__ || __FreeBSD__ || __OpenBSD__ */


/* Pointers to G members used for atexit/signal handlers.
   Those are assigned in setup_signal_handlers and before atexit(). */
static s32 *shm_id_ptr, *forksrv_pid_ptr, *child_pid_ptr;
volatile static u8 *stop_soon_ptr, *skip_requested_ptr, *child_timed_out_ptr;
static volatile u8 *clear_screen_ptr;

static void init_G(struct g* G) {
  G->exec_tmout = EXEC_TIMEOUT;
  G->mem_limit = MEM_LIMIT;
  G->stats_update_freq = 1;
  G->bitmap_changed = 1;
  G->dev_urandom_fd = -1;
  G->dev_null_fd = -1;
  G->child_pid = -1;
  G->out_dir_fd = -1;
  G->clear_screen = 1;
  G->havoc_div = 1;
  G->stage_name = "init";
  G->splicing_with = -1;
}


/* Mark deterministic checks as done for a particular queue entry. We use the
   .state file to avoid repeating deterministic fuzzing when resuming aborted
   scans. */

void mark_as_det_done(struct g* G, struct queue_entry* q) {

  u8* fn = strrchr(q->fname, '/');
  s32 fd;

  fn = alloc_printf("%s/queue/.state/deterministic_done/%s", G->out_dir, fn + 1);

  fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0) PFATAL("Unable to create '%s'", fn);
  close(fd);

  ck_free(fn);

  q->passed_det = 1;

}


/* Mark as variable. Create symlinks if possible to make it easier to examine
   the files. */

static void mark_as_variable(struct g* G, struct queue_entry* q) {

  u8 *fn = strrchr(q->fname, '/') + 1, *ldest;

  ldest = alloc_printf("../../%s", fn);
  fn = alloc_printf("%s/queue/.state/variable_behavior/%s", G->out_dir, fn);

  if (symlink(ldest, fn)) {

    s32 fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) PFATAL("Unable to create '%s'", fn);
    close(fd);

  }

  ck_free(ldest);
  ck_free(fn);

  q->var_behavior = 1;

}


/* Mark / unmark as redundant (edge-only). This is not used for restoring state,
   but may be useful for post-processing datasets. */

static void mark_as_redundant(struct g* G, struct queue_entry* q, u8 state) {

  u8* fn;
  s32 fd;

  if (state == q->fs_redundant) return;

  q->fs_redundant = state;

  fn = strrchr(q->fname, '/');
  fn = alloc_printf("%s/queue/.state/redundant_edges/%s", G->out_dir, fn + 1);

  if (state) {

    fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) PFATAL("Unable to create '%s'", fn);
    close(fd);

  } else {

    if (unlink(fn)) PFATAL("Unable to remove '%s'", fn);

  }

  ck_free(fn);

}


/* Append new test case to the queue. */

static void add_to_queue(struct g* G, u8* fname, u32 len, u8 passed_det) {

  struct queue_entry* q = ck_alloc(sizeof(struct queue_entry));

  q->fname        = fname;
  q->len          = len;
  q->depth        = G->cur_depth + 1;
  q->passed_det   = passed_det;

  if (q->depth > G->max_depth) G->max_depth = q->depth;

  if (G->queue_top) {

    G->queue_top->next = q;
    G->queue_top = q;

  } else G->q_prev100 = G->queue = G->queue_top = q;

  G->queued_paths++;
  G->pending_not_fuzzed++;

  if (!(G->queued_paths % 100)) {

    G->q_prev100->next_100 = q;
    G->q_prev100 = q;

  }

  G->last_path_time = get_cur_time();

}


/* Destroy the entire queue. */

static void destroy_queue(struct g* G) {

  struct queue_entry *q = G->queue, *n;

  while (q) {

    n = q->next;
    ck_free(q->fname);
    ck_free(q->trace_mini);
    ck_free(q);
    q = n;

  }

}


/* Write bitmap to file. The bitmap is useful mostly for the secret
   -B option, to focus a separate fuzzing session on a particular
   interesting input without rediscovering all the others. */

static void write_bitmap(struct g* G) {

  u8* fname;
  s32 fd;

  if (!G->bitmap_changed) return;
  G->bitmap_changed = 0;

  fname = alloc_printf("%s/fuzz_bitmap", G->out_dir);
  fd = open(fname, O_WRONLY | O_CREAT | O_TRUNC, 0600);

  if (fd < 0) PFATAL("Unable to open '%s'", fname);

  ck_write(fd, G->virgin_bits, MAP_SIZE, fname);

  close(fd);
  ck_free(fname);

}


/* Read bitmap from file. This is for the -B option again. */

static void read_bitmap(struct g* G, u8* fname) {

  s32 fd = open(fname, O_RDONLY);

  if (fd < 0) PFATAL("Unable to open '%s'", fname);

  ck_read(fd, G->virgin_bits, MAP_SIZE, fname);

  close(fd);

}


/* Check if the current execution path brings anything new to the table.
   Update virgin bits to reflect the finds. Returns 1 if the only change is
   the hit-count for a particular tuple; 2 if there are new tuples seen. 
   Updates the map, so subsequent calls will always return 0.

   This function is called after every exec() on a fairly large buffer, so
   it needs to be fast. We do this in 32-bit and 64-bit flavors. */

#define FFL(_b) (0xffULL << ((_b) << 3))
#define FF(_b)  (0xff << ((_b) << 3))

static inline u8 has_new_bits(struct g* G, u8* virgin_map) {

#ifdef __x86_64__

  u64* current = (u64*)G->trace_bits;
  u64* virgin  = (u64*)virgin_map;

  u32  i = (MAP_SIZE >> 3);

#else

  u32* current = (u32*)G->trace_bits;
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

  if (ret && virgin_map == G->virgin_bits) G->bitmap_changed = 1;

  return ret;

}


/* Count the number of bits set in the provided bitmap. Used for the status
   screen several times every second, does not have to be fast. */

static u32 count_bits(u8* mem) {

  u32* ptr = (u32*)mem;
  u32  i   = (MAP_SIZE >> 2);
  u32  ret = 0;

  while (i--) {

    u32 v = *(ptr++);

    /* This gets called on the inverse, virgin bitmap; optimize for sparse
       data. */

    if (v == 0xffffffff) {
      ret += 32;
      continue;
    }

    v -= ((v >> 1) & 0x55555555);
    v = (v & 0x33333333) + ((v >> 2) & 0x33333333);
    ret += (((v + (v >> 4)) & 0xF0F0F0F) * 0x01010101) >> 24;

  }

  return ret;

}


/* Count the number of bytes set in the bitmap. Called fairly sporadically,
   mostly to update the status screen or calibrate and examine confirmed
   new paths. */

static u32 count_bytes(u8* mem) {

  u32* ptr = (u32*)mem;
  u32  i   = (MAP_SIZE >> 2);
  u32  ret = 0;

  while (i--) {

    u32 v = *(ptr++);

    if (!v) continue;
    if (v & FF(0)) ret++;
    if (v & FF(1)) ret++;
    if (v & FF(2)) ret++;
    if (v & FF(3)) ret++;

  }

  return ret;

}


/* Count the number of non-255 bytes set in the bitmap. Used strictly for the
   status screen, several calls per second or so. */

static u32 count_non_255_bytes(u8* mem) {

  u32* ptr = (u32*)mem;
  u32  i   = (MAP_SIZE >> 2);
  u32  ret = 0;

  while (i--) {

    u32 v = *(ptr++);

    /* This is called on the virgin bitmap, so optimize for the most likely
       case. */

    if (v == 0xffffffff) continue;
    if ((v & FF(0)) != FF(0)) ret++;
    if ((v & FF(1)) != FF(1)) ret++;
    if ((v & FF(2)) != FF(2)) ret++;
    if ((v & FF(3)) != FF(3)) ret++;

  }

  return ret;

}


/* Destructively simplify trace by eliminating hit count information
   and replacing it with 0x80 or 0x01 depending on whether the tuple
   is hit or not. Called on every new crash or hang, should be
   reasonably fast. */

static u8 simplify_lookup[256] = { 
  /*    4 */ 1, 128, 128, 128,
  /*   +4 */ AREP4(128),
  /*   +8 */ AREP8(128),
  /*  +16 */ AREP16(128),
  /*  +32 */ AREP32(128),
  /*  +64 */ AREP64(128),
  /* +128 */ AREP128(128)
};

#ifdef __x86_64__

static void simplify_trace(u64* mem) {

  u32 i = MAP_SIZE >> 3;

  while (i--) {

    /* Optimize for sparse bitmaps. */

    if (*mem) {

      u8* mem8 = (u8*)mem;

      mem8[0] = simplify_lookup[mem8[0]];
      mem8[1] = simplify_lookup[mem8[1]];
      mem8[2] = simplify_lookup[mem8[2]];
      mem8[3] = simplify_lookup[mem8[3]];
      mem8[4] = simplify_lookup[mem8[4]];
      mem8[5] = simplify_lookup[mem8[5]];
      mem8[6] = simplify_lookup[mem8[6]];
      mem8[7] = simplify_lookup[mem8[7]];

    } else *mem = 0x0101010101010101ULL;

    mem++;

  }

}

#else

static void simplify_trace(u32* mem) {

  u32 i = MAP_SIZE >> 2;

  while (i--) {

    /* Optimize for sparse bitmaps. */

    if (*mem) {

      u8* mem8 = (u8*)mem;

      mem8[0] = simplify_lookup[mem8[0]];
      mem8[1] = simplify_lookup[mem8[1]];
      mem8[2] = simplify_lookup[mem8[2]];
      mem8[3] = simplify_lookup[mem8[3]];

    } else *mem = 0x01010101;

    mem++;
  }

}

#endif /* ^__x86_64__ */


/* Get rid of shared memory (atexit handler). */

static void remove_shm(void) {

  shmctl(*shm_id_ptr, IPC_RMID, NULL);

}


/* Compact trace bytes into a smaller bitmap. We effectively just drop the
   count information here. This is called only sporadically, for some
   new paths. */

static void minimize_bits(u8* dst, u8* src) {

  u32 i = 0;

  while (i < MAP_SIZE) {

    if (*(src++)) dst[i >> 3] |= 1 << (i & 7);
    i++;

  }

}


/* When we bump into a new path, we call this to see if the path appears
   more "favorable" than any of the existing ones. The purpose of the
   "favorables" is to have a minimal set of paths that trigger all the bits
   seen in the bitmap so far, and focus on fuzzing them at the expense of
   the rest.

   The first step of the process is to maintain a list of G->top_rated[] entries
   for every byte in the bitmap. We win that slot if there is no previous
   contender, or if the contender has a more favorable speed x size factor. */

void update_bitmap_score(struct g* G, struct queue_entry* q) {

  u32 i;
  u64 fav_factor = q->exec_us * q->len;

  /* For every byte set in G->trace_bits[], see if there is a previous winner,
     and how it compares to us. */

  for (i = 0; i < MAP_SIZE; i++)

    if (G->trace_bits[i]) {

       if (G->top_rated[i]) {

         /* Faster-executing or smaller test cases are favored. */

         if (fav_factor > G->top_rated[i]->exec_us * G->top_rated[i]->len) continue;

         /* Looks like we're going to win. Decrease ref count for the
            previous winner, discard its G->trace_bits[] if necessary. */

         if (!--G->top_rated[i]->tc_ref) {
           ck_free(G->top_rated[i]->trace_mini);
           G->top_rated[i]->trace_mini = 0;
         }

       }

       /* Insert ourselves as the new winner. */

       G->top_rated[i] = q;
       q->tc_ref++;

       if (!q->trace_mini) {
         q->trace_mini = ck_alloc(MAP_SIZE >> 3);
         minimize_bits(q->trace_mini, G->trace_bits);
       }

       G->score_changed = 1;

     }

}


/* The second part of the mechanism discussed above is a routine that
   goes over G->top_rated[] entries, and then sequentially grabs winners for
   previously-unseen bytes (temp_v) and marks them as favored, at least
   until the next run. The favored entries are given more air time during
   all fuzzing steps. */

static void cull_queue(struct g* G) {

  struct queue_entry* q;
  static u8 temp_v[MAP_SIZE >> 3];
  u32 i;

  if (G->dumb_mode || !G->score_changed) return;

  G->score_changed = 0;

  memset(temp_v, 255, MAP_SIZE >> 3);

  G->queued_favored  = 0;
  G->pending_favored = 0;

  q = G->queue;

  while (q) {
    q->favored = 0;
    q = q->next;
  }

  /* Let's see if anything in the bitmap isn't captured in temp_v.
     If yes, and if it has a G->top_rated[] contender, let's use it. */

  for (i = 0; i < MAP_SIZE; i++)
    if (G->top_rated[i] && (temp_v[i >> 3] & (1 << (i & 7)))) {

      u32 j = MAP_SIZE >> 3;

      /* Remove all bits belonging to the current entry from temp_v. */

      while (j--) 
        if (G->top_rated[i]->trace_mini[j])
          temp_v[j] &= ~G->top_rated[i]->trace_mini[j];

      G->top_rated[i]->favored = 1;
      G->queued_favored++;

      if (!G->top_rated[i]->was_fuzzed) G->pending_favored++;

    }

  q = G->queue;

  while (q) {
    mark_as_redundant(G, q, !q->favored);
    q = q->next;
  }

}


/* Configure shared memory and G->virgin_bits. This is called at startup. */

static void setup_shm(struct g* G) {

  u8* shm_str;

  if (!G->in_bitmap) memset(G->virgin_bits, 255, MAP_SIZE);

  memset(G->virgin_hang, 255, MAP_SIZE);
  memset(G->virgin_crash, 255, MAP_SIZE);

  G->shm_id = shmget(IPC_PRIVATE, MAP_SIZE, IPC_CREAT | IPC_EXCL | 0600);

  if (G->shm_id < 0) PFATAL("shmget() failed");

  shm_id_ptr = &G->shm_id;
  atexit(remove_shm);

  shm_str = alloc_printf("%d", G->shm_id);

  /* If somebody is asking us to fuzz instrumented binaries in dumb mode,
     we don't want them to detect instrumentation, since we won't be sending
     fork server commands. This should be replaced with better auto-detection
     later on, perhaps? */

  if (G->dumb_mode != 1)
    setenv(SHM_ENV_VAR, shm_str, 1);

  ck_free(shm_str);

  G->trace_bits = shmat(G->shm_id, NULL, 0);
  
  if (!G->trace_bits) PFATAL("shmat() failed");

}


/* Load postprocessor, if available. */

static void setup_post(struct g* G) {

  void* dh;
  u8* fn = getenv("AFL_POST_LIBRARY");
  u32 tlen = 6;

  if (!fn) return;

  ACTF("Loading postprocessor from '%s'...", fn);

  dh = dlopen(fn, RTLD_NOW);
  if (!dh) FATAL("%s", dlerror());

  G->post_handler = dlsym(dh, "afl_postprocess");
  if (!G->post_handler) FATAL("Symbol 'afl_postprocess' not found.");

  /* Do a quick test. It's better to segfault now than later =) */

  G->post_handler("hello", &tlen);

  OKF("Postprocessor installed successfully.");

}


/* Read all testcases from the input directory, then queue them for testing.
   Called at startup. */

static void read_testcases(struct g* G) {

  struct dirent **nl;
  s32 nl_cnt;
  u32 i;
  u8* fn;

  /* Auto-detect non-in-place resumption attempts. */

  fn = alloc_printf("%s/queue", G->in_dir);
  if (!access(fn, F_OK)) G->in_dir = fn; else ck_free(fn);

  ACTF("Scanning '%s'...", G->in_dir);

  /* We use scandir() + alphasort() rather than readdir() because otherwise,
     the ordering  of test cases would vary somewhat randomly and would be
     difficult to control. */

  nl_cnt = scandir(G->in_dir, &nl, NULL, alphasort);

  if (nl_cnt < 0) {

    if (errno == ENOENT || errno == ENOTDIR)

      SAYF("\n" cLRD "[-] " cRST
           "The input directory does not seem to be valid - try again. The fuzzer needs\n"
           "    one or more test case to start with - ideally, a small file under 1 kB\n"
           "    or so. The cases must be stored as regular files directly in the input\n"
           "    directory.\n");

    PFATAL("Unable to open '%s'", G->in_dir);

  }

  for (i = 0; i < nl_cnt; i++) {

    struct stat st;

    u8* fn = alloc_printf("%s/%s", G->in_dir, nl[i]->d_name);
    u8* dfn = alloc_printf("%s/.state/deterministic_done/%s", G->in_dir, nl[i]->d_name);

    u8  passed_det = 0;

    free(nl[i]); /* not tracked */
 
    if (lstat(fn, &st) || access(fn, R_OK))
      PFATAL("Unable to access '%s'", fn);

    /* This also takes care of . and .. */

    if (!S_ISREG(st.st_mode) || !st.st_size || strstr(fn, "/README.txt")) {

      ck_free(fn);
      ck_free(dfn);
      continue;

    }

    if (st.st_size > MAX_FILE) 
      FATAL("Test case '%s' is too big (%s, limit is %s)", fn,
            DMS(st.st_size), DMS(MAX_FILE));

    /* Check for metadata that indicates that deterministic fuzzing
       is complete for this entry. We don't want to repeat deterministic
       fuzzing when resuming aborted scans, because it would be pointless
       and probably very time-consuming. */

    if (!access(dfn, F_OK)) passed_det = 1;
    ck_free(dfn);

    add_to_queue(G, fn, st.st_size, passed_det);

  }

  free(nl); /* not tracked */

  if (!G->queued_paths) {

    SAYF("\n" cLRD "[-] " cRST
         "Looks like there are no valid test cases in the input directory! The fuzzer\n"
         "    needs one or more test case to start with - ideally, a small file under\n"
         "    1 kB or so. The cases must be stored as regular files directly in the\n"
         "    input directory.\n");

    FATAL("No usable test cases in '%s'", G->in_dir);

  }

  G->last_path_time = 0;
  G->queued_at_start = G->queued_paths;

}


/* Helper function for load_extras. */

int compare_extras_len(const void* p1, const void* p2) {
  struct extra_data *e1 = (struct extra_data*)p1,
                    *e2 = (struct extra_data*)p2;

  return e1->len - e2->len;
}


/* Read G->extras from a file, sort by size. */

static void load_extras_file(struct g* G, u8* fname, u32* min_len,
                             u32* max_len, u32 dict_level) {

  FILE* f;
  u8  buf[MAX_LINE];
  u8  *lptr;
  u32 cur_line = 0;

  f = fopen(fname, "r");

  if (!f) PFATAL("Unable to open '%s'", fname);

  while ((lptr = fgets(buf, MAX_LINE, f))) {

    u8 *rptr, *wptr;
    u32 klen = 0;

    cur_line++;

    /* Trim on left and right. */

    while (isspace(*lptr)) lptr++;

    rptr = lptr + strlen(lptr) - 1;
    while (rptr >= lptr && isspace(*rptr)) rptr--;
    rptr++;
    *rptr = 0;

    /* Skip empty lines and comments. */

    if (!*lptr || *lptr == '#') continue;

    /* All other lines must end with '"', which we can consume. */

    rptr--;

    if (rptr < lptr || *rptr != '"')
      FATAL("Malformed name=\"value\" pair in line %u.", cur_line);

    *rptr = 0;

    /* Skip alphanumerics and dashes (label). */

    while (isalnum(*lptr) || *lptr == '_') lptr++;

    /* If @number follows, parse that. */

    if (*lptr == '@') {

      lptr++;
      if (atoi(lptr) > dict_level) continue;
      while (isdigit(*lptr)) lptr++;

    }

    /* Skip whitespace and = signs. */

    while (isspace(*lptr) || *lptr == '=') lptr++;

    /* Consume opening '"'. */

    if (*lptr != '"')
      FATAL("Malformed name=\"keyword\" pair in line %u.", cur_line);

    lptr++;

    if (!*lptr) FATAL("Empty keyword in line %u.", cur_line);

    /* Okay, let's allocate memory and copy data between "...", handling
       \xNN escaping, \\, and \". */

    G->extras = ck_realloc_block(G->extras, (G->extras_cnt + 1) *
               sizeof(struct extra_data));

    wptr = G->extras[G->extras_cnt].data = ck_alloc(rptr - lptr);

    while (*lptr) {

      char* hexdigits = "0123456789abcdef";

      switch (*lptr) {

        case 1 ... 31:
        case 128 ... 255:
          FATAL("Non-printable characters in line %u.", cur_line);

        case '\\':

          lptr++;

          if (*lptr == '\\' || *lptr == '"') {
            *(wptr++) = *(lptr++);
            klen++;
            break;
          }

          if (*lptr != 'x' || !isxdigit(lptr[1]) || !isxdigit(lptr[2]))
            FATAL("Invalid escaping (not \\xNN) in line %u.", cur_line);

          *(wptr++) =
            ((strchr(hexdigits, tolower(lptr[1])) - hexdigits) << 4) |
            (strchr(hexdigits, tolower(lptr[2])) - hexdigits);

          lptr += 3;
          klen++;

          break;

        default:

          *(wptr++) = *(lptr++);
          klen++;

      }

    }

    G->extras[G->extras_cnt].len = klen;

    if (G->extras[G->extras_cnt].len > MAX_DICT_FILE)
      FATAL("Keyword too big in line %u (%s, limit is %s)", cur_line,
            DMS(klen), DMS(MAX_DICT_FILE));

    if (*min_len > klen) *min_len = klen;
    if (*max_len < klen) *max_len = klen;

    G->extras_cnt++;

  }

  fclose(f);

}


/* Read G->extras from the G->extras directory and sort them by size. */

static void load_extras(struct g* G, u8* dir) {

  DIR* d;
  struct dirent* de;
  u32 min_len = MAX_DICT_FILE, max_len = 0, dict_level = 0;
  u8* x;

  /* If the name ends with @, extract level and continue. */

  if ((x = strchr(dir, '@'))) {

    *x = 0;
    dict_level = atoi(x + 1);

  }

  ACTF("Loading extra dictionary from '%s' (level %u)...", dir, dict_level);

  d = opendir(dir);

  if (!d) {

    if (errno == ENOTDIR) {
      load_extras_file(G, dir, &min_len, &max_len, dict_level);
      goto check_and_sort;
    }

    PFATAL("Unable to open '%s'", dir);

  }

  if (x) FATAL("Dictinary levels not supported for directories.");

  while ((de = readdir(d))) {

    struct stat st;
    u8* fn = alloc_printf("%s/%s", dir, de->d_name);
    s32 fd;

    if (lstat(fn, &st) || access(fn, R_OK))
      PFATAL("Unable to access '%s'", fn);

    /* This also takes care of . and .. */
    if (!S_ISREG(st.st_mode) || !st.st_size) {

      ck_free(fn);
      continue;

    }

    if (st.st_size > MAX_DICT_FILE)
      FATAL("Extra '%s' is too big (%s, limit is %s)", fn,
            DMS(st.st_size), DMS(MAX_DICT_FILE));

    if (min_len > st.st_size) min_len = st.st_size;
    if (max_len < st.st_size) max_len = st.st_size;

    G->extras = ck_realloc_block(G->extras, (G->extras_cnt + 1) *
               sizeof(struct extra_data));

    G->extras[G->extras_cnt].data = ck_alloc(st.st_size);
    G->extras[G->extras_cnt].len  = st.st_size;

    fd = open(fn, O_RDONLY);

    if (fd < 0) PFATAL("Unable to open '%s'", fn);

    ck_read(fd, G->extras[G->extras_cnt].data, st.st_size, fn);

    close(fd);
    ck_free(fn);

    G->extras_cnt++;

  }

  closedir(d);

check_and_sort:

  if (!G->extras_cnt) FATAL("No usable files in '%s'", dir);

  qsort(G->extras, G->extras_cnt, sizeof(struct extra_data), compare_extras_len);

  OKF("Loaded %u extra tokens, size range %s to %s.", G->extras_cnt,
      DMS(min_len), DMS(max_len));

  if (max_len > 32)
    WARNF("Some tokens are relatively large (%s) - consider trimming.",
          DMS(max_len));

  if (G->extras_cnt > MAX_DET_EXTRAS)
    WARNF("More than %u tokens - will use them probabilistically.",
          MAX_DET_EXTRAS);

}





/* Maybe add automatic extra. */


/* Save automatically generated G->extras. */

static void save_auto(struct g* G) {

  u32 i;

  if (!G->auto_changed) return;
  G->auto_changed = 0;

  for (i = 0; i < MIN(USE_AUTO_EXTRAS, G->a_extras_cnt); i++) {

    u8* fn = alloc_printf("%s/queue/.state/auto_extras/auto_%06u", G->out_dir, i);
    s32 fd;

    fd = open(fn, O_WRONLY | O_CREAT | O_TRUNC, 0600);

    if (fd < 0) PFATAL("Unable to create '%s'", fn);

    ck_write(fd, G->a_extras[i].data, G->a_extras[i].len, fn);

    close(fd);
    ck_free(fn);

  }

}


/* Load automatically generated G->extras. */

static void load_auto(struct g* G) {

  u32 i;

  for (i = 0; i < USE_AUTO_EXTRAS; i++) {

    u8  tmp[MAX_AUTO_EXTRA + 1];
    u8* fn = alloc_printf("%s/.state/auto_extras/auto_%06u", G->in_dir, i);
    s32 fd, len;

    fd = open(fn, O_RDONLY, 0600);

    if (fd < 0) {

      if (errno != ENOENT) PFATAL("Unable to open '%s'", fn);
      ck_free(fn);
      break;

    }

    /* We read one byte more to cheaply detect tokens that are too
       long (and skip them). */

    len = read(fd, tmp, MAX_AUTO_EXTRA + 1);

    if (len < 0) PFATAL("Unable to read from '%s'", fn);

    if (len >= MIN_AUTO_EXTRA && len <= MAX_AUTO_EXTRA)
      maybe_add_auto(G, tmp, len);

    close(fd);
    ck_free(fn);

  }

  if (i) OKF("Loaded %u auto-discovered dictionary tokens.", i);
  else OKF("No auto-generated dictionary tokens to reuse.");

}


/* Destroy G->extras. */

static void destroy_extras(struct g* G) {

  u32 i;

  for (i = 0; i < G->extras_cnt; i++) 
    ck_free(G->extras[i].data);

  ck_free(G->extras);

  for (i = 0; i < G->a_extras_cnt; i++) 
    ck_free(G->a_extras[i].data);

  ck_free(G->a_extras);

}


/* Spin up fork server (instrumented mode only). The idea is explained here:

   http://lcamtuf.blogspot.com/2014/10/fuzzing-binaries-without-execve.html

   In essence, the instrumentation allows us to skip execve(), and just keep
   cloning a stopped child. So, we just execute once, and then send commands
   through a pipe. The other part of this logic is in afl-as.h. */

static void init_forkserver(struct g* G, char** argv) {

  static struct itimerval it;
  int st_pipe[2], ctl_pipe[2];
  int status;
  s32 rlen;

  ACTF("Spinning up the fork server...");

  if (pipe(st_pipe) || pipe(ctl_pipe)) PFATAL("pipe() failed");

  G->forksrv_pid = fork();

  if (G->forksrv_pid < 0) PFATAL("fork() failed");

  if (!G->forksrv_pid) {

    struct rlimit r;

    /* Umpf. On OpenBSD, the default fd limit for root users is set to
       soft 128. Let's try to fix that... */

    if (!getrlimit(RLIMIT_NOFILE, &r) && r.rlim_cur < FORKSRV_FD + 2) {

      r.rlim_cur = FORKSRV_FD + 2;
      setrlimit(RLIMIT_NOFILE, &r); /* Ignore errors */

    }

    if (G->mem_limit) {

      r.rlim_max = r.rlim_cur = ((rlim_t)G->mem_limit) << 20;

#ifdef RLIMIT_AS

      setrlimit(RLIMIT_AS, &r); /* Ignore errors */

#else

      /* This takes care of OpenBSD, which doesn't have RLIMIT_AS, but
         according to reliable sources, RLIMIT_DATA covers anonymous
         maps - so we should be getting good protection against OOM bugs. */

      setrlimit(RLIMIT_DATA, &r); /* Ignore errors */

#endif /* ^RLIMIT_AS */


    }

    /* Dumping cores is slow and can lead to anomalies if SIGKILL is delivered
       before the dump is complete. */

    r.rlim_max = r.rlim_cur = 0;

    setrlimit(RLIMIT_CORE, &r); /* Ignore errors */

    /* Isolate the process and configure standard descriptors. If G->out_file is
       specified, stdin is /dev/null; otherwise, G->out_fd is cloned instead. */

    setsid();

    dup2(G->dev_null_fd, 1);
    dup2(G->dev_null_fd, 2);

    if (G->out_file) {

      dup2(G->dev_null_fd, 0);

    } else {

      dup2(G->out_fd, 0);
      close(G->out_fd);

    }

    /* Set up control and status pipes, close the unneeded original fds. */

    if (dup2(ctl_pipe[0], FORKSRV_FD) < 0) PFATAL("dup2() failed");
    if (dup2(st_pipe[1], FORKSRV_FD + 1) < 0) PFATAL("dup2() failed");

    close(ctl_pipe[0]);
    close(ctl_pipe[1]);
    close(st_pipe[0]);
    close(st_pipe[1]);

    close(G->out_dir_fd);
    close(G->dev_null_fd);
    close(G->dev_urandom_fd);
    close(fileno(G->plot_file));

    /* This should improve performance a bit, since it stops the linker from
       doing extra work post-fork(). */

    if (!getenv("LD_BIND_LAZY")) setenv("LD_BIND_NOW", "1", 0);

    /* Set sane defaults for ASAN if nothing else specified. */

    setenv("ASAN_OPTIONS", "abort_on_error=1:"
                           "detect_leaks=0:"
                           "allocator_may_return_null=1", 0);

    /* MSAN is tricky, because it doesn't support abort_on_error=1 at this
       point. So, we do this in a very hacky way. */

    setenv("MSAN_OPTIONS", "exit_code=" STRINGIFY(MSAN_ERROR) ":"
                           "msan_track_origins=0", 0);

    execv(G->target_path, argv);

    /* Use a distinctive bitmap signature to tell the parent about execv()
       falling through. */

    *(u32*)G->trace_bits = EXEC_FAIL_SIG;
    exit(0);

  }

  /* Close the unneeded endpoints. */

  close(ctl_pipe[0]);
  close(st_pipe[1]);

  G->fsrv_ctl_fd = ctl_pipe[1];
  G->fsrv_st_fd  = st_pipe[0];

  /* Wait for the fork server to come up, but don't wait too long. */

  it.it_value.tv_sec = ((G->exec_tmout * FORK_WAIT_MULT) / 1000);
  it.it_value.tv_usec = ((G->exec_tmout * FORK_WAIT_MULT) % 1000) * 1000;

  setitimer(ITIMER_REAL, &it, NULL);

  rlen = read(G->fsrv_st_fd, &status, 4);

  it.it_value.tv_sec = 0;
  it.it_value.tv_usec = 0;

  setitimer(ITIMER_REAL, &it, NULL);

  /* If we have a four-byte "hello" message from the server, we're all set.
     Otherwise, try to figure out what went wrong. */

  if (rlen == 4) {
    OKF("All right - fork server is up.");
    return;
  }

  if (G->child_timed_out)
    FATAL("Timeout while initializing fork server (adjusting -t may help)");

  if (waitpid(G->forksrv_pid, &status, 0) <= 0)
    PFATAL("waitpid() failed");

  if (WIFSIGNALED(status)) {

    if (G->mem_limit && G->mem_limit < 500 && G->uses_asan) {

      SAYF("\n" cLRD "[-] " cRST
           "Whoops, the target binary crashed suddenly, before receiving any input\n"
           "    from the fuzzer! Since it seems to be built with ASAN and you have a\n"
           "    restrictive memory limit configured, this is expected; please read\n"
           "    %s/notes_for_asan.txt for help.\n", G->doc_path);

    } else if (!G->mem_limit) {

      SAYF("\n" cLRD "[-] " cRST
           "Whoops, the target binary crashed suddenly, before receiving any input\n"
           "    from the fuzzer! There are several probable explanations:\n\n"

           "    - The binary is just buggy and explodes entirely on its own. If so, you\n"
           "      need to fix the underlying problem or find a better replacement.\n\n"

#ifdef __APPLE__

           "    - On MacOS X, the semantics of fork() syscalls are non-standard and may\n"
           "      break afl-fuzz performance optimizations when running platform-specific\n"
           "      targets. To fix this, set AFL_NO_FORKSRV=1 in the environment.\n\n"

#endif /* __APPLE__ */

           "    - Less likely, there is a horrible bug in the fuzzer. If other options\n"
           "      fail, poke <lcamtuf@coredump.cx> for troubleshooting tips.\n");

    } else {

      SAYF("\n" cLRD "[-] " cRST
           "Whoops, the target binary crashed suddenly, before receiving any input\n"
           "    from the fuzzer! There are several probable explanations:\n\n"

           "    - The current memory limit (%s) is too restrictive, causing the\n"
           "      target to hit an OOM condition in the dynamic linker. Try bumping up\n"
           "      the limit with the -m setting in the command line. A simple way confirm\n"
           "      this diagnosis would be:\n\n"

#ifdef RLIMIT_AS
           "      ( ulimit -Sv $[%llu << 10]; /path/to/fuzzed_app )\n\n"
#else
           "      ( ulimit -Sd $[%llu << 10]; /path/to/fuzzed_app )\n\n"
#endif /* ^RLIMIT_AS */

           "      Tip: you can use http://jwilk.net/software/recidivm to quickly\n"
           "      estimate the required amount of virtual memory for the binary.\n\n"

           "    - The binary is just buggy and explodes entirely on its own. If so, you\n"
           "      need to fix the underlying problem or find a better replacement.\n\n"

#ifdef __APPLE__

           "    - On MacOS X, the semantics of fork() syscalls are non-standard and may\n"
           "      break afl-fuzz performance optimizations when running platform-specific\n"
           "      targets. To fix this, set AFL_NO_FORKSRV=1 in the environment.\n\n"

#endif /* __APPLE__ */

           "    - Less likely, there is a horrible bug in the fuzzer. If other options\n"
           "      fail, poke <lcamtuf@coredump.cx> for troubleshooting tips.\n",
           DMS(G->mem_limit << 20), G->mem_limit - 1);

    }

    FATAL("Fork server crashed with signal %d", WTERMSIG(status));

  }

  if (*(u32*)G->trace_bits == EXEC_FAIL_SIG)
    FATAL("Unable to execute target application ('%s')", argv[0]);

  if (G->mem_limit && G->mem_limit < 500 && G->uses_asan) {

    SAYF("\n" cLRD "[-] " cRST
           "Hmm, looks like the target binary terminated before we could complete a\n"
           "    handshake with the injected code. Since it seems to be built with ASAN and\n"
           "    you have a restrictive memory limit configured, this is expected; please\n"
           "    read %s/notes_for_asan.txt for help.\n", G->doc_path);

  } else if (!G->mem_limit) {

    SAYF("\n" cLRD "[-] " cRST
         "Hmm, looks like the target binary terminated before we could complete a\n"
         "    handshake with the injected code. Perhaps there is a horrible bug in the\n"
         "    fuzzer. Poke <lcamtuf@coredump.cx> for troubleshooting tips.\n");

  } else {

    SAYF("\n" cLRD "[-] " cRST
         "Hmm, looks like the target binary terminated before we could complete a\n"
         "    handshake with the injected code. There are %s probable explanations:\n\n"

         "%s"
         "    - The current memory limit (%s) is too restrictive, causing an OOM\n"
         "      fault in the dynamic linker. This can be fixed with the -m option. A\n"
         "      simple way to confirm the diagnosis may be:\n\n"

#ifdef RLIMIT_AS
         "      ( ulimit -Sv $[%llu << 10]; /path/to/fuzzed_app )\n\n"
#else
         "      ( ulimit -Sd $[%llu << 10]; /path/to/fuzzed_app )\n\n"
#endif /* ^RLIMIT_AS */

         "      Tip: you can use http://jwilk.net/software/recidivm to quickly\n"
         "      estimate the required amount of virtual memory for the binary.\n\n"

         "    - Less likely, there is a horrible bug in the fuzzer. If other options\n"
         "      fail, poke <lcamtuf@coredump.cx> for troubleshooting tips.\n",
         getenv("AFL_DEFER_FORKSRV") ? "three" : "two",
         getenv("AFL_DEFER_FORKSRV") ?
         "    - You are using AFL_DEFER_FORKSRV, but __afl_manual_init() is never\n"
         "      reached before the program terminates.\n\n" : "",
         DMS(G->mem_limit << 20), G->mem_limit - 1);

  }

  FATAL("Fork server handshake failed");

}



/* Write modified data to file for testing. If G->out_file is set, the old file
   is unlinked and a new one is created. Otherwise, G->out_fd is rewound and
   truncated. */

void write_to_testcase(struct g* G, void* mem, u32 len) {

  s32 fd = G->out_fd;

  if (G->out_file) {

    unlink(G->out_file); /* Ignore errors. */

    fd = open(G->out_file, O_WRONLY | O_CREAT | O_EXCL, 0600);

    if (fd < 0) PFATAL("Unable to create '%s'", G->out_file);

  } else lseek(fd, 0, SEEK_SET);

  ck_write(fd, mem, len, G->out_file);

  if (!G->out_file) {

    if (ftruncate(fd, len)) PFATAL("ftruncate() failed");
    lseek(fd, 0, SEEK_SET);

  } else close(fd);

}


/* Calibrate a new test case. This is done when processing the input directory
   to warn about flaky or otherwise problematic test cases early on; and when
   new paths are discovered to detect variable behavior and so on. */

u8 calibrate_case(struct g* G, char** argv, struct queue_entry* q,
                  u8* use_mem, u32 handicap, u8 from_queue) {

  u8  fault = 0, new_bits = 0, var_detected = 0, first_run = (q->exec_cksum == 0);
  u64 start_us, stop_us;

  s32 old_sc = G->stage_cur, old_sm = G->stage_max, old_tmout = G->exec_tmout;
  u8* old_sn = G->stage_name;

  /* Be a bit more generous about timeouts when resuming sessions, or when
     trying to calibrate already-added finds. This helps avoid trouble due
     to intermittent latency. */

  if (!from_queue || G->resuming_fuzz)
    G->exec_tmout = MAX(G->exec_tmout + CAL_TMOUT_ADD,
                     G->exec_tmout * CAL_TMOUT_PERC / 100);

  q->cal_failed++;

  G->stage_name = "calibration";
  G->stage_max  = G->no_var_check ? CAL_CYCLES_NO_VAR : CAL_CYCLES;

  /* Make sure the forkserver is up before we do anything, and let's not
     count its spin-up time toward binary calibration. */

  if (G->dumb_mode != 1 && !G->no_forkserver && !G->forksrv_pid)
    init_forkserver(G, argv);

  start_us = get_cur_time_us();

  for (G->stage_cur = 0; G->stage_cur < G->stage_max; G->stage_cur++) {

    u32 cksum;

    if (!first_run && !(G->stage_cur % G->stats_update_freq)) show_stats(G);

    write_to_testcase(G, use_mem, q->len);

    fault = run_target(G, argv, &G->kill_signal, &G->total_execs,
                       &G->stop_soon, &G->child_timed_out, &G->child_pid,
                       G->trace_bits);

    /* G->stop_soon is set by the handler for Ctrl+C. When it's pressed,
       we want to bail out quickly. */

    if (G->stop_soon || fault != G->crash_mode) goto abort_calibration;

    if (!G->dumb_mode && !G->stage_cur && !count_bytes(G->trace_bits)) {
      fault = FAULT_NOINST;
      goto abort_calibration;
    }

    cksum = hash32(G->trace_bits, MAP_SIZE, HASH_CONST);

    if (q->exec_cksum != cksum) {

      u8 hnb = has_new_bits(G, G->virgin_bits);
      if (hnb > new_bits) new_bits = hnb;

      if (!G->no_var_check && q->exec_cksum) {

        var_detected = 1;
        G->stage_max    = CAL_CYCLES_LONG;

      } else q->exec_cksum = cksum;

    }

  }

  stop_us = get_cur_time_us();

  G->total_cal_us     += stop_us - start_us;
  G->total_cal_cycles += G->stage_max;

  /* OK, let's collect some stats about the performance of this test case.
     This is used for fuzzing air time calculations in calculate_score(). */

  q->exec_us     = (stop_us - start_us) / G->stage_max;
  q->bitmap_size = count_bytes(G->trace_bits);
  q->handicap    = handicap;
  q->cal_failed  = 0;

  G->total_bitmap_size += q->bitmap_size;
  G->total_bitmap_entries++;

  update_bitmap_score(G, q);

  /* If this case didn't result in new output from the instrumentation, tell
     parent. This is a non-critical problem, but something to warn the user
     about. */

  if (!G->dumb_mode && first_run && !fault && !new_bits) fault = FAULT_NOBITS;

abort_calibration:

  if (new_bits == 2 && !q->has_new_cov) {
    q->has_new_cov = 1;
    G->queued_with_cov++;
  }

  /* Mark variable paths. */

  if (var_detected && !q->var_behavior) {
    mark_as_variable(G, q);
    G->queued_variable++;
  }

  G->stage_name = old_sn;
  G->stage_cur  = old_sc;
  G->stage_max  = old_sm;
  G->exec_tmout = old_tmout;

  if (!first_run) show_stats(G);

  return fault;

}


/* Examine map coverage. Called once, for first test case. */

static void check_map_coverage(struct g* G) {

  u32 i;

  if (count_bytes(G->trace_bits) < 100) return;

  for (i = (1 << (MAP_SIZE_POW2 - 1)); i < MAP_SIZE; i++)
    if (G->trace_bits[i]) return;

  WARNF("Recompile binary with newer version of afl to improve coverage!");

}


/* Perform dry run of all test cases to confirm that the app is working as
   expected. This is done only for the initial inputs, and only once. */

static void perform_dry_run(struct g* G, char** argv) {

  struct queue_entry* q = G->queue;
  u32 cal_failures = 0;
  u8* skip_crashes = getenv("AFL_SKIP_CRASHES");

  while (q) {

    u8* use_mem;
    u8  res;
    s32 fd;

    u8* fn = strrchr(q->fname, '/') + 1;

    ACTF("Attempting dry run with '%s'...", fn);

    fd = open(q->fname, O_RDONLY);
    if (fd < 0) PFATAL("Unable to open '%s'", q->fname);

    use_mem = ck_alloc_nozero(q->len);

    if (read(fd, use_mem, q->len) != q->len)
      FATAL("Short read from '%s'", q->fname);

    close(fd);

    res = calibrate_case(G, argv, q, use_mem, 0, 1);
    ck_free(use_mem);

    if (G->stop_soon) return;

    if (res == G->crash_mode || res == FAULT_NOBITS)
      SAYF(cGRA "    len = %u, map size = %u, exec speed = %llu us\n" cRST, 
           q->len, q->bitmap_size, q->exec_us);

    switch (res) {

      case FAULT_NONE:

        if (q == G->queue) check_map_coverage(G);

        if (G->crash_mode) FATAL("Test case '%s' does *NOT* crash", fn);

        break;

      case FAULT_HANG:

        if (G->timeout_given) {

          /* The -t nn+ syntax in the command line sets G->timeout_given to '2' and
             instructs afl-fuzz to tolerate but skip queue entries that time
             out. */

          if (G->timeout_given > 1) {
            WARNF("Test case results in a hang (skipping)");
            q->cal_failed = CAL_CHANCES;
            cal_failures++;
            break;
          }

          SAYF("\n" cLRD "[-] " cRST
               "The program took more than %u ms to process one of the initial test cases.\n"
               "    Usually, the right thing to do is to relax the -t option - or to delete it\n"
               "    altogether and allow the fuzzer to auto-calibrate. That said, if you know\n"
               "    what you are doing and want to simply skip the unruly test cases, append\n"
               "    '+' at the end of the value passed to -t ('-t %u+').\n", G->exec_tmout,
               G->exec_tmout);

          FATAL("Test case '%s' results in a hang", fn);

        } else {

          SAYF("\n" cLRD "[-] " cRST
               "The program took more than %u ms to process one of the initial test cases.\n"
               "    This is bad news; raising the limit with the -t option is possible, but\n"
               "    will probably make the fuzzing process extremely slow.\n\n"

               "    If this test case is just a fluke, the other option is to just avoid it\n"
               "    altogether, and find one that is less of a CPU hog.\n", G->exec_tmout);

          FATAL("Test case '%s' results in a hang", fn);

        }

      case FAULT_CRASH:  

        if (G->crash_mode) break;

        if (skip_crashes) {
          WARNF("Test case results in a crash (skipping)");
          q->cal_failed = CAL_CHANCES;
          cal_failures++;
          break;
        }

        if (G->mem_limit) {

          SAYF("\n" cLRD "[-] " cRST
               "Oops, the program crashed with one of the test cases provided. There are\n"
               "    several possible explanations:\n\n"

               "    - The test case causes known crashes under normal working conditions. If\n"
               "      so, please remove it. The fuzzer should be seeded with interesting\n"
               "      inputs - but not ones that cause an outright crash.\n\n"

               "    - The current memory limit (%s) is too low for this program, causing\n"
               "      it to die due to OOM when parsing valid files. To fix this, try\n"
               "      bumping it up with the -m setting in the command line. If in doubt,\n"
               "      try something along the lines of:\n\n"

#ifdef RLIMIT_AS
               "      ( ulimit -Sv $[%llu << 10]; /path/to/binary [...] <testcase )\n\n"
#else
               "      ( ulimit -Sd $[%llu << 10]; /path/to/binary [...] <testcase )\n\n"
#endif /* ^RLIMIT_AS */

               "      Tip: you can use http://jwilk.net/software/recidivm to quickly\n"
               "      estimate the required amount of virtual memory for the binary. Also,\n"
               "      if you are using ASAN, see %s/notes_for_asan.txt.\n\n"

#ifdef __APPLE__
  
               "    - On MacOS X, the semantics of fork() syscalls are non-standard and may\n"
               "      break afl-fuzz performance optimizations when running platform-specific\n"
               "      binaries. To fix this, set AFL_NO_FORKSRV=1 in the environment.\n\n"

#endif /* __APPLE__ */

               "    - Least likely, there is a horrible bug in the fuzzer. If other options\n"
               "      fail, poke <lcamtuf@coredump.cx> for troubleshooting tips.\n",
               DMS(G->mem_limit << 20), G->mem_limit - 1, G->doc_path);

        } else {

          SAYF("\n" cLRD "[-] " cRST
               "Oops, the program crashed with one of the test cases provided. There are\n"
               "    several possible explanations:\n\n"

               "    - The test case causes known crashes under normal working conditions. If\n"
               "      so, please remove it. The fuzzer should be seeded with interesting\n"
               "      inputs - but not ones that cause an outright crash.\n\n"

#ifdef __APPLE__
  
               "    - On MacOS X, the semantics of fork() syscalls are non-standard and may\n"
               "      break afl-fuzz performance optimizations when running platform-specific\n"
               "      binaries. To fix this, set AFL_NO_FORKSRV=1 in the environment.\n\n"

#endif /* __APPLE__ */

               "    - Least likely, there is a horrible bug in the fuzzer. If other options\n"
               "      fail, poke <lcamtuf@coredump.cx> for troubleshooting tips.\n");

        }

        FATAL("Test case '%s' results in a crash", fn);

      case FAULT_ERROR:

        FATAL("Unable to execute target application ('%s')", argv[0]);

      case FAULT_NOINST:

        FATAL("No instrumentation detected");

      case FAULT_NOBITS: 

        G->useless_at_start++;

        if (!G->in_bitmap)
          WARNF("No new instrumentation output, test case may be useless.");

        break;

    }

    if (q->var_behavior) WARNF("Instrumentation output varies across runs.");

    q = q->next;

  }

  if (cal_failures) {

    if (cal_failures == G->queued_paths)
      FATAL("All test cases time out%s, giving up!",
            skip_crashes ? " or crash" : "");

    WARNF("Skipped %u test cases (%0.02f%%) due to timeouts%s.", cal_failures,
          ((double)cal_failures) * 100 / G->queued_paths,
          skip_crashes ? " or crashes" : "");

    if (cal_failures * 5 > G->queued_paths)
      WARNF(cLRD "High percentage of rejected test cases, check settings!");

  }

  OKF("All test cases processed.");

}


/* Helper function: link() if possible, copy otherwise. */

static void link_or_copy(u8* old_path, u8* new_path) {

  s32 i = link(old_path, new_path);
  s32 sfd, dfd;
  u8* tmp;

  if (!i) return;

  sfd = open(old_path, O_RDONLY);
  if (sfd < 0) PFATAL("Unable to open '%s'", old_path);

  dfd = open(new_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (dfd < 0) PFATAL("Unable to create '%s'", new_path);

  tmp = ck_alloc(64 * 1024);

  while ((i = read(sfd, tmp, 64 * 1024)) > 0) 
    ck_write(dfd, tmp, i, new_path);

  if (i < 0) PFATAL("read() failed");

  ck_free(tmp);
  close(sfd);
  close(dfd);

}


static void nuke_resume_dir(struct g* G);

/* Create hard links for input test cases in the output directory, choosing
   good names and pivoting accordingly. */

static void pivot_inputs(struct g* G) {

  struct queue_entry* q = G->queue;
  u32 id = 0;

  ACTF("Creating hard links for all input files...");

  while (q) {

    u8  *nfn, *rsl = strrchr(q->fname, '/');
    u32 orig_id;

    if (!rsl) rsl = q->fname; else rsl++;

    /* If the original file name conforms to the syntax and the recorded
       ID matches the one we'd assign, just use the original file name.
       This is valuable for resuming fuzzing runs. */

#ifndef SIMPLE_FILES
#  define CASE_PREFIX "id:"
#else
#  define CASE_PREFIX "id_"
#endif /* ^!SIMPLE_FILES */

    if (!strncmp(rsl, CASE_PREFIX, 3) &&
        sscanf(rsl + 3, "%06u", &orig_id) == 1 && orig_id == id) {

      u8* src_str;
      u32 src_id;

      G->resuming_fuzz = 1;
      nfn = alloc_printf("%s/queue/%s", G->out_dir, rsl);

      /* Since we're at it, let's also try to find parent and figure out the
         appropriate depth for this entry. */

      src_str = strchr(rsl + 3, ':');

      if (src_str && sscanf(src_str + 1, "%06u", &src_id) == 1) {

        struct queue_entry* s = G->queue;
        while (src_id-- && s) s = s->next;
        if (s) q->depth = s->depth + 1;

        if (G->max_depth < q->depth) G->max_depth = q->depth;

      }

    } else {

      /* No dice - invent a new name, capturing the original one as a
         substring. */

#ifndef SIMPLE_FILES

      u8* use_name = strstr(rsl, ",orig:");

      if (use_name) use_name += 6; else use_name = rsl;
      nfn = alloc_printf("%s/queue/id:%06u,orig:%s", G->out_dir, id, use_name);

#else

      nfn = alloc_printf("%s/queue/id_%06u", G->out_dir, id);

#endif /* ^!SIMPLE_FILES */

    }

    /* Pivot to the new queue entry. */

    link_or_copy(q->fname, nfn);
    ck_free(q->fname);
    q->fname = nfn;

    /* Make sure that the passed_det value carries over, too. */

    if (q->passed_det) mark_as_det_done(G, q);

    q = q->next;
    id++;

  }

  if (G->in_place_resume) nuke_resume_dir(G);

}


#ifndef SIMPLE_FILES

/* Construct a file name for a new test case, capturing the operation
   that led to its discovery. Uses a static buffer. */

static u8* describe_op(struct g* G, u8 hnb) {

  static u8 ret[256];

  if (G->syncing_party) {

    sprintf(ret, "sync:%s,src:%06u", G->syncing_party, G->syncing_case);

  } else {

    sprintf(ret, "src:%06u", G->current_entry);

    if (G->splicing_with >= 0)
      sprintf(ret + strlen(ret), "+%06u", G->splicing_with);

    sprintf(ret + strlen(ret), ",op:%s", G->stage_short);

    if (G->stage_cur_byte >= 0) {

      sprintf(ret + strlen(ret), ",pos:%u", G->stage_cur_byte);

      if (G->stage_val_type != STAGE_VAL_NONE)
        sprintf(ret + strlen(ret), ",val:%s%+d", 
                (G->stage_val_type == STAGE_VAL_BE) ? "be:" : "",
                G->stage_cur_val);

    } else sprintf(ret + strlen(ret), ",rep:%u", G->stage_cur_val);

  }

  if (hnb == 2) strcat(ret, ",+cov");

  return ret;

}

#endif /* !SIMPLE_FILES */


/* Write a message accompanying the crash directory :-) */

static void write_crash_readme(struct g* G) {

  u8* fn = alloc_printf("%s/crashes/README.txt", G->out_dir);
  s32 fd;
  FILE* f;

  fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
  ck_free(fn);

  /* Do not die on errors here - that would be impolite. */

  if (fd < 0) return;

  f = fdopen(fd, "w");

  if (!f) {
    close(fd);
    return;
  }

  fprintf(f, "Command line used to find this crash:\n\n"

             "%s\n\n"

             "If you can't reproduce a bug outside of afl-fuzz, be sure to set the same\n"
             "memory limit. The limit used for this fuzzing session was %s.\n\n"

             "Need a tool to minimize test cases before investigating the crashes or sending\n"
             "them to a vendor? Check out the afl-tmin that comes with the fuzzer!\n\n"

             "Found any cool bugs in open-source tools using afl-fuzz? If yes, please drop\n"
             "me a mail at <lcamtuf@coredump.cx> once the issues are fixed - I'd love to\n"
             "add your finds to the gallery at:\n\n"

             "  http://lcamtuf.coredump.cx/afl/\n\n"

             "Thanks :-)\n",

             G->orig_cmdline, DMS(G->mem_limit << 20)); /* ignore errors */

  fclose(f);

}


/* Check if the result of an execve() during routine fuzzing is interesting,
   save or queue the input test case for further analysis if so. Returns 1 if
   entry is saved, 0 otherwise. */

u8 save_if_interesting(struct g* G, char** argv, void* mem, u32 len,
                       u8 fault) {

  u8  *fn = "";
  u8  hnb;
  s32 fd;
  u8  keeping = 0, res;

  if (fault == G->crash_mode) {

    /* Keep only if there are new bits in the map, add to queue for
       future fuzzing, etc. */

    if (!(hnb = has_new_bits(G, G->virgin_bits))) {
      if (G->crash_mode) G->total_crashes++;
      return 0;
    }    

#ifndef SIMPLE_FILES

    fn = alloc_printf("%s/queue/id:%06u,%s", G->out_dir, G->queued_paths,
                      describe_op(G, hnb));

#else

    fn = alloc_printf("%s/queue/id_%06u", G->out_dir, G->queued_paths);

#endif /* ^!SIMPLE_FILES */

    add_to_queue(G, fn, len, 0);

    if (hnb == 2) {
      G->queue_top->has_new_cov = 1;
      G->queued_with_cov++;
    }

    G->queue_top->exec_cksum = hash32(G->trace_bits, MAP_SIZE, HASH_CONST);

    /* Try to calibrate inline; this also calls update_bitmap_score() when
       successful. */

    res = calibrate_case(G, argv, G->queue_top, mem, G->queue_cycle - 1, 0);

    if (res == FAULT_ERROR)
      FATAL("Unable to execute target application");

    fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) PFATAL("Unable to create '%s'", fn);
    ck_write(fd, mem, len, fn);
    close(fd);

    keeping = 1;

  }

  switch (fault) {

    case FAULT_HANG:

      /* Hangs are not very interesting, but we're still obliged to keep
         a handful of samples. We use the presence of new bits in the
         hang-specific bitmap as a signal of uniqueness. In "dumb" mode, we
         just keep everything. */

      G->total_hangs++;

      if (G->unique_hangs >= KEEP_UNIQUE_HANG) return keeping;

      if (!G->dumb_mode) {

#ifdef __x86_64__
        simplify_trace((u64*)G->trace_bits);
#else
        simplify_trace((u32*)G->trace_bits);
#endif /* ^__x86_64__ */

        if (!has_new_bits(G, G->virgin_hang)) return keeping;

      }

#ifndef SIMPLE_FILES

      fn = alloc_printf("%s/hangs/id:%06llu,%s", G->out_dir,
                        G->unique_hangs, describe_op(G, 0));

#else

      fn = alloc_printf("%s/hangs/id_%06llu", G->out_dir,
                        G->unique_hangs);

#endif /* ^!SIMPLE_FILES */

      G->unique_hangs++;

      G->last_hang_time = get_cur_time();

      break;

    case FAULT_CRASH:

      /* This is handled in a manner roughly similar to hangs,
         except for slightly different limits. */

      G->total_crashes++;

      if (G->unique_crashes >= KEEP_UNIQUE_CRASH) return keeping;

      if (!G->dumb_mode) {

#ifdef __x86_64__
        simplify_trace((u64*)G->trace_bits);
#else
        simplify_trace((u32*)G->trace_bits);
#endif /* ^__x86_64__ */

        if (!has_new_bits(G, G->virgin_crash)) return keeping;

      }

      if (!G->unique_crashes) write_crash_readme(G);

#ifndef SIMPLE_FILES

      fn = alloc_printf("%s/crashes/id:%06llu,sig:%02u,%s", G->out_dir,
                        G->unique_crashes, G->kill_signal, describe_op(G, 0));

#else

      fn = alloc_printf("%s/crashes/id_%06llu_%02u", G->out_dir, G->unique_crashes,
                        G->kill_signal);

#endif /* ^!SIMPLE_FILES */

      G->unique_crashes++;

      G->last_crash_time = get_cur_time();

      break;

    case FAULT_ERROR: FATAL("Unable to execute target application");

    default: return keeping;

  }

  /* If we're here, we apparently want to save the crash or hang
     test case, too. */

  fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0) PFATAL("Unable to create '%s'", fn);
  ck_write(fd, mem, len, fn);
  close(fd);

  ck_free(fn);

  return keeping;

}


/* When resuming, try to find the queue position to start from. This makes sense
   only when resuming, and when we can find the original fuzzer_stats. */

static u32 find_start_position(struct g* G) {

  static u8 tmp[4096]; /* Ought to be enough for anybody. */

  u8  *fn, *off;
  s32 fd, i;
  u32 ret;

  if (!G->resuming_fuzz) return 0;

  if (G->in_place_resume) fn = alloc_printf("%s/fuzzer_stats", G->out_dir);
  else fn = alloc_printf("%s/../fuzzer_stats", G->in_dir);

  fd = open(fn, O_RDONLY);
  ck_free(fn);

  if (fd < 0) return 0;

  i = read(fd, tmp, sizeof(tmp) - 1); (void)i; /* Ignore errors */
  close(fd);

  off = strstr(tmp, "cur_path       : ");
  if (!off) return 0;

  ret = atoi(off + 17);
  if (ret >= G->queued_paths) ret = 0;
  return ret;

}


/* The same, but for timeouts. The idea is that when resuming sessions without
   -t given, we don't want to keep auto-scaling the timeout over and over
   again to prevent it from growing due to random flukes. */

static void find_timeout(struct g* G) {

  static u8 tmp[4096]; /* Ought to be enough for anybody. */

  u8  *fn, *off;
  s32 fd, i;
  u32 ret;

  if (!G->resuming_fuzz) return;

  if (G->in_place_resume) fn = alloc_printf("%s/fuzzer_stats", G->out_dir);
  else fn = alloc_printf("%s/../fuzzer_stats", G->in_dir);

  fd = open(fn, O_RDONLY);
  ck_free(fn);

  if (fd < 0) return;

  i = read(fd, tmp, sizeof(tmp) - 1); (void)i; /* Ignore errors */
  close(fd);

  off = strstr(tmp, "exec_timeout   : ");
  if (!off) return;

  ret = atoi(off + 17);
  if (ret <= 4) return;

  G->exec_tmout = ret;
  G->timeout_given = 3;

}


/* Update stats file for unattended monitoring. */

static void write_stats_file(struct g* G, double bitmap_cvg, double eps) {

  static double last_bcvg, last_eps;

  u8* fn = alloc_printf("%s/fuzzer_stats", G->out_dir);
  s32 fd;
  FILE* f;

  fd = open(fn, O_WRONLY | O_CREAT | O_TRUNC, 0600);

  if (fd < 0) PFATAL("Unable to create '%s'", fn);

  ck_free(fn);

  f = fdopen(fd, "w");

  if (!f) PFATAL("fdopen() failed");

  /* Keep last values in case we're called from another context
     where exec/sec stats and such are not readily available. */

  if (!bitmap_cvg && !eps) {
    bitmap_cvg = last_bcvg;
    eps        = last_eps;
  } else {
    last_bcvg = bitmap_cvg;
    last_eps  = eps;
  }

  fprintf(f, "start_time     : %llu\n"
             "last_update    : %llu\n"
             "fuzzer_pid     : %u\n"
             "cycles_done    : %llu\n"
             "execs_done     : %llu\n"
             "execs_per_sec  : %0.02f\n"
             "paths_total    : %u\n"
             "paths_favored  : %u\n"
             "paths_found    : %u\n"
             "paths_imported : %u\n"
             "max_depth      : %u\n"
             "cur_path       : %u\n"
             "pending_favs   : %u\n"
             "pending_total  : %u\n"
             "variable_paths : %u\n"
             "bitmap_cvg     : %0.02f%%\n"
             "unique_crashes : %llu\n"
             "unique_hangs   : %llu\n"
             "last_path      : %llu\n"
             "last_crash     : %llu\n"
             "last_hang      : %llu\n"
             "exec_timeout   : %u\n"
             "afl_banner     : %s\n"
             "afl_version    : " VERSION "\n"
             "command_line   : %s\n",
             G->start_time / 1000, get_cur_time() / 1000, getpid(),
             G->queue_cycle ? (G->queue_cycle - 1) : 0, G->total_execs, eps,
             G->queued_paths, G->queued_favored, G->queued_discovered, G->queued_imported,
             G->max_depth, G->current_entry, G->pending_favored, G->pending_not_fuzzed,
             G->queued_variable, bitmap_cvg, G->unique_crashes, G->unique_hangs,
             G->last_path_time / 1000, G->last_crash_time / 1000,
             G->last_hang_time / 1000, G->exec_tmout, G->use_banner, G->orig_cmdline);
             /* ignore errors */

  fclose(f);

}


/* Update the plot file if there is a reason to. */

static void maybe_update_plot_file(struct g* G, double bitmap_cvg, double eps) {

  static u32 prev_qp, prev_pf, prev_pnf, prev_ce, prev_md;
  static u64 prev_qc, prev_uc, prev_uh;

  if (prev_qp == G->queued_paths && prev_pf == G->pending_favored && 
      prev_pnf == G->pending_not_fuzzed && prev_ce == G->current_entry &&
      prev_qc == G->queue_cycle && prev_uc == G->unique_crashes &&
      prev_uh == G->unique_hangs && prev_md == G->max_depth) return;

  prev_qp  = G->queued_paths;
  prev_pf  = G->pending_favored;
  prev_pnf = G->pending_not_fuzzed;
  prev_ce  = G->current_entry;
  prev_qc  = G->queue_cycle;
  prev_uc  = G->unique_crashes;
  prev_uh  = G->unique_hangs;
  prev_md  = G->max_depth;

  /* Fields in the file:

     unix_time, cycles_done, cur_path, paths_total, paths_not_fuzzed,
     favored_not_fuzzed, G->unique_crashes, G->unique_hangs, G->max_depth,
     execs_per_sec */

  fprintf(G->plot_file, 
          "%llu, %llu, %u, %u, %u, %u, %0.02f%%, %llu, %llu, %u, %0.02f\n",
          get_cur_time() / 1000, G->queue_cycle - 1, G->current_entry, G->queued_paths,
          G->pending_not_fuzzed, G->pending_favored, bitmap_cvg, G->unique_crashes,
          G->unique_hangs, G->max_depth, eps); /* ignore errors */

  fflush(G->plot_file);

}



/* A helper function for maybe_delete_out_dir(), deleting all prefixed
   files in a directory. */

static u8 delete_files(u8* path, u8* prefix) {

  DIR* d;
  struct dirent* d_ent;

  d = opendir(path);

  if (!d) return 0;

  while ((d_ent = readdir(d))) {

    if (d_ent->d_name[0] != '.' && (!prefix ||
        !strncmp(d_ent->d_name, prefix, strlen(prefix)))) {

      u8* fname = alloc_printf("%s/%s", path, d_ent->d_name);
      if (unlink(fname)) PFATAL("Unable to delete '%s'", fname);
      ck_free(fname);

    }

  }

  closedir(d);

  return !!rmdir(path);

}


/* Get the number of runnable processes, with some simple smoothing. */

static double get_runnable_processes(void) {

  static double res;

#if defined(__APPLE__) || defined(__FreeBSD__) || defined (__OpenBSD__)

  /* I don't see any portable sysctl or so that would quickly give us the
     number of runnable processes; the 1-minute load average can be a
     semi-decent approximation, though. */

  if (getloadavg(&res, 1) != 1) return 0;

#else

  /* On Linux, /proc/stat is probably the best way; load averages are
     computed in funny ways and sometimes don't reflect extremely short-lived
     processes well. */

  FILE* f = fopen("/proc/stat", "r");
  u8 tmp[1024];
  u32 val = 0;

  if (!f) return 0;

  while (fgets(tmp, sizeof(tmp), f)) {

    if (!strncmp(tmp, "procs_running ", 14) ||
        !strncmp(tmp, "procs_blocked ", 14)) val += atoi(tmp + 14);

  }
 
  fclose(f);

  if (!res) {

    res = val;

  } else {

    res = res * (1.0 - 1.0 / AVG_SMOOTHING) +
          ((double)val) * (1.0 / AVG_SMOOTHING);

  }

#endif /* ^(__APPLE__ || __FreeBSD__ || __OpenBSD__) */

  return res;

}


/* Delete the temporary directory used for in-place session resume. */

static void nuke_resume_dir(struct g* G) {

  u8* fn;

  fn = alloc_printf("%s/_resume/.state/deterministic_done", G->out_dir);
  if (delete_files(fn, CASE_PREFIX)) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/_resume/.state/auto_extras", G->out_dir);
  if (delete_files(fn, "auto_")) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/_resume/.state/redundant_edges", G->out_dir);
  if (delete_files(fn, CASE_PREFIX)) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/_resume/.state/variable_behavior", G->out_dir);
  if (delete_files(fn, CASE_PREFIX)) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/_resume/.state", G->out_dir);
  if (rmdir(fn) && errno != ENOENT) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/_resume", G->out_dir);
  if (delete_files(fn, CASE_PREFIX)) goto dir_cleanup_failed;
  ck_free(fn);

  return;

dir_cleanup_failed:

  FATAL("_resume directory cleanup failed");

}


/* Delete fuzzer output directory if we recognize it as ours, if the fuzzer
   is not currently running, and if the last run time isn't too great. */

static void maybe_delete_out_dir(struct g* G) {

  FILE* f;
  u8 *fn = alloc_printf("%s/fuzzer_stats", G->out_dir);

  /* See if the output directory is locked. If yes, bail out. If not,
     create a lock that will persist for the lifetime of the process
     (this requires leaving the descriptor open).*/

  G->out_dir_fd = open(G->out_dir, O_RDONLY);
  if (G->out_dir_fd < 0) PFATAL("Unable to open '%s'", G->out_dir);

#ifndef __sun

  if (flock(G->out_dir_fd, LOCK_EX | LOCK_NB) && errno == EWOULDBLOCK) {

    SAYF("\n" cLRD "[-] " cRST
         "Looks like the job output directory is being actively used by another\n"
         "    instance of afl-fuzz. You will need to choose a different %s\n"
         "    or stop the other process first.\n",
         G->sync_id ? "fuzzer ID" : "output location");

    FATAL("Directory '%s' is in use", G->out_dir);

  }

#endif /* !__sun */

  f = fopen(fn, "r");

  if (f) {

    u64 start_time, last_update;

    if (fscanf(f, "start_time     : %llu\n"
                  "last_update    : %llu\n", &start_time, &last_update) != 2)
      FATAL("Malformed data in '%s'", fn);

    fclose(f);

    /* Let's see how much work is at stake. */

    if (!G->in_place_resume && last_update - start_time > OUTPUT_GRACE * 60) {

      SAYF("\n" cLRD "[-] " cRST
           "The job output directory already exists and contains the results of more\n"
           "    than %u minutes worth of fuzzing. To avoid data loss, afl-fuzz will *NOT*\n"
           "    automatically delete this data for you.\n\n"

           "    If you wish to start a new session, remove or rename the directory manually,\n"
           "    or specify a different output location for this job. To resume the old\n"
           "    session, put '-' as the input directory in the command line ('-i -') and\n"
           "    try again.\n", OUTPUT_GRACE);

       FATAL("At-risk data found in in '%s'", G->out_dir);

    }

  }

  ck_free(fn);

  /* The idea for in-place resume is pretty simple: we temporarily move the old
     queue/ to a new location that gets deleted once import to the new queue/
     is finished. If _resume/ already exists, the current queue/ may be
     incomplete due to an earlier abort, so we want to use the old _resume/
     dir instead, and we let rename() fail silently. */

  if (G->in_place_resume) {

    u8* orig_q = alloc_printf("%s/queue", G->out_dir);

    G->in_dir = alloc_printf("%s/_resume", G->out_dir);

    rename(orig_q, G->in_dir); /* Ignore errors */

    OKF("Output directory exists, will attempt session resume.");

    ck_free(orig_q);

  } else {

    OKF("Output directory exists but deemed OK to reuse.");

  }

  ACTF("Deleting old session data...");

  /* Okay, let's get the ball rolling! First, we need to get rid of the entries
     in <G->out_dir>/.synced/.../id:*, if any are present. */

  fn = alloc_printf("%s/.synced", G->out_dir);
  if (delete_files(fn, NULL)) goto dir_cleanup_failed;
  ck_free(fn);

  /* Next, we need to clean up <G->out_dir>/queue/.state/ subdirectories: */

  fn = alloc_printf("%s/queue/.state/deterministic_done", G->out_dir);
  if (delete_files(fn, CASE_PREFIX)) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/queue/.state/auto_extras", G->out_dir);
  if (delete_files(fn, "auto_")) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/queue/.state/redundant_edges", G->out_dir);
  if (delete_files(fn, CASE_PREFIX)) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/queue/.state/variable_behavior", G->out_dir);
  if (delete_files(fn, CASE_PREFIX)) goto dir_cleanup_failed;
  ck_free(fn);

  /* Then, get rid of the .state subdirectory itself (should be empty by now)
     and everything matching <G->out_dir>/queue/id:*. */

  fn = alloc_printf("%s/queue/.state", G->out_dir);
  if (rmdir(fn) && errno != ENOENT) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/queue", G->out_dir);
  if (delete_files(fn, CASE_PREFIX)) goto dir_cleanup_failed;
  ck_free(fn);

  /* All right, let's do <G->out_dir>/crashes/id:* and <G->out_dir>/hangs/id:*. */

  if (!G->in_place_resume) {

    fn = alloc_printf("%s/crashes/README.txt", G->out_dir);
    unlink(fn); /* Ignore errors */
    ck_free(fn);

  }

  fn = alloc_printf("%s/crashes", G->out_dir);

  /* Make backup of the crashes directory if it's not empty and if we're
     doing in-place resume. */

  if (G->in_place_resume && rmdir(fn)) {

    time_t cur_t = time(0);
    struct tm* t = localtime(&cur_t);

#ifndef SIMPLE_FILES

    u8* nfn = alloc_printf("%s.%04u-%02u-%02u-%02u:%02u:%02u", fn,
                           t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
                           t->tm_hour, t->tm_min, t->tm_sec);

#else

    u8* nfn = alloc_printf("%s_%04u%02u%02u%02u%02u%02u", fn,
                           t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
                           t->tm_hour, t->tm_min, t->tm_sec);

#endif /* ^!SIMPLE_FILES */

    rename(fn, nfn); /* Ignore errors. */
    ck_free(nfn);

  }

  if (delete_files(fn, CASE_PREFIX)) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/hangs", G->out_dir);

  /* Backup hangs, too. */

  if (G->in_place_resume && rmdir(fn)) {

    time_t cur_t = time(0);
    struct tm* t = localtime(&cur_t);

#ifndef SIMPLE_FILES

    u8* nfn = alloc_printf("%s.%04u-%02u-%02u-%02u:%02u:%02u", fn,
                           t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
                           t->tm_hour, t->tm_min, t->tm_sec);

#else

    u8* nfn = alloc_printf("%s_%04u%02u%02u%02u%02u%02u", fn,
                           t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
                           t->tm_hour, t->tm_min, t->tm_sec);

#endif /* ^!SIMPLE_FILES */

    rename(fn, nfn); /* Ignore errors. */
    ck_free(nfn);

  }

  if (delete_files(fn, CASE_PREFIX)) goto dir_cleanup_failed;
  ck_free(fn);

  /* And now, for some finishing touches. */

  fn = alloc_printf("%s/.cur_input", G->out_dir);
  if (unlink(fn) && errno != ENOENT) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/fuzz_bitmap", G->out_dir);
  if (unlink(fn) && errno != ENOENT) goto dir_cleanup_failed;
  ck_free(fn);

  if (!G->in_place_resume) {
    fn  = alloc_printf("%s/fuzzer_stats", G->out_dir);
    if (unlink(fn) && errno != ENOENT) goto dir_cleanup_failed;
    ck_free(fn);
  }

  fn = alloc_printf("%s/plot_data", G->out_dir);
  if (unlink(fn) && errno != ENOENT) goto dir_cleanup_failed;
  ck_free(fn);

  OKF("Output dir cleanup successful.");

  /* Wow... is that all? If yes, celebrate! */

  return;

dir_cleanup_failed:

  SAYF("\n" cLRD "[-] " cRST
       "Whoops, the fuzzer tried to reuse your output directory, but bumped into\n"
       "    some files that shouldn't be there or that couldn't be removed - so it\n"
       "    decided to abort! This happened while processing this path:\n\n"

       "    %s\n\n"
       "    Please examine and manually delete the files, or specify a different\n"
       "    output location for the tool.\n", fn);

  FATAL("Output directory cleanup failed");

}


static void check_term_size(struct g* G);


/* A spiffy retro stats screen! This is called every G->stats_update_freq
   execve() calls, plus in several other circumstances. */

void show_stats(struct g* G) {

  static u64 last_stats_ms, last_plot_ms, last_ms, last_execs;
  static double avg_exec;
  double t_byte_ratio;

  u64 cur_ms;
  u32 t_bytes, t_bits;

  u32 banner_len, banner_pad;
  u8  tmp[256];

  cur_ms = get_cur_time();

  /* If not enough time has passed since last UI update, bail out. */

  if (cur_ms - last_ms < 1000 / UI_TARGET_HZ) return;

  /* Check if we're past the 10 minute mark. */

  if (cur_ms - G->start_time > 10 * 60 * 1000) G->run_over10m = 1;

  /* Calculate smoothed exec speed stats. */

  if (!last_execs) {
  
    avg_exec = ((double)G->total_execs) * 1000 / (cur_ms - G->start_time);

  } else {

    double cur_avg = ((double)(G->total_execs - last_execs)) * 1000 /
                     (cur_ms - last_ms);

    /* If there is a dramatic (5x+) jump in speed, reset the indicator
       more quickly. */

    if (cur_avg * 5 < avg_exec || cur_avg / 5 > avg_exec)
      avg_exec = cur_avg;

    avg_exec = avg_exec * (1.0 - 1.0 / AVG_SMOOTHING) +
               cur_avg * (1.0 / AVG_SMOOTHING);

  }

  last_ms = cur_ms;
  last_execs = G->total_execs;

  /* Tell the callers when to contact us (as measured in execs). */

  G->stats_update_freq = avg_exec / (UI_TARGET_HZ * 10);
  if (!G->stats_update_freq) G->stats_update_freq = 1;

  /* Do some bitmap stats. */

  t_bytes = count_non_255_bytes(G->virgin_bits);
  t_byte_ratio = ((double)t_bytes * 100) / MAP_SIZE;

  /* Roughly every minute, update fuzzer stats and save auto tokens. */

  if (cur_ms - last_stats_ms > STATS_UPDATE_SEC * 1000) {

    last_stats_ms = cur_ms;
    write_stats_file(G, t_byte_ratio, avg_exec);
    save_auto(G);
    write_bitmap(G);

  }

  /* Every now and then, write plot data. */

  if (cur_ms - last_plot_ms > PLOT_UPDATE_SEC * 1000) {

    last_plot_ms = cur_ms;
    maybe_update_plot_file(G, t_byte_ratio, avg_exec);
 
  }

  /* Honor AFL_EXIT_WHEN_DONE. */

  if (!G->dumb_mode && G->cycles_wo_finds > 20 && !G->pending_not_fuzzed &&
      getenv("AFL_EXIT_WHEN_DONE")) G->stop_soon = 1;

  /* If we're not on TTY, bail out. */

  if (G->not_on_tty) return;

  /* Compute some mildly useful bitmap stats. */

  t_bits = (MAP_SIZE << 3) - count_bits(G->virgin_bits);

  /* Now, for the visuals... */

  if (G->clear_screen) {

    SAYF(TERM_CLEAR CURSOR_HIDE);
    G->clear_screen = 0;

    check_term_size(G);

  }

  SAYF(TERM_HOME);

  if (G->term_too_small) {

    SAYF(cBRI "Your terminal is too small to display the UI.\n"
         "Please resize terminal window to at least 80x25.\n" cNOR);

    return;

  }

  /* Let's start by drawing a centered banner. */

  banner_len = (G->crash_mode ? 24 : 22) + strlen(VERSION) + strlen(G->use_banner);
  banner_pad = (80 - banner_len) / 2;
  memset(tmp, ' ', banner_pad);

  sprintf(tmp + banner_pad, "%s " cLCY VERSION cLGN
          " (%s)",  G->crash_mode ? cPIN "peruvian were-rabbit" : 
          cYEL "american fuzzy lop", G->use_banner);

  SAYF("\n%s\n\n", tmp);

  /* "Handy" shortcuts for drawing boxes... */

#define bSTG    bSTART cGRA
#define bH2     bH bH
#define bH5     bH2 bH2 bH
#define bH10    bH5 bH5
#define bH20    bH10 bH10
#define bH30    bH20 bH10
#define SP5     "     "
#define SP10    SP5 SP5
#define SP20    SP10 SP10

  /* Lord, forgive me this. */

  SAYF(SET_G1 bSTG bLT bH bSTOP cCYA " process timing " bSTG bH30 bH5 bH2 bHB
       bH bSTOP cCYA " overall results " bSTG bH5 bRT "\n");

  if (G->dumb_mode) {

    strcpy(tmp, cNOR);

  } else {

    /* First queue cycle: don't stop now! */
    if (G->queue_cycle == 1) strcpy(tmp, cMGN); else

    /* Subsequent cycles, but we're still making finds. */
    if (G->cycles_wo_finds < 3) strcpy(tmp, cYEL); else

    /* No finds for a long time and no test cases to try. */
    if (G->cycles_wo_finds > 20 && !G->pending_not_fuzzed) strcpy(tmp, cLGN);

    /* Default: cautiously OK to stop? */
    else strcpy(tmp, cLBL);

  }

  SAYF(bV bSTOP "        run time : " cNOR "%-34s " bSTG bV bSTOP
       "  cycles done : %s%-5s  " bSTG bV "\n",
       DTD(cur_ms, G->start_time), tmp, DI(G->queue_cycle - 1));

  /* We want to warn people about not seeing new paths after a full cycle,
     except when resuming fuzzing or running in non-instrumented mode. */

  if (!G->dumb_mode && (G->last_path_time || G->resuming_fuzz || G->queue_cycle == 1 ||
      G->in_bitmap || G->crash_mode)) {

    SAYF(bV bSTOP "   last new path : " cNOR "%-34s ",
         DTD(cur_ms, G->last_path_time));

  } else {

    if (G->dumb_mode)

      SAYF(bV bSTOP "   last new path : " cPIN "n/a" cNOR 
           " (non-instrumented mode)        ");

     else

      SAYF(bV bSTOP "   last new path : " cNOR "none yet " cLRD
           "(odd, check syntax!)      ");

  }

  SAYF(bSTG bV bSTOP "  total paths : " cNOR "%-5s  " bSTG bV "\n",
       DI(G->queued_paths));

  /* Highlight crashes in red if found, denote going over the KEEP_UNIQUE_CRASH
     limit with a '+' appended to the count. */

  sprintf(tmp, "%s%s", DI(G->unique_crashes),
          (G->unique_crashes >= KEEP_UNIQUE_CRASH) ? "+" : "");

  SAYF(bV bSTOP " last uniq crash : " cNOR "%-34s " bSTG bV bSTOP
       " uniq crashes : %s%-6s " bSTG bV "\n",
       DTD(cur_ms, G->last_crash_time), G->unique_crashes ? cLRD : cNOR,
       tmp);

  sprintf(tmp, "%s%s", DI(G->unique_hangs),
         (G->unique_hangs >= KEEP_UNIQUE_HANG) ? "+" : "");

  SAYF(bV bSTOP "  last uniq hang : " cNOR "%-34s " bSTG bV bSTOP 
       "   uniq hangs : " cNOR "%-6s " bSTG bV "\n",
       DTD(cur_ms, G->last_hang_time), tmp);

  SAYF(bVR bH bSTOP cCYA " cycle progress " bSTG bH20 bHB bH bSTOP cCYA
       " map coverage " bSTG bH bHT bH20 bH2 bH bVL "\n");

  /* This gets funny because we want to print several variable-length variables
     together, but then cram them into a fixed-width field - so we need to
     put them in a temporary buffer first. */

  sprintf(tmp, "%s%s (%0.02f%%)", DI(G->current_entry),
          G->queue_cur->favored ? "" : "*",
          ((double)G->current_entry * 100) / G->queued_paths);

  SAYF(bV bSTOP "  now processing : " cNOR "%-17s " bSTG bV bSTOP, tmp);


  sprintf(tmp, "%s (%0.02f%%)", DI(t_bytes), t_byte_ratio);

  SAYF("    map density : %s%-21s " bSTG bV "\n", t_byte_ratio > 70 ? cLRD : 
       ((t_bytes < 200 && !G->dumb_mode) ? cPIN : cNOR), tmp);

  sprintf(tmp, "%s (%0.02f%%)", DI(G->cur_skipped_paths),
          ((double)G->cur_skipped_paths * 100) / G->queued_paths);

  SAYF(bV bSTOP " paths timed out : " cNOR "%-17s " bSTG bV, tmp);

  sprintf(tmp, "%0.02f bits/tuple",
          t_bytes ? (((double)t_bits) / t_bytes) : 0);

  SAYF(bSTOP " count coverage : " cNOR "%-21s " bSTG bV "\n", tmp);

  SAYF(bVR bH bSTOP cCYA " stage progress " bSTG bH20 bX bH bSTOP cCYA
       " findings in depth " bSTG bH20 bVL "\n");

  sprintf(tmp, "%s (%0.02f%%)", DI(G->queued_favored),
          ((double)G->queued_favored) * 100 / G->queued_paths);

  /* Yeah... it's still going on... halp? */

  SAYF(bV bSTOP "  now trying : " cNOR "%-21s " bSTG bV bSTOP 
       " favored paths : " cNOR "%-22s " bSTG bV "\n", G->stage_name, tmp);

  if (!G->stage_max) {

    sprintf(tmp, "%s/-", DI(G->stage_cur));

  } else {

    sprintf(tmp, "%s/%s (%0.02f%%)", DI(G->stage_cur), DI(G->stage_max),
            ((double)G->stage_cur) * 100 / G->stage_max);

  }

  SAYF(bV bSTOP " stage execs : " cNOR "%-21s " bSTG bV bSTOP, tmp);

  sprintf(tmp, "%s (%0.02f%%)", DI(G->queued_with_cov),
          ((double)G->queued_with_cov) * 100 / G->queued_paths);

  SAYF("  new edges on : " cNOR "%-22s " bSTG bV "\n", tmp);

  sprintf(tmp, "%s (%s%s unique)", DI(G->total_crashes), DI(G->unique_crashes),
          (G->unique_crashes >= KEEP_UNIQUE_CRASH) ? "+" : "");

  if (G->crash_mode) {

    SAYF(bV bSTOP " total execs : " cNOR "%-21s " bSTG bV bSTOP
         "   new crashes : %s%-22s " bSTG bV "\n", DI(G->total_execs),
         G->unique_crashes ? cLRD : cNOR, tmp);

  } else {

    SAYF(bV bSTOP " total execs : " cNOR "%-21s " bSTG bV bSTOP
         " total crashes : %s%-22s " bSTG bV "\n", DI(G->total_execs),
         G->unique_crashes ? cLRD : cNOR, tmp);

  }

  /* Show a warning about slow execution. */

  if (avg_exec < 100) {

    sprintf(tmp, "%s/sec (%s)", DF(avg_exec), avg_exec < 20 ?
            "zzzz..." : "slow!");

    SAYF(bV bSTOP "  exec speed : " cLRD "%-21s ", tmp);

  } else {

    sprintf(tmp, "%s/sec", DF(avg_exec));
    SAYF(bV bSTOP "  exec speed : " cNOR "%-21s ", tmp);

  }

  sprintf(tmp, "%s (%s%s unique)", DI(G->total_hangs), DI(G->unique_hangs),
          (G->unique_hangs >= KEEP_UNIQUE_HANG) ? "+" : "");

  SAYF (bSTG bV bSTOP "   total hangs : " cNOR "%-22s " bSTG bV "\n", tmp);

  /* Aaaalmost there... hold on! */

  SAYF(bVR bH cCYA bSTOP " fuzzing strategy yields " bSTG bH10 bH bHT bH10
       bH5 bHB bH bSTOP cCYA " path geometry " bSTG bH5 bH2 bH bVL "\n");

  if (G->skip_deterministic) {

    strcpy(tmp, "n/a, n/a, n/a");

  } else {

    sprintf(tmp, "%s/%s, %s/%s, %s/%s",
            DI(G->stage_finds[STAGE_FLIP1]), DI(G->stage_cycles[STAGE_FLIP1]),
            DI(G->stage_finds[STAGE_FLIP2]), DI(G->stage_cycles[STAGE_FLIP2]),
            DI(G->stage_finds[STAGE_FLIP4]), DI(G->stage_cycles[STAGE_FLIP4]));

  }

  SAYF(bV bSTOP "   bit flips : " cNOR "%-37s " bSTG bV bSTOP "    levels : "
       cNOR "%-10s " bSTG bV "\n", tmp, DI(G->max_depth));

  if (!G->skip_deterministic)
    sprintf(tmp, "%s/%s, %s/%s, %s/%s",
            DI(G->stage_finds[STAGE_FLIP8]), DI(G->stage_cycles[STAGE_FLIP8]),
            DI(G->stage_finds[STAGE_FLIP16]), DI(G->stage_cycles[STAGE_FLIP16]),
            DI(G->stage_finds[STAGE_FLIP32]), DI(G->stage_cycles[STAGE_FLIP32]));

  SAYF(bV bSTOP "  byte flips : " cNOR "%-37s " bSTG bV bSTOP "   pending : "
       cNOR "%-10s " bSTG bV "\n", tmp, DI(G->pending_not_fuzzed));

  if (!G->skip_deterministic)
    sprintf(tmp, "%s/%s, %s/%s, %s/%s",
            DI(G->stage_finds[STAGE_ARITH8]), DI(G->stage_cycles[STAGE_ARITH8]),
            DI(G->stage_finds[STAGE_ARITH16]), DI(G->stage_cycles[STAGE_ARITH16]),
            DI(G->stage_finds[STAGE_ARITH32]), DI(G->stage_cycles[STAGE_ARITH32]));

  SAYF(bV bSTOP " arithmetics : " cNOR "%-37s " bSTG bV bSTOP "  pend fav : "
       cNOR "%-10s " bSTG bV "\n", tmp, DI(G->pending_favored));

  if (!G->skip_deterministic)
    sprintf(tmp, "%s/%s, %s/%s, %s/%s",
            DI(G->stage_finds[STAGE_INTEREST8]), DI(G->stage_cycles[STAGE_INTEREST8]),
            DI(G->stage_finds[STAGE_INTEREST16]), DI(G->stage_cycles[STAGE_INTEREST16]),
            DI(G->stage_finds[STAGE_INTEREST32]), DI(G->stage_cycles[STAGE_INTEREST32]));

  SAYF(bV bSTOP "  known ints : " cNOR "%-37s " bSTG bV bSTOP " own finds : "
       cNOR "%-10s " bSTG bV "\n", tmp, DI(G->queued_discovered));

  if (!G->skip_deterministic)
    sprintf(tmp, "%s/%s, %s/%s, %s/%s",
            DI(G->stage_finds[STAGE_EXTRAS_UO]), DI(G->stage_cycles[STAGE_EXTRAS_UO]),
            DI(G->stage_finds[STAGE_EXTRAS_UI]), DI(G->stage_cycles[STAGE_EXTRAS_UI]),
            DI(G->stage_finds[STAGE_EXTRAS_AO]), DI(G->stage_cycles[STAGE_EXTRAS_AO]));

  SAYF(bV bSTOP "  dictionary : " cNOR "%-37s " bSTG bV bSTOP
       "  imported : " cNOR "%-10s " bSTG bV "\n", tmp,
       G->sync_id ? DI(G->queued_imported) : (u8*)"n/a");

  sprintf(tmp, "%s/%s, %s/%s",
          DI(G->stage_finds[STAGE_HAVOC]), DI(G->stage_cycles[STAGE_HAVOC]),
          DI(G->stage_finds[STAGE_SPLICE]), DI(G->stage_cycles[STAGE_SPLICE]));

  SAYF(bV bSTOP "       havoc : " cNOR "%-37s " bSTG bV bSTOP 
       "  variable : %s%-10s " bSTG bV "\n", tmp, G->queued_variable ? cLRD : cNOR,
      G->no_var_check ? (u8*)"n/a" : DI(G->queued_variable));

  if (!G->bytes_trim_out) {

    sprintf(tmp, "n/a, ");

  } else {

    sprintf(tmp, "%0.02f%%/%s, ",
            ((double)(G->bytes_trim_in - G->bytes_trim_out)) * 100 / G->bytes_trim_in,
            DI(G->trim_execs));

  }

  if (!G->blocks_eff_total) {

    u8 tmp2[128];

    sprintf(tmp2, "n/a");
    strcat(tmp, tmp2);

  } else {

    u8 tmp2[128];

    sprintf(tmp2, "%0.02f%%",
            ((double)(G->blocks_eff_total - G->blocks_eff_select)) * 100 /
            G->blocks_eff_total);

    strcat(tmp, tmp2);

  }

  SAYF(bV bSTOP "        trim : " cNOR "%-37s " bSTG bVR bH20 bH2 bH2 bRB "\n"
       bLB bH30 bH20 bH2 bH bRB bSTOP cRST RESET_G1, tmp);

  /* Provide some CPU utilization stats. */

  if (G->cpu_core_count) {

    double cur_runnable = get_runnable_processes();
    u32 cur_utilization = cur_runnable * 100 / G->cpu_core_count;

    u8* cpu_color = cCYA;

    /* If we could still run one or more processes, use green. */

    if (G->cpu_core_count > 1 && cur_runnable + 1 <= G->cpu_core_count)
      cpu_color = cLGN;

    /* If we're clearly oversubscribed, use red. */

    if (!G->no_cpu_meter_red && cur_utilization >= 150) cpu_color = cLRD;

    SAYF(SP10 cGRA "   [cpu:%s%3u%%" cGRA "]\r" cRST,
         cpu_color, cur_utilization < 999 ? cur_utilization : 999);

  } else SAYF("\r");

  /* Hallelujah! */

  fflush(0);

}


/* Display quick statistics at the end of processing the input directory,
   plus a bunch of warnings. Some calibration stuff also ended up here,
   along with several hardcoded constants. Maybe clean up eventually. */

static void show_init_stats(struct g* G) {

  struct queue_entry* q = G->queue;
  u32 min_bits = 0, max_bits = 0;
  u64 min_us = 0, max_us = 0;
  u64 avg_us = 0;
  u32 max_len = 0;

  if (G->total_cal_cycles) avg_us = G->total_cal_us / G->total_cal_cycles;

  while (q) {

    if (!min_us || q->exec_us < min_us) min_us = q->exec_us;
    if (q->exec_us > max_us) max_us = q->exec_us;

    if (!min_bits || q->bitmap_size < min_bits) min_bits = q->bitmap_size;
    if (q->bitmap_size > max_bits) max_bits = q->bitmap_size;

    if (q->len > max_len) max_len = q->len;

    q = q->next;

  }

  SAYF("\n");

  if (avg_us > (G->qemu_mode ? 50000 : 10000)) 
    WARNF(cLRD "The target binary is pretty slow! See %s/perf_tips.txt.",
          G->doc_path);

  /* Let's keep things moving with slow binaries. */

  if (avg_us > 50000) G->havoc_div = 10;     /* 0-19 execs/sec   */
  else if (avg_us > 20000) G->havoc_div = 5; /* 20-49 execs/sec  */
  else if (avg_us > 10000) G->havoc_div = 2; /* 50-100 execs/sec */

  if (!G->resuming_fuzz) {

    if (max_len > 50 * 1024)
      WARNF(cLRD "Some test cases are huge (%s) - see %s/perf_tips.txt!",
            DMS(max_len), G->doc_path);
    else if (max_len > 10 * 1024)
      WARNF("Some test cases are big (%s) - see %s/perf_tips.txt.",
            DMS(max_len), G->doc_path);

    if (G->useless_at_start && !G->in_bitmap)
      WARNF(cLRD "Some test cases look useless. Consider using a smaller set.");

    if (G->queued_paths > 100)
      WARNF(cLRD "You probably have far too many input files! Consider trimming down.");
    else if (G->queued_paths > 20)
      WARNF("You have lots of input files; try starting small.");

  }

  OKF("Here are some useful stats:\n\n"

      cGRA "    Test case count : " cNOR "%u favored, %u variable, %u total\n"
      cGRA "       Bitmap range : " cNOR "%u to %u bits (average: %0.02f bits)\n"
      cGRA "        Exec timing : " cNOR "%s to %s us (average: %s us)\n",
      G->queued_favored, G->queued_variable, G->queued_paths, min_bits, max_bits, 
      ((double)G->total_bitmap_size) / (G->total_bitmap_entries ? G->total_bitmap_entries : 1),
      DI(min_us), DI(max_us), DI(avg_us));

  if (!G->timeout_given) {

    /* Figure out the appropriate timeout. The basic idea is: 5x average or
       1x max, rounded up to EXEC_TM_ROUND ms and capped at 1 second.

       If the program is slow, the multiplier is lowered to 2x or 3x, because
       random scheduler jitter is less likely to have any impact, and because
       our patience is wearing thin =) */

    if (avg_us > 50000) G->exec_tmout = avg_us * 2 / 1000;
    else if (avg_us > 10000) G->exec_tmout = avg_us * 3 / 1000;
    else G->exec_tmout = avg_us * 5 / 1000;

    G->exec_tmout = MAX(G->exec_tmout, max_us / 1000);
    G->exec_tmout = (G->exec_tmout + EXEC_TM_ROUND) / EXEC_TM_ROUND * EXEC_TM_ROUND;

    if (G->exec_tmout > EXEC_TIMEOUT) G->exec_tmout = EXEC_TIMEOUT;

    ACTF("No -t option specified, so I'll use exec timeout of %u ms.", 
         G->exec_tmout);

    G->timeout_given = 1;

  } else if (G->timeout_given == 3) {

    ACTF("Applying timeout settings from resumed session (%u ms).", G->exec_tmout);

  }

  OKF("All set and ready to roll!");

}




/* Calculate case desirability score to adjust the length of havoc fuzzing.
   A helper function for fuzz_one(). Maybe some of these constants should
   go into config.h. */

u32 calculate_score(struct g* G, struct queue_entry* q) {

  u32 avg_exec_us = G->total_cal_us / G->total_cal_cycles;
  u32 avg_bitmap_size = G->total_bitmap_size / G->total_bitmap_entries;
  u32 perf_score = 100;

  /* Adjust score based on execution speed of this path, compared to the
     global average. Multiplier ranges from 0.1x to 3x. Fast inputs are
     less expensive to fuzz, so we're giving them more air time. */

  if (q->exec_us * 0.1 > avg_exec_us) perf_score = 10;
  else if (q->exec_us * 0.25 > avg_exec_us) perf_score = 25;
  else if (q->exec_us * 0.5 > avg_exec_us) perf_score = 50;
  else if (q->exec_us * 0.75 > avg_exec_us) perf_score = 75;
  else if (q->exec_us * 4 < avg_exec_us) perf_score = 300;
  else if (q->exec_us * 3 < avg_exec_us) perf_score = 200;
  else if (q->exec_us * 2 < avg_exec_us) perf_score = 150;

  /* Adjust score based on bitmap size. The working theory is that better
     coverage translates to better targets. Multiplier from 0.25x to 3x. */

  if (q->bitmap_size * 0.3 > avg_bitmap_size) perf_score *= 3;
  else if (q->bitmap_size * 0.5 > avg_bitmap_size) perf_score *= 2;
  else if (q->bitmap_size * 0.75 > avg_bitmap_size) perf_score *= 1.5;
  else if (q->bitmap_size * 3 < avg_bitmap_size) perf_score *= 0.25;
  else if (q->bitmap_size * 2 < avg_bitmap_size) perf_score *= 0.5;
  else if (q->bitmap_size * 1.5 < avg_bitmap_size) perf_score *= 0.75;

  /* Adjust score based on handicap. Handicap is proportional to how late
     in the game we learned about this path. Latecomers are allowed to run
     for a bit longer until they catch up with the rest. */

  if (q->handicap >= 4) {

    perf_score *= 4;
    q->handicap -= 4;

  } else if (q->handicap) {

    perf_score *= 2;
    q->handicap--;

  }

  /* Final adjustment based on input depth, under the assumption that fuzzing
     deeper test cases is more likely to reveal stuff that can't be
     discovered with traditional fuzzers. */

  switch (q->depth) {

    case 0 ... 3:   break;
    case 4 ... 7:   perf_score *= 2; break;
    case 8 ... 13:  perf_score *= 4; break;
    case 14 ... 25: perf_score *= 6; break;
    default:        perf_score *= 8;

  }

  /* Make sure that we don't go over limit. */

  if (perf_score > HAVOC_MAX_MULT * 100) perf_score = HAVOC_MAX_MULT * 100;

  return perf_score;

}



/* Grab interesting test cases from other fuzzers. */

static void sync_fuzzers(struct g* G, char** argv) {

  DIR* sd;
  struct dirent* sd_ent;
  u32 sync_cnt = 0;

  sd = opendir(G->sync_dir);
  if (!sd) PFATAL("Unable to open '%s'", G->sync_dir);

  G->stage_max = G->stage_cur = 0;
  G->cur_depth = 0;

  /* Look at the entries created for every other fuzzer in the sync directory. */

  while ((sd_ent = readdir(sd))) {

    static u8 stage_tmp[128];

    DIR* qd;
    struct dirent* qd_ent;
    u8 *qd_path, *qd_synced_path;
    u32 min_accept = 0, next_min_accept;

    s32 id_fd;

    /* Skip dot files and our own output directory. */

    if (sd_ent->d_name[0] == '.' || !strcmp(G->sync_id, sd_ent->d_name)) continue;

    /* Skip anything that doesn't have a queue/ subdirectory. */

    qd_path = alloc_printf("%s/%s/queue", G->sync_dir, sd_ent->d_name);

    if (!(qd = opendir(qd_path))) {
      ck_free(qd_path);
      continue;
    }

    /* Retrieve the ID of the last seen test case. */

    qd_synced_path = alloc_printf("%s/.synced/%s", G->out_dir, sd_ent->d_name);

    id_fd = open(qd_synced_path, O_RDWR | O_CREAT, 0600);

    if (id_fd < 0) PFATAL("Unable to create '%s'", qd_synced_path);

    if (read(id_fd, &min_accept, sizeof(u32)) > 0) 
      lseek(id_fd, 0, SEEK_SET);

    next_min_accept = min_accept;

    /* Show stats */    

    sprintf(stage_tmp, "sync %u", ++sync_cnt);
    G->stage_name = stage_tmp;
    G->stage_cur  = 0;
    G->stage_max  = 0;

    /* For every file queued by this fuzzer, parse ID and see if we have looked at
       it before; exec a test case if not. */

    while ((qd_ent = readdir(qd))) {

      u8* path;
      s32 fd;
      struct stat st;

      if (qd_ent->d_name[0] == '.' ||
          sscanf(qd_ent->d_name, CASE_PREFIX "%06u", &G->syncing_case) != 1 || 
          G->syncing_case < min_accept) continue;

      /* OK, sounds like a new one. Let's give it a try. */

      if (G->syncing_case >= next_min_accept)
        next_min_accept = G->syncing_case + 1;

      path = alloc_printf("%s/%s", qd_path, qd_ent->d_name);

      fd = open(path, O_RDONLY);
      if (fd < 0) PFATAL("Unable to open '%s'", path);

      if (fstat(fd, &st)) PFATAL("fstat() failed");

      /* Ignore zero-sized or oversized files. */

      if (st.st_size && st.st_size <= MAX_FILE) {

        u8  fault;
        u8* mem = mmap(0, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);

        if (mem == MAP_FAILED) PFATAL("Unable to mmap '%s'", path);

        /* See what happens. We rely on save_if_interesting() to catch major
           errors and save the test case. */

        write_to_testcase(G, mem, st.st_size);

        fault = run_target(G, argv, &G->kill_signal, &G->total_execs,
                           &G->stop_soon, &G->child_timed_out, &G->child_pid,
                           G->trace_bits);

        if (G->stop_soon) return;

        G->syncing_party = sd_ent->d_name;
        G->queued_imported += save_if_interesting(G, argv, mem, st.st_size, fault);
        G->syncing_party = 0;

        munmap(mem, st.st_size);

        if (!(G->stage_cur++ % G->stats_update_freq)) show_stats(G);

      }

      ck_free(path);
      close(fd);

    }

    ck_write(id_fd, &next_min_accept, sizeof(u32), qd_synced_path);

    close(id_fd);
    closedir(qd);
    ck_free(qd_path);
    ck_free(qd_synced_path);
    
  }  

  closedir(sd);

}


/* Handle stop signal (Ctrl-C, etc). */

static void handle_stop_sig(int sig) {

  *stop_soon_ptr = 1;

  if (*child_pid_ptr > 0) kill(*child_pid_ptr, SIGKILL);
  if (*forksrv_pid_ptr > 0) kill(*forksrv_pid_ptr, SIGKILL);

}


/* Handle skip request (SIGUSR1). */

static void handle_skipreq(int sig) {

  *skip_requested_ptr = 1;

}

/* Handle timeout (SIGALRM). */

static void handle_timeout(int sig) {

  if (*child_pid_ptr > 0) {

    *child_timed_out_ptr = 1; 
    kill(*child_pid_ptr, SIGKILL);

  } else if (*child_pid_ptr == -1 && *forksrv_pid_ptr > 0) {

    *child_timed_out_ptr = 1; 
    kill(*forksrv_pid_ptr, SIGKILL);

  }

}


/* Do a PATH search and find target binary to see that it exists and
   isn't a shell script - a common and painful mistake. We also check for
   a valid ELF header and for evidence of AFL instrumentation. */

static void check_binary(struct g* G, u8* fname) {

  u8* env_path = 0;
  struct stat st;

  s32 fd;
  u8* f_data;
  u32 f_len = 0;

  ACTF("Validating target binary...");

  if (strchr(fname, '/') || !(env_path = getenv("PATH"))) {

    G->target_path = ck_strdup(fname);
    if (stat(G->target_path, &st) || !S_ISREG(st.st_mode) ||
        !(st.st_mode & 0111) || (f_len = st.st_size) < 4)
      FATAL("Program '%s' not found or not executable", fname);

  } else {

    while (env_path) {

      u8 *cur_elem, *delim = strchr(env_path, ':');

      if (delim) {

        cur_elem = ck_alloc(delim - env_path + 1);
        memcpy(cur_elem, env_path, delim - env_path);
        delim++;

      } else cur_elem = ck_strdup(env_path);

      env_path = delim;

      if (cur_elem[0])
        G->target_path = alloc_printf("%s/%s", cur_elem, fname);
      else
        G->target_path = ck_strdup(fname);

      ck_free(cur_elem);

      if (!stat(G->target_path, &st) && S_ISREG(st.st_mode) &&
          (st.st_mode & 0111) && (f_len = st.st_size) >= 4) break;

      ck_free(G->target_path);
      G->target_path = 0;

    }

    if (!G->target_path) FATAL("Program '%s' not found or not executable", fname);

  }

  if (getenv("AFL_SKIP_BIN_CHECK")) return;

  /* Check for blatant user errors. */

  if ((!strncmp(G->target_path, "/tmp/", 5) && !strchr(G->target_path + 5, '/')) ||
      (!strncmp(G->target_path, "/var/tmp/", 9) && !strchr(G->target_path + 9, '/')))
     FATAL("Please don't keep binaries in /tmp or /var/tmp");

  fd = open(G->target_path, O_RDONLY);

  if (fd < 0) PFATAL("Unable to open '%s'", G->target_path);

  f_data = mmap(0, f_len, PROT_READ, MAP_PRIVATE, fd, 0);

  if (f_data == MAP_FAILED) PFATAL("Unable to mmap file '%s'", G->target_path);

  close(fd);

  if (f_data[0] == '#' && f_data[1] == '!') {

    SAYF("\n" cLRD "[-] " cRST
         "Oops, the target binary looks like a shell script. Some build systems will\n"
         "    sometimes generate shell stubs for dynamically linked programs; try static\n"
         "    library mode (./configure --disable-shared) if that's the case.\n\n"

         "    Another possible cause is that you are actually trying to use a shell\n" 
         "    wrapper around the fuzzed component. Invoking shell can slow down the\n" 
         "    fuzzing process by a factor of 20x or more; it's best to write the wrapper\n"
         "    in a compiled language instead.\n");

    FATAL("Program '%s' is a shell script", G->target_path);

  }

#ifndef __APPLE__

  if (f_data[0] != 0x7f || memcmp(f_data + 1, "ELF", 3))
    FATAL("Program '%s' is not an ELF binary", G->target_path);

#else

  if (f_data[0] != 0xCF || f_data[1] != 0xFA || f_data[2] != 0xED)
    FATAL("Program '%s' is not a 64-bit Mach-O binary", G->target_path);

#endif /* ^!__APPLE__ */

  if (!G->qemu_mode && !G->dumb_mode &&
      !memmem(f_data, f_len, SHM_ENV_VAR, strlen(SHM_ENV_VAR) + 1)) {

    SAYF("\n" cLRD "[-] " cRST
         "Looks like the target binary is not instrumented! The fuzzer depends on\n"
         "    compile-time instrumentation to isolate interesting test cases while\n"
         "    mutating the input data. For more information, and for tips on how to\n"
         "    instrument binaries, please see %s/README.\n\n"

         "    When source code is not available, you may be able to leverage QEMU\n"
         "    mode support. Consult the README for tips on how to enable this.\n"

         "    (It is also possible to use afl-fuzz as a traditional, \"dumb\" fuzzer.\n"
         "    For that, you can use the -n option - but expect much worse results.)\n",
         G->doc_path);

    FATAL("No instrumentation detected");

  }

  if (G->qemu_mode &&
      memmem(f_data, f_len, SHM_ENV_VAR, strlen(SHM_ENV_VAR) + 1)) {

    SAYF("\n" cLRD "[-] " cRST
         "This program appears to be instrumented with afl-gcc, but is being run in\n"
         "    QEMU mode (-Q). This is probably not what you want - this setup will be\n"
         "    slow and offer no practical benefits.\n");

    FATAL("Instrumentation found in -Q mode");

  }

  if (memmem(f_data, f_len, "libasan.so", 10) ||
      memmem(f_data, f_len, "__msan_init", 11)) G->uses_asan = 1;

  if (munmap(f_data, f_len)) PFATAL("unmap() failed");

}


/* Trim and possibly create a banner for the run. */

static void fix_up_banner(struct g* G, u8* name) {

  if (!G->use_banner) {

    if (G->sync_id) {

      G->use_banner = G->sync_id;

    } else {

      u8* trim = strrchr(name, '/');
      if (!trim) G->use_banner = name; else G->use_banner = trim + 1;

    }

  }

  if (strlen(G->use_banner) > 40) {

    u8* tmp = ck_alloc(44);
    sprintf(tmp, "%.40s...", G->use_banner);
    G->use_banner = tmp;

  }

}


/* Check if we're on TTY. */

static void check_if_tty(struct g* G) {

  struct winsize ws;

  if (ioctl(1, TIOCGWINSZ, &ws)) {

    if (errno == ENOTTY) {
      OKF("Looks like we're not running on a tty, so I'll be a bit less verbose.");
      G->not_on_tty = 1;
    }

    return;
  }

}


/* Check terminal dimensions after resize. */

static void check_term_size(struct g* G) {

  struct winsize ws;

  G->term_too_small = 0;

  if (ioctl(1, TIOCGWINSZ, &ws)) return;

  if (ws.ws_row < 25 || ws.ws_col < 80) G->term_too_small = 1;

}



/* Display usage hints. */

static void usage(struct g* G, u8* argv0) {

  SAYF("\n%s [ options ] -- /path/to/fuzzed_app [ ... ]\n\n"

       "Required parameters:\n\n"

       "  -i dir        - input directory with test cases\n"
       "  -o dir        - output directory for fuzzer findings\n\n"

       "Execution control settings:\n\n"

       "  -f file       - location read by the fuzzed program (stdin)\n"
       "  -t msec       - timeout for each run (auto-scaled, 50-%u ms)\n"
       "  -m megs       - memory limit for child process (%u MB)\n"
       "  -Q            - use binary-only instrumentation (QEMU mode)\n\n"     
 
       "Fuzzing behavior settings:\n\n"

       "  -d            - quick & dirty mode (skips deterministic steps)\n"
       "  -n            - fuzz without instrumentation (dumb mode)\n"
       "  -x dir        - optional fuzzer dictionary (see README)\n\n"

       "Other stuff:\n\n"

       "  -T text       - text banner to show on the screen\n"
       "  -M / -S id    - distributed mode (see parallel_fuzzing.txt)\n"
       "  -C            - crash exploration mode (the peruvian rabbit thing)\n\n"

       "For additional tips, please consult %s/README.\n\n",

       argv0, EXEC_TIMEOUT, MEM_LIMIT, G->doc_path);

  exit(1);

}


/* Prepare output directories and fds. */

static void setup_dirs_fds(struct g* G) {

  u8* tmp;
  s32 fd;

  ACTF("Setting up output directories...");

  if (G->sync_id && mkdir(G->sync_dir, 0700) && errno != EEXIST)
      PFATAL("Unable to create '%s'", G->sync_dir);

  if (mkdir(G->out_dir, 0700)) {

    if (errno != EEXIST) PFATAL("Unable to create '%s'", G->out_dir);

    maybe_delete_out_dir(G);

  } else {

    if (G->in_place_resume)
      FATAL("Resume attempted but old output directory not found");

    G->out_dir_fd = open(G->out_dir, O_RDONLY);

#ifndef __sun

    if (G->out_dir_fd < 0 || flock(G->out_dir_fd, LOCK_EX | LOCK_NB))
      PFATAL("Unable to flock() output directory.");

#endif /* !__sun */

  }

  /* Queue directory for any starting & discovered paths. */

  tmp = alloc_printf("%s/queue", G->out_dir);
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* Top-level directory for queue metadata used for session
     resume and related tasks. */

  tmp = alloc_printf("%s/queue/.state/", G->out_dir);
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* Directory for flagging queue entries that went through
     deterministic fuzzing in the past. */

  tmp = alloc_printf("%s/queue/.state/deterministic_done/", G->out_dir);
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* Directory with the auto-selected dictionary entries. */

  tmp = alloc_printf("%s/queue/.state/auto_extras/", G->out_dir);
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* The set of paths currently deemed redundant. */

  tmp = alloc_printf("%s/queue/.state/redundant_edges/", G->out_dir);
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* The set of paths showing variable behavior. */

  tmp = alloc_printf("%s/queue/.state/variable_behavior/", G->out_dir);
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* Sync directory for keeping track of cooperating fuzzers. */

  if (G->sync_id) {

    tmp = alloc_printf("%s/.synced/", G->out_dir);
    if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
    ck_free(tmp);

  }

  /* All recorded crashes. */

  tmp = alloc_printf("%s/crashes", G->out_dir);
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* All recorded hangs. */

  tmp = alloc_printf("%s/hangs", G->out_dir);
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* Generally useful file descriptors. */

  G->dev_null_fd = open("/dev/null", O_RDWR);
  if (G->dev_null_fd < 0) PFATAL("Unable to open /dev/null");

  G->dev_urandom_fd = open("/dev/urandom", O_RDONLY);
  if (G->dev_urandom_fd < 0) PFATAL("Unable to open /dev/urandom");

  /* Gnuplot output file. */

  tmp = alloc_printf("%s/plot_data", G->out_dir);
  fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  G->plot_file = fdopen(fd, "w");
  if (!G->plot_file) PFATAL("fdopen() failed");

  fprintf(G->plot_file, "# unix_time, cycles_done, cur_path, paths_total, "
                     "pending_total, pending_favs, map_size, unique_crashes, "
                     "unique_hangs, G->max_depth, execs_per_sec\n");
                     /* ignore errors */

}


/* Setup the output file for fuzzed data, if not using -f. */

static void setup_stdio_file(struct g* G) {

  u8* fn = alloc_printf("%s/.cur_input", G->out_dir);

  unlink(fn); /* Ignore errors */

  G->out_fd = open(fn, O_RDWR | O_CREAT | O_EXCL, 0600);

  if (G->out_fd < 0) PFATAL("Unable to create '%s'", fn);

  ck_free(fn);

}


/* Make sure that core dumps don't go to a program. */

static void check_crash_handling(void) {

#ifdef __APPLE__

  /* Yuck! There appears to be no simple C API to query for the state of 
     loaded daemons on MacOS X, and I'm a bit hesitant to do something
     more sophisticated, such as disabling crash reporting via Mach ports,
     until I get a box to test the code. So, for now, we check for crash
     reporting the awful way. */
  
  if (system("launchctl list 2>/dev/null | grep -q '\\.ReportCrash$'")) return;

  SAYF("\n" cLRD "[-] " cRST
       "Whoops, your system is configured to forward crash notifications to an\n"
       "    external crash reporting utility. This will cause issues due to the\n"
       "    extended delay between the fuzzed binary malfunctioning and this fact\n"
       "    being relayed to the fuzzer via the standard waitpid() API.\n\n"
       "    To avoid having crashes misinterpreted as hangs, please run the\n" 
       "    following commands:\n\n"

       "    SL=/System/Library; PL=com.apple.ReportCrash\n"
       "    launchctl unload -w ${SL}/LaunchAgents/${PL}.plist\n"
       "    sudo launchctl unload -w ${SL}/LaunchDaemons/${PL}.Root.plist\n");

  FATAL("Crash reporter detected");

#else

  /* This is Linux specific, but I don't think there's anything equivalent on
     *BSD, so we can just let it slide for now. */

  s32 fd = open("/proc/sys/kernel/core_pattern", O_RDONLY);
  u8  fchar;

  if (fd < 0) return;

  ACTF("Checking core_pattern...");

  if (read(fd, &fchar, 1) == 1 && fchar == '|') {

    SAYF("\n" cLRD "[-] " cRST
         "Hmm, your system is configured to send core dump notifications to an\n"
         "    external utility. This will cause issues due to an extended delay\n"
         "    between the fuzzed binary malfunctioning and this information being\n"
         "    eventually relayed to the fuzzer via the standard waitpid() API.\n\n"

         "    To avoid having crashes misinterpreted as hangs, please log in as root\n" 
         "    and temporarily modify /proc/sys/kernel/core_pattern, like so:\n\n"

         "    echo core >/proc/sys/kernel/core_pattern\n");

    FATAL("Pipe at the beginning of 'core_pattern'");

  }
 
  close(fd);

#endif /* ^__APPLE__ */

}


/* Check CPU governor. */

static void check_cpu_governor(void) {

  FILE* f;
  u8 tmp[128];
  u64 min = 0, max = 0;

  if (getenv("AFL_SKIP_CPUFREQ")) return;

  f = fopen("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor", "r");
  if (!f) return;

  ACTF("Checking CPU scaling governor...");

  if (!fgets(tmp, 128, f)) PFATAL("fgets() failed");

  fclose(f);

  if (!strncmp(tmp, "perf", 4)) return;

  f = fopen("/sys/devices/system/cpu/cpu0/cpufreq/scaling_min_freq", "r");

  if (f) {
    if (fscanf(f, "%llu", &min) != 1) min = 0;
    fclose(f);
  }

  f = fopen("/sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq", "r");

  if (f) {
    if (fscanf(f, "%llu", &max) != 1) max = 0;
    fclose(f);
  }

  if (min == max) return;

  SAYF("\n" cLRD "[-] " cRST
       "Whoops, your system uses on-demand CPU frequency scaling, adjusted\n"
       "    between %llu and %llu MHz. Unfortunately, the scaling algorithm in the\n"
       "    kernel is imperfect and can miss the short-lived processes spawned by\n"
       "    afl-fuzz. To keep things moving, run these commands as root:\n\n"

       "    cd /sys/devices/system/cpu\n"
       "    echo performance | tee cpu*/cpufreq/scaling_governor\n\n"

       "    You can later go back to the original state by replacing 'performance' with\n"
       "    'ondemand'. If you don't want to change the settings, set AFL_SKIP_CPUFREQ\n"
       "    to make afl-fuzz skip this check - but expect some performance drop.\n",
       min / 1024, max / 1024);

  FATAL("Suboptimal CPU scaling governor");

}


/* Count the number of logical CPU cores. */

static void get_core_count(struct g* G) {

  u32 cur_runnable = 0;

#if defined(__APPLE__) || defined(__FreeBSD__) || defined (__OpenBSD__)

  size_t s = sizeof(G->cpu_core_count);

  /* On *BSD systems, we can just use a sysctl to get the number of CPUs. */

#ifdef __APPLE__

  if (sysctlbyname("hw.logicalcpu", &G->cpu_core_count, &s, NULL, 0) < 0)
    return;

#else

  int s_name[2] = { CTL_HW, HW_NCPU };

  if (sysctl(s_name, 2, &G->cpu_core_count, &s, NULL, 0) < 0) return;

#endif /* ^__APPLE__ */

#else

  /* On Linux, a simple way is to look at /proc/stat, especially since we'd
     be parsing it anyway for other reasons later on. */

  FILE* f = fopen("/proc/stat", "r");
  u8 tmp[1024];

  if (!f) return;

  while (fgets(tmp, sizeof(tmp), f))
    if (!strncmp(tmp, "cpu", 3) && isdigit(tmp[3])) G->cpu_core_count++;

  fclose(f);
  
#endif /* ^(__APPLE__ || __FreeBSD__ || __OpenBSD__) */

  if (G->cpu_core_count) {

    cur_runnable = (u32)get_runnable_processes();

#if defined(__APPLE__) || defined(__FreeBSD__) || defined (__OpenBSD__)

    /* Add ourselves, since the 1-minute average doesn't include that yet. */

    cur_runnable++;

#endif /* __APPLE__ || __FreeBSD__ || __OpenBSD__ */

    OKF("You have %u CPU cores and %u runnable tasks (utilization: %0.0f%%).",
        G->cpu_core_count, cur_runnable, cur_runnable * 100.0 / G->cpu_core_count);

    if (G->cpu_core_count > 1) {

      if (cur_runnable > G->cpu_core_count * 1.5) {

        WARNF("System under apparent load, performance may be spotty.");

      } else if (cur_runnable + 1 <= G->cpu_core_count) {

        OKF("Try parallel jobs - see %s/parallel_fuzzing.txt.", G->doc_path);
  
      }

    }

  } else WARNF("Unable to figure out the number of CPU cores.");

}


/* Validate and fix up G->out_dir and G->sync_dir when using -S. */

static void fix_up_sync(struct g* G) {

  u8* x = G->sync_id;

  if (G->dumb_mode)
    FATAL("-S / -M and -n are mutually exclusive");

  if (G->skip_deterministic) {

    if (G->force_deterministic)
      FATAL("use -S instead of -M -d");
    else
      FATAL("-S already implies -d");

  }

  while (*x) {

    if (!isalnum(*x) && *x != '_' && *x != '-')
      FATAL("Non-alphanumeric fuzzer ID specified via -S or -M");

    x++;

  }

  if (strlen(G->sync_id) > 32) FATAL("Fuzzer ID too long");

  x = alloc_printf("%s/%s", G->out_dir, G->sync_id);

  G->sync_dir = G->out_dir;
  G->out_dir  = x;

  if (!G->force_deterministic) {
    G->skip_deterministic = 1;
    G->use_splicing = 1;
  }

}


/* Handle screen resize (SIGWINCH). */

static void handle_resize(int sig) {
  *clear_screen_ptr = 1;
}


/* Check ASAN options. */

static void check_asan_opts(void) {
  u8* x = getenv("ASAN_OPTIONS");

  if (x && !strstr(x, "abort_on_error=1"))
    FATAL("Custom ASAN_OPTIONS set without abort_on_error=1 - please fix!");

  x = getenv("MSAN_OPTIONS");

  if (x && !strstr(x, "exit_code=" STRINGIFY(MSAN_ERROR)))
    FATAL("Custom MSAN_OPTIONS set without exit_code="
          STRINGIFY(MSAN_ERROR) " - please fix!");

} 


/* Detect @@ in args. */

static void detect_file_args(struct g* G, char** argv) {

  u32 i = 0;
  u8* cwd = getcwd(NULL, 0);

  if (!cwd) PFATAL("getcwd() failed");

  while (argv[i]) {

    u8* aa_loc = strstr(argv[i], "@@");

    if (aa_loc) {

      u8 *aa_subst, *n_arg;

      /* If we don't have a file name chosen yet, use a safe default. */

      if (!G->out_file)
        G->out_file = alloc_printf("%s/.cur_input", G->out_dir);

      /* Be sure that we're always using fully-qualified paths. */

      if (G->out_file[0] == '/') aa_subst = G->out_file;
      else aa_subst = alloc_printf("%s/%s", cwd, G->out_file);

      /* Construct a replacement argv value. */

      *aa_loc = 0;
      n_arg = alloc_printf("%s%s%s", argv[i], aa_subst, aa_loc + 2);
      argv[i] = n_arg;
      *aa_loc = '@';

      if (G->out_file[0] != '/') ck_free(aa_subst);

    }

    i++;

  }

  free(cwd); /* not tracked */

}


/* Set up signal handlers. More complicated that needs to be, because libc on
   Solaris doesn't resume interrupted reads(), sets SA_RESETHAND when you call
   siginterrupt(), and does other stupid things. */

static void setup_signal_handlers(struct g* G) {

  struct sigaction sa;

  child_pid_ptr = &G->child_pid;
  forksrv_pid_ptr = &G->forksrv_pid;
  stop_soon_ptr = &G->stop_soon;
  skip_requested_ptr = &G->skip_requested;
  child_timed_out_ptr = &G->child_timed_out;
  clear_screen_ptr = &G->clear_screen;

  sa.sa_handler   = NULL;
  sa.sa_flags     = SA_RESTART;
  sa.sa_sigaction = NULL;

  sigemptyset(&sa.sa_mask);

  /* Various ways of saying "stop". */

  sa.sa_handler = handle_stop_sig;
  sigaction(SIGHUP, &sa, NULL);
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);

  /* Exec timeout notifications. */

  sa.sa_handler = handle_timeout;
  sigaction(SIGALRM, &sa, NULL);

  /* Window resize */

  sa.sa_handler = handle_resize;
  sigaction(SIGWINCH, &sa, NULL);

  /* SIGUSR1: skip entry */

  sa.sa_handler = handle_skipreq;
  sigaction(SIGUSR1, &sa, NULL);

  /* Things we don't care about. */

  sa.sa_handler = SIG_IGN;
  sigaction(SIGTSTP, &sa, NULL);
  sigaction(SIGPIPE, &sa, NULL);

}


/* Rewrite argv for QEMU. */

static char** get_qemu_argv(struct g* G, u8* own_loc, char** argv, int argc) {

  char** new_argv = ck_alloc(sizeof(char*) * (argc + 4));
  u8 *tmp, *cp, *rsl, *own_copy;

  memcpy(new_argv + 3, argv + 1, sizeof(char*) * argc);

  new_argv[2] = G->target_path;
  new_argv[1] = "--";

  /* Now we need to actually find the QEMU binary to put in argv[0]. */

  tmp = getenv("AFL_PATH");

  if (tmp) {

    cp = alloc_printf("%s/afl-qemu-trace", tmp);

    if (access(cp, X_OK))
      FATAL("Unable to find '%s'", tmp);

    G->target_path = new_argv[0] = cp;
    return new_argv;

  }

  own_copy = ck_strdup(own_loc);
  rsl = strrchr(own_copy, '/');

  if (rsl) {

    *rsl = 0;

    cp = alloc_printf("%s/afl-qemu-trace", own_copy);
    ck_free(own_copy);

    if (!access(cp, X_OK)) {

      G->target_path = new_argv[0] = cp;
      return new_argv;

    }

  } else ck_free(own_copy);

  if (!access(BIN_PATH "/afl-qemu-trace", X_OK)) {

    G->target_path = new_argv[0] = ck_strdup(BIN_PATH "/afl-qemu-trace");
    return new_argv;

  }

  SAYF("\n" cLRD "[-] " cRST
       "Oops, unable to find the 'afl-qemu-trace' binary. The binary must be built\n"
       "    separately by following the instructions in G->qemu_mode/README.qemu. If you\n"
       "    already have the binary installed, you may need to specify AFL_PATH in the\n"
       "    environment.\n\n"

       "    Of course, even without QEMU, afl-fuzz can still work with binaries that are\n"
       "    instrumented at compile time with afl-gcc. It is also possible to use it as a\n"
       "    traditional \"dumb\" fuzzer by specifying '-n' in the command line.\n");

  FATAL("Failed to locate 'afl-qemu-trace'.");

}


/* Make a copy of the current command line. */

static void save_cmdline(struct g* G, u32 argc, char** argv) {

  u32 len = 1, i;
  u8* buf;

  for (i = 0; i < argc; i++)
    len += strlen(argv[i]) + 1;
  
  buf = G->orig_cmdline = ck_alloc(len);

  for (i = 0; i < argc; i++) {

    u32 l = strlen(argv[i]);

    memcpy(buf, argv[i], l);
    buf += l;

    if (i != argc - 1) *(buf++) = ' ';

  }

  *buf = 0;

}


/* Main entry point */

int main(int argc, char** argv) {

  struct g* G = ck_alloc(sizeof(*G));

  s32 opt;
  u64 prev_queued = 0;
  u32 sync_interval_cnt = 0, seek_to;
  u8  *extras_dir = 0;
  u8  mem_limit_given = 0;

  char** use_argv;

  init_G(G);

  SAYF(cCYA "afl-fuzz " cBRI VERSION cRST " by <lcamtuf@google.com>\n");

  G->doc_path = access(DOC_PATH, F_OK) ? "docs" : DOC_PATH;

  while ((opt = getopt(argc, argv, "+i:o:f:m:t:T:dnCB:S:M:x:Q")) > 0)

    switch (opt) {

      case 'i':

        if (G->in_dir) FATAL("Multiple -i options not supported");
        G->in_dir = optarg;

        if (!strcmp(G->in_dir, "-")) G->in_place_resume = 1;

        break;

      case 'o': /* output dir */

        if (G->out_dir) FATAL("Multiple -o options not supported");
        G->out_dir = optarg;
        break;

      case 'M':

        G->force_deterministic = 1;
        /* Fall through */

      case 'S': /* sync ID */

        if (G->sync_id) FATAL("Multiple -S or -M options not supported");
        G->sync_id = optarg;
        break;

      case 'f': /* target file */

        if (G->out_file) FATAL("Multiple -f options not supported");
        G->out_file = optarg;
        break;

      case 'x':

        if (extras_dir) FATAL("Multiple -x options not supported");
        extras_dir = optarg;
        break;

      case 't': {

          u8 suffix = 0;

          if (G->timeout_given) FATAL("Multiple -t options not supported");

          if (sscanf(optarg, "%u%c", &G->exec_tmout, &suffix) < 1 ||
              optarg[0] == '-') FATAL("Bad syntax used for -t");

          if (G->exec_tmout < 5) FATAL("Dangerously low value of -t");

          if (suffix == '+') G->timeout_given = 2; else G->timeout_given = 1;

          break;

      }

      case 'm': {

          u8 suffix = 'M';

          if (mem_limit_given) FATAL("Multiple -m options not supported");
          mem_limit_given = 1;

          if (!strcmp(optarg, "none")) {

            G->mem_limit = 0;
            break;

          }

          if (sscanf(optarg, "%llu%c", &G->mem_limit, &suffix) < 1 ||
              optarg[0] == '-') FATAL("Bad syntax used for -m");

          switch (suffix) {

            case 'T': G->mem_limit *= 1024 * 1024; break;
            case 'G': G->mem_limit *= 1024; break;
            case 'k': G->mem_limit /= 1024; break;
            case 'M': break;

            default:  FATAL("Unsupported suffix or bad syntax for -m");

          }

          if (G->mem_limit < 5) FATAL("Dangerously low value of -m");

          if (sizeof(rlim_t) == 4 && G->mem_limit > 2000)
            FATAL("Value of -m out of range on 32-bit systems");

        }

        break;

      case 'd':

        if (G->skip_deterministic) FATAL("Multiple -d options not supported");
        G->skip_deterministic = 1;
        G->use_splicing = 1;
        break;

      case 'B':

        /* This is a secret undocumented option! It is useful if you find
           an interesting test case during a normal fuzzing process, and want
           to mutate it without rediscovering any of the test cases already
           found during an earlier run.

           To use this mode, you need to point -B to the fuzz_bitmap produced
           by an earlier run for the exact same binary... and that's it.

           I only used this once or twice to get variants of a particular
           file, so I'm not making this an official setting. */

        if (G->in_bitmap) FATAL("Multiple -B options not supported");

        G->in_bitmap = optarg;
        read_bitmap(G, G->in_bitmap);
        break;

      case 'C':

        if (G->crash_mode) FATAL("Multiple -C options not supported");
        G->crash_mode = FAULT_CRASH;
        break;

      case 'n':

        if (G->dumb_mode) FATAL("Multiple -n options not supported");
        if (getenv("AFL_DUMB_FORKSRV")) G->dumb_mode = 2 ; else G->dumb_mode = 1;

        break;

      case 'T':

        if (G->use_banner) FATAL("Multiple -T options not supported");
        G->use_banner = optarg;
        break;

      case 'Q':

        if (G->qemu_mode) FATAL("Multiple -Q options not supported");
        G->qemu_mode = 1;

        if (!mem_limit_given) G->mem_limit = MEM_LIMIT_QEMU;

        break;

      default:

        usage(G, argv[0]);

    }

  if (optind == argc || !G->in_dir || !G->out_dir) usage(G, argv[0]);

  setup_signal_handlers(G);
  check_asan_opts();

  if (G->sync_id) fix_up_sync(G);

  if (!strcmp(G->in_dir, G->out_dir))
    FATAL("Input and output directories can't be the same");

  if (G->dumb_mode) {

    if (G->crash_mode) FATAL("-C and -n are mutually exclusive");
    if (G->qemu_mode)  FATAL("-Q and -n are mutually exclusive");

  }

  if (getenv("AFL_NO_FORKSRV")) G->no_forkserver    = 1;
  if (getenv("AFL_NO_CPU_RED")) G->no_cpu_meter_red = 1;

  if (getenv("AFL_NO_VAR_CHECK") || getenv("AFL_PERSISTENT"))
    G->no_var_check = 1;

  if (G->dumb_mode == 2 && G->no_forkserver)
    FATAL("AFL_DUMB_FORKSRV and AFL_NO_FORKSRV are mutually exclusive");

  save_cmdline(G, argc, argv);

  fix_up_banner(G, argv[optind]);

  check_if_tty(G);

  get_core_count(G);
  check_crash_handling();
  check_cpu_governor();

  setup_post(G);
  setup_shm(G);

  setup_dirs_fds(G);
  read_testcases(G);
  load_auto(G);

  pivot_inputs(G);

  if (extras_dir) load_extras(G, extras_dir);

  if (!G->timeout_given) find_timeout(G);

  detect_file_args(G, argv + optind + 1);

  if (!G->out_file) setup_stdio_file(G);

  check_binary(G, argv[optind]);

  G->start_time = get_cur_time();

  if (G->qemu_mode)
    use_argv = get_qemu_argv(G, argv[0], argv + optind, argc - optind);
  else
    use_argv = argv + optind;

  perform_dry_run(G, use_argv);

  cull_queue(G);

  show_init_stats(G);

  seek_to = find_start_position(G);

  write_stats_file(G, 0, 0);
  save_auto(G);

  if (G->stop_soon) goto stop_fuzzing;

  /* Woop woop woop */

  if (!G->not_on_tty) {
    sleep(4);
    G->start_time += 4000;
    if (G->stop_soon) goto stop_fuzzing;
  }

  while (1) {

    u8 skipped_fuzz;

    cull_queue(G);

    if (!G->queue_cur) {

      G->queue_cycle++;
      G->current_entry     = 0;
      G->cur_skipped_paths = 0;
      G->queue_cur         = G->queue;

      while (seek_to) {
        G->current_entry++;
        seek_to--;
        G->queue_cur = G->queue_cur->next;
      }

      show_stats(G);

      if (G->not_on_tty) {
        ACTF("Entering queue cycle %llu.", G->queue_cycle);
        fflush(stdout);
      }

      /* If we had a full queue cycle with no new finds, try
         recombination strategies next. */

      if (G->queued_paths == prev_queued) {

        if (G->use_splicing) G->cycles_wo_finds++; else G->use_splicing = 1;

      } else G->cycles_wo_finds = 0;

      prev_queued = G->queued_paths;

      if (G->sync_id && G->queue_cycle == 1 && getenv("AFL_IMPORT_FIRST"))
        sync_fuzzers(G, use_argv);

    }

    skipped_fuzz = fuzz_one(G, use_argv);

    if (!G->stop_soon && G->sync_id && !skipped_fuzz) {
      
      if (!(sync_interval_cnt++ % SYNC_INTERVAL))
        sync_fuzzers(G, use_argv);

    }

    if (G->stop_soon) break;

    G->queue_cur = G->queue_cur->next;
    G->current_entry++;

  }

  if (G->queue_cur) show_stats(G);

  write_bitmap(G);
  write_stats_file(G, 0, 0);
  save_auto(G);

stop_fuzzing:

  SAYF(CURSOR_SHOW cLRD "\n\n+++ Testing aborted by user +++\n" cRST);

  /* Running for more than 30 minutes but still doing first cycle? */

  if (G->queue_cycle == 1 && get_cur_time() - G->start_time > 30 * 60 * 1000) {

    SAYF("\n" cYEL "[!] " cRST
           "Stopped during the first cycle, results may be incomplete.\n"
           "    (For info on resuming, see %s/README.)\n", G->doc_path);

  }

  fclose(G->plot_file);
  destroy_queue(G);
  destroy_extras(G);
  ck_free(G->target_path);

  alloc_report();

  OKF("We're done here. Have a nice day!\n");

  exit(0);

}
