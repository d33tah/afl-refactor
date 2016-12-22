#include "shm-instr.h"
#include "debug.h"
#include "util.h"
#include "alloc-inl.h"

#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/shm.h>

static s32 *shm_id_ptr;

/* Get rid of shared memory (atexit handler). */

static void remove_shm(void) {

  shmctl(*shm_id_ptr, IPC_RMID, NULL);

}

/* Configure shared memory and G->virgin_bits. This is called at startup. */

void setup_shm(struct g* G) {

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

void simplify_trace(u64* mem) {

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



/* Compact trace bytes into a smaller bitmap. We effectively just drop the
   count information here. This is called only sporadically, for some
   new paths. */

static void minimize_bits(u8* dst, const u8* src) {

  u32 i = 0;

  while (i < MAP_SIZE) {

    if (*(src++)) dst[i >> 3] |= 1 << (i & 7);
    i++;

  }

}


/* Destructively classify execution counts in a trace. This is used as a
   preprocessing step for any newly acquired traces. Called on every exec,
   must be fast. */

static u8 count_class_lookup[256] = {

  /* 0 - 3:       4 */ 0, 1, 2, 4,
  /* 4 - 7:      +4 */ AREP4(8),
  /* 8 - 15:     +8 */ AREP8(16),
  /* 16 - 31:   +16 */ AREP16(32),
  /* 32 - 127:  +96 */ AREP64(64), AREP32(64),
  /* 128+:     +128 */ AREP128(128)

};

#ifdef __x86_64__

static inline void classify_counts(u64* mem) {

  u32 i = MAP_SIZE >> 3;

  while (i--) {

    /* Optimize for sparse bitmaps. */

    if (*mem) {

      u8* mem8 = (u8*)mem;

      mem8[0] = count_class_lookup[mem8[0]];
      mem8[1] = count_class_lookup[mem8[1]];
      mem8[2] = count_class_lookup[mem8[2]];
      mem8[3] = count_class_lookup[mem8[3]];
      mem8[4] = count_class_lookup[mem8[4]];
      mem8[5] = count_class_lookup[mem8[5]];
      mem8[6] = count_class_lookup[mem8[6]];
      mem8[7] = count_class_lookup[mem8[7]];

    }

    mem++;

  }

}

#else

static inline void classify_counts(u32* mem) {

  u32 i = MAP_SIZE >> 2;

  while (i--) {

    /* Optimize for sparse bitmaps. */

    if (*mem) {

      u8* mem8 = (u8*)mem;

      mem8[0] = count_class_lookup[mem8[0]];
      mem8[1] = count_class_lookup[mem8[1]];
      mem8[2] = count_class_lookup[mem8[2]];
      mem8[3] = count_class_lookup[mem8[3]];

    }

    mem++;

  }

}

#endif /* ^__x86_64__ */


/* When we bump into a new path, we call this to see if the path appears
   more "favorable" than any of the existing ones. The purpose of the
   "favorables" is to have a minimal set of paths that trigger all the bits
   seen in the bitmap so far, and focus on fuzzing them at the expense of
   the rest.

   The first step of the process is to maintain a list of G->top_rated[] entries
   for every byte in the bitmap. We win that slot if there is no previous
   contender, or if the contender has a more favorable speed x size factor. */

void update_bitmap_score(const u8 *trace_bits, struct queue_entry* q,
                         struct queue_entry* top_rated[MAP_SIZE],
                         u8 *score_changed) {

  u32 i;
  u64 fav_factor = q->exec_us * q->len;

  /* For every byte set in G->trace_bits[], see if there is a previous winner,
     and how it compares to us. */

  for (i = 0; i < MAP_SIZE; i++)

    if (trace_bits[i]) {

       if (top_rated[i]) {

         /* Faster-executing or smaller test cases are favored. */

         if (fav_factor > top_rated[i]->exec_us * top_rated[i]->len) continue;

         /* Looks like we're going to win. Decrease ref count for the
            previous winner, discard its G->trace_bits[] if necessary. */

         if (!--top_rated[i]->tc_ref) {
           ck_free(top_rated[i]->trace_mini);
           top_rated[i]->trace_mini = 0;
         }

       }

       /* Insert ourselves as the new winner. */

       top_rated[i] = q;
       q->tc_ref++;

       if (!q->trace_mini) {
         q->trace_mini = ck_alloc(MAP_SIZE >> 3);
         minimize_bits(q->trace_mini, trace_bits);
       }

       *score_changed = 1;

     }

}


/* Execute target application, monitoring for timeouts. Return status
   information. The called program will update G->trace_bits[]. */

u8 run_target(const struct g* G, char** argv, u8 *kill_signal,
              u64 *total_execs, volatile u8* stop_soon,
              volatile u8* child_timed_out, s32 *child_pid, u8 *trace_bits) {

  static struct itimerval it;
  static u32 prev_timed_out = 0;

  int status = 0;
  u32 tb4;

  *child_timed_out = 0;

  /* After this memset, G->trace_bits[] are effectively volatile, so we
     must prevent any earlier operations from venturing into that
     territory. */

  memset(trace_bits, 0, MAP_SIZE);
  MEM_BARRIER();

  /* If we're running in "dumb" mode, we can't rely on the fork server
     logic compiled into the target program, so we will just keep calling
     execve(). There is a bit of code duplication between here and 
     init_forkserver(), but c'est la vie. */

  if (G->dumb_mode == 1 || G->no_forkserver) {

    *child_pid = fork();

    if (*child_pid < 0) PFATAL("fork() failed");

    if (!*child_pid) {

      struct rlimit r;

      if (G->mem_limit) {

        r.rlim_max = r.rlim_cur = ((rlim_t)G->mem_limit) << 20;

#ifdef RLIMIT_AS

        setrlimit(RLIMIT_AS, &r); /* Ignore errors */

#else

        setrlimit(RLIMIT_DATA, &r); /* Ignore errors */

#endif /* ^RLIMIT_AS */

      }

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

      /* On Linux, would be faster to use O_CLOEXEC. Maybe TODO. */

      close(G->dev_null_fd);
      close(G->out_dir_fd);
      close(G->dev_urandom_fd);
      close(fileno(G->plot_file));

      /* Set sane defaults for ASAN if nothing else specified. */

      setenv("ASAN_OPTIONS", "abort_on_error=1:"
                             "detect_leaks=0:"
                             "allocator_may_return_null=1", 0);

      setenv("MSAN_OPTIONS", "exit_code=" STRINGIFY(MSAN_ERROR) ":"
                             "msan_track_origins=0", 0);

      execv(G->target_path, argv);

      /* Use a distinctive bitmap value to tell the parent about execv()
         falling through. */

      *(u32*)trace_bits = EXEC_FAIL_SIG;
      exit(0);

    }

  } else {

    s32 res;

    /* In non-dumb mode, we have the fork server up and running, so simply
       tell it to have at it, and then read back PID. */

    if ((res = write(G->fsrv_ctl_fd, &prev_timed_out, 4)) != 4) {

      if (*stop_soon) return 0;
      RPFATAL(res, "Unable to request new process from fork server (OOM?)");

    }

    if ((res = read(G->fsrv_st_fd, child_pid, 4)) != 4) {

      if (*stop_soon) return 0;
      RPFATAL(res, "Unable to request new process from fork server (OOM?)");

    }

    if (*child_pid <= 0) FATAL("Fork server is misbehaving (OOM?)");

  }

  /* Configure timeout, as requested by user, then wait for child to terminate. */

  it.it_value.tv_sec = (G->exec_tmout / 1000);
  it.it_value.tv_usec = (G->exec_tmout % 1000) * 1000;

  setitimer(ITIMER_REAL, &it, NULL);

  /* The SIGALRM handler simply kills the G->child_pid and sets G->child_timed_out. */

  if (G->dumb_mode == 1 || G->no_forkserver) {

    if (waitpid(*child_pid, &status, 0) <= 0) PFATAL("waitpid() failed");

  } else {

    s32 res;

    if ((res = read(G->fsrv_st_fd, &status, 4)) != 4) {

      if (*stop_soon) return 0;
      RPFATAL(res, "Unable to communicate with fork server");

    }

  }

  *child_pid = 0;
  it.it_value.tv_sec = 0;
  it.it_value.tv_usec = 0;

  setitimer(ITIMER_REAL, &it, NULL);

  (*total_execs)++;

  /* Any subsequent operations on G->trace_bits must not be moved by the
     compiler below this point. Past this location, G->trace_bits[] behave
     very normally and do not have to be treated as volatile. */

  MEM_BARRIER();

  tb4 = *(u32*)trace_bits;

#ifdef __x86_64__
  classify_counts((u64*)trace_bits);
#else
  classify_counts((u32*)trace_bits);
#endif /* ^__x86_64__ */

  prev_timed_out = *child_timed_out;

  /* Report outcome to caller. */

  if (*child_timed_out) return FAULT_HANG;

  if (WIFSIGNALED(status) && !*stop_soon) {
    *kill_signal = WTERMSIG(status);
    return FAULT_CRASH;
  }

  /* A somewhat nasty hack for MSAN, which doesn't support abort_on_error and
     must use a special exit code. */

  if (G->uses_asan && WEXITSTATUS(status) == MSAN_ERROR) {
    *kill_signal = 0;
    return FAULT_CRASH;
  }

  if ((G->dumb_mode == 1 || G->no_forkserver) && tb4 == EXEC_FAIL_SIG)
    return FAULT_ERROR;

  return FAULT_NONE;

}


