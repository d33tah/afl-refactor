#include "afl-fuzz.h"
#include "debug.h"

#include <unistd.h>
#include <string.h>

/* Generate a random number (from 0 to limit - 1). This may
   have slight bias. */

inline u32 UR(struct g* G, u32 limit) {

  if (!G->rand_cnt--) {

    u32 seed[2];

    ck_read(G->dev_urandom_fd, &seed, sizeof(seed), "/dev/urandom");

    srandom(seed[0]);
    G->rand_cnt = (RESEED_RNG / 2) + (seed[1] % RESEED_RNG);

  }

  return random() % limit;

}


