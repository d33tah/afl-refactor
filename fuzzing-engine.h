#include "afl-fuzz.h"

u8 trim_case(struct g* G, char** argv, struct queue_entry* q, u8* in_buf);
u8 fuzz_one(struct g* G, char** argv);
void maybe_add_auto(struct g* G, u8* mem, u32 len);
u8 calibrate_case(struct g* G, char** argv, struct queue_entry* q,
                  u8* use_mem, u32 handicap, u8 from_queue);

