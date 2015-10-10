#include "afl-fuzz.h"

u8 fuzz_one(struct g* G, char** argv);
void maybe_add_auto(struct g* G, u8* mem, u32 len);
