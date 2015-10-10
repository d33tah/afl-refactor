#include "afl-fuzz.h"

/* Take the current entry from the queue, fuzz it for a while. This
   function is a tad too long... returns 0 if fuzzed successfully, 1 if
   skipped or bailed out. */

u8 fuzz_one(struct g* G, char** argv) {

  s32 len, fd, temp_len, i, j;
  u8  *in_buf, *out_buf, *orig_in, *ex_tmp, *eff_map = 0;
  u64 havoc_queued,  orig_hit_cnt, new_hit_cnt;
  u32 splice_cycle = 0, perf_score = 100, orig_perf, prev_cksum, eff_cnt = 1;

  u8  ret_val = 1;

  u8  a_collect[MAX_AUTO_EXTRA];
  u32 a_len = 0;

#ifdef IGNORE_FINDS

  /* In IGNORE_FINDS mode, skip any entries that weren't in the
     initial data set. */

  if (G->queue_cur->depth > 1) return 1;

#else

  if (G->pending_favored) {

    /* If we have any favored, non-fuzzed new arrivals in the queue,
       possibly skip to them at the expense of already-fuzzed or non-favored
       cases. */

    if ((G->queue_cur->was_fuzzed || !G->queue_cur->favored) &&
        UR(G, 100) < SKIP_TO_NEW_PROB) return 1;

  } else if (!G->dumb_mode && !G->queue_cur->favored && G->queued_paths > 10) {

    /* Otherwise, still possibly skip non-favored cases, albeit less often.
       The odds of skipping stuff are higher for already-fuzzed inputs and
       lower for never-fuzzed entries. */

    if (G->queue_cycle > 1 && !G->queue_cur->was_fuzzed) {

      if (UR(G, 100) < SKIP_NFAV_NEW_PROB) return 1;

    } else {

      if (UR(G, 100) < SKIP_NFAV_OLD_PROB) return 1;

    }

  }

#endif /* ^IGNORE_FINDS */

  if (G->not_on_tty)
    ACTF("Fuzzing test case #%u (%u total)...", G->current_entry, G->queued_paths);

  /* Map the test case into memory. */

  fd = open(G->queue_cur->fname, O_RDONLY);

  if (fd < 0) PFATAL("Unable to open '%s'", G->queue_cur->fname);

  len = G->queue_cur->len;

  orig_in = in_buf = mmap(0, len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);

  if (orig_in == MAP_FAILED) PFATAL("Unable to mmap '%s'", G->queue_cur->fname);

  close(fd);

  /* We could mmap() out_buf as MAP_PRIVATE, but we end up clobbering every
     single byte anyway, so it wouldn't give us any performance or memory usage
     benefits. */

  out_buf = ck_alloc_nozero(len);

  G->subseq_hangs = 0;

  G->cur_depth = G->queue_cur->depth;

  /*******************************************
   * CALIBRATION (only if failed earlier on) *
   *******************************************/

  if (G->queue_cur->cal_failed) {

    u8 res = FAULT_HANG;

    if (G->queue_cur->cal_failed < CAL_CHANCES) {

      res = calibrate_case(G, argv, G->queue_cur, in_buf, G->queue_cycle - 1, 0);

      if (res == FAULT_ERROR)
        FATAL("Unable to execute target application");

    }

    if (G->stop_soon || res != G->crash_mode) {
      G->cur_skipped_paths++;
      goto abandon_entry;
    }

  }

  /************
   * TRIMMING *
   ************/

  if (!G->dumb_mode && !G->queue_cur->trim_done) {

    u8 res = trim_case(G, argv, G->queue_cur, in_buf);

    if (res == FAULT_ERROR)
      FATAL("Unable to execute target application");

    if (G->stop_soon) {
      G->cur_skipped_paths++;
      goto abandon_entry;
    }

    /* Don't retry trimming, even if it failed. */

    G->queue_cur->trim_done = 1;

    if (len != G->queue_cur->len) len = G->queue_cur->len;

  }

  memcpy(out_buf, in_buf, len);

  /*********************
   * PERFORMANCE SCORE *
   *********************/

  orig_perf = perf_score = calculate_score(G, G->queue_cur);

  /* Skip right away if -d is given, if we have done deterministic fuzzing on
     this entry ourselves (was_fuzzed), or if it has gone through deterministic
     testing in earlier, resumed runs (passed_det). */

  if (G->skip_deterministic || G->queue_cur->was_fuzzed || G->queue_cur->passed_det)
    goto havoc_stage;

  /*********************************************
   * SIMPLE BITFLIP (+dictionary construction) *
   *********************************************/

#define FLIP_BIT(_ar, _b) do { \
    u8* _arf = (u8*)(_ar); \
    u32 _bf = (_b); \
    _arf[(_bf) >> 3] ^= (128 >> ((_bf) & 7)); \
  } while (0)

  /* Single walking bit. */

  G->stage_short = "flip1";
  G->stage_max   = len << 3;
  G->stage_name  = "bitflip 1/1";

  G->stage_val_type = STAGE_VAL_NONE;

  orig_hit_cnt = G->queued_paths + G->unique_crashes;

  prev_cksum = G->queue_cur->exec_cksum;

  for (G->stage_cur = 0; G->stage_cur < G->stage_max; G->stage_cur++) {

    G->stage_cur_byte = G->stage_cur >> 3;

    FLIP_BIT(out_buf, G->stage_cur);

    if (common_fuzz_stuff(G, argv, out_buf, len)) goto abandon_entry;

    FLIP_BIT(out_buf, G->stage_cur);

    /* While flipping the least significant bit in every byte, pull of an extra
       trick to detect possible syntax tokens. In essence, the idea is that if
       you have a binary blob like this:

       xxxxxxxxIHDRxxxxxxxx

       ...and changing the leading and trailing bytes causes variable or no
       changes in program flow, but touching any character in the "IHDR" string
       always produces the same, distinctive path, it's highly likely that
       "IHDR" is an atomically-checked magic value of special significance to
       the fuzzed format.

       We do this here, rather than as a separate stage, because it's a nice
       way to keep the operation approximately "free" (i.e., no extra execs).
       
       Empirically, performing the check when flipping the least significant bit
       is advantageous, compared to doing it at the time of more disruptive
       changes, where the program flow may be affected in more violent ways.

       The caveat is that we won't generate dictionaries in the -d mode or -S
       mode - but that's probably a fair trade-off.

       This won't work particularly well with paths that exhibit variable
       behavior, but fails gracefully, so we'll carry out the checks anyway.

      */

    if (!G->dumb_mode && (G->stage_cur & 7) == 7) {

      u32 cksum = hash32(G->trace_bits, MAP_SIZE, HASH_CONST);

      if (G->stage_cur == G->stage_max - 1 && cksum == prev_cksum) {

        /* If at end of file and we are still collecting a string, grab the
           final character and force output. */

        if (a_len < MAX_AUTO_EXTRA) a_collect[a_len] = out_buf[G->stage_cur >> 3];
        a_len++;

        if (a_len >= MIN_AUTO_EXTRA && a_len <= MAX_AUTO_EXTRA)
          maybe_add_auto(G, a_collect, a_len);

      } else if (cksum != prev_cksum) {

        /* Otherwise, if the checksum has changed, see if we have something
           worthwhile queued up, and collect that if the answer is yes. */

        if (a_len >= MIN_AUTO_EXTRA && a_len <= MAX_AUTO_EXTRA)
          maybe_add_auto(G, a_collect, a_len);

        a_len = 0;
        prev_cksum = cksum;

      }

      /* Continue collecting string, but only if the bit flip actually made
         any difference - we don't want no-op tokens. */

      if (cksum != G->queue_cur->exec_cksum) {

        if (a_len < MAX_AUTO_EXTRA) a_collect[a_len] = out_buf[G->stage_cur >> 3];        
        a_len++;

      }

    }

  }

  new_hit_cnt = G->queued_paths + G->unique_crashes;

  G->stage_finds[STAGE_FLIP1]  += new_hit_cnt - orig_hit_cnt;
  G->stage_cycles[STAGE_FLIP1] += G->stage_max;

  if (G->queue_cur->passed_det) goto havoc_stage;

  /* Two walking bits. */

  G->stage_name  = "bitflip 2/1";
  G->stage_short = "flip2";
  G->stage_max   = (len << 3) - 1;

  orig_hit_cnt = new_hit_cnt;

  for (G->stage_cur = 0; G->stage_cur < G->stage_max; G->stage_cur++) {

    G->stage_cur_byte = G->stage_cur >> 3;

    FLIP_BIT(out_buf, G->stage_cur);
    FLIP_BIT(out_buf, G->stage_cur + 1);

    if (common_fuzz_stuff(G, argv, out_buf, len)) goto abandon_entry;

    FLIP_BIT(out_buf, G->stage_cur);
    FLIP_BIT(out_buf, G->stage_cur + 1);

  }

  new_hit_cnt = G->queued_paths + G->unique_crashes;

  G->stage_finds[STAGE_FLIP2]  += new_hit_cnt - orig_hit_cnt;
  G->stage_cycles[STAGE_FLIP2] += G->stage_max;

  /* Four walking bits. */

  G->stage_name  = "bitflip 4/1";
  G->stage_short = "flip4";
  G->stage_max   = (len << 3) - 3;

  orig_hit_cnt = new_hit_cnt;

  for (G->stage_cur = 0; G->stage_cur < G->stage_max; G->stage_cur++) {

    G->stage_cur_byte = G->stage_cur >> 3;

    FLIP_BIT(out_buf, G->stage_cur);
    FLIP_BIT(out_buf, G->stage_cur + 1);
    FLIP_BIT(out_buf, G->stage_cur + 2);
    FLIP_BIT(out_buf, G->stage_cur + 3);

    if (common_fuzz_stuff(G, argv, out_buf, len)) goto abandon_entry;

    FLIP_BIT(out_buf, G->stage_cur);
    FLIP_BIT(out_buf, G->stage_cur + 1);
    FLIP_BIT(out_buf, G->stage_cur + 2);
    FLIP_BIT(out_buf, G->stage_cur + 3);

  }

  new_hit_cnt = G->queued_paths + G->unique_crashes;

  G->stage_finds[STAGE_FLIP4]  += new_hit_cnt - orig_hit_cnt;
  G->stage_cycles[STAGE_FLIP4] += G->stage_max;

  /* Effector map setup. These macros calculate:

     EFF_APOS      - position of a particular file offset in the map.
     EFF_ALEN      - length of an map with a particular number of bytes.
     EFF_SPAN_ALEN - map span for a sequence of bytes.

   */

#define EFF_APOS(_p)          ((_p) >> EFF_MAP_SCALE2)
#define EFF_REM(_x)           ((_x) & ((1 << EFF_MAP_SCALE2) - 1))
#define EFF_ALEN(_l)          (EFF_APOS(_l) + !!EFF_REM(_l))
#define EFF_SPAN_ALEN(_p, _l) (EFF_APOS((_p) + (_l) - 1) - EFF_APOS(_p) + 1)

  /* Initialize effector map for the next step (see comments below). Always
     flag first and last byte as doing something. */

  eff_map    = ck_alloc(EFF_ALEN(len));
  eff_map[0] = 1;

  if (EFF_APOS(len - 1) != 0) {
    eff_map[EFF_APOS(len - 1)] = 1;
    eff_cnt++;
  }

  /* Walking byte. */

  G->stage_name  = "bitflip 8/8";
  G->stage_short = "flip8";
  G->stage_max   = len;

  orig_hit_cnt = new_hit_cnt;

  for (G->stage_cur = 0; G->stage_cur < G->stage_max; G->stage_cur++) {

    G->stage_cur_byte = G->stage_cur;

    out_buf[G->stage_cur] ^= 0xFF;

    if (common_fuzz_stuff(G, argv, out_buf, len)) goto abandon_entry;

    /* We also use this stage to pull off a simple trick: we identify
       bytes that seem to have no effect on the current execution path
       even when fully flipped - and we skip them during more expensive
       deterministic stages, such as arithmetics or known ints. */

    if (!eff_map[EFF_APOS(G->stage_cur)]) {

      u32 cksum;

      /* If in dumb mode or if the file is very short, just flag everything
         without wasting time on checksums. */

      if (!G->dumb_mode && len >= EFF_MIN_LEN)
        cksum = hash32(G->trace_bits, MAP_SIZE, HASH_CONST);
      else
        cksum = ~G->queue_cur->exec_cksum;

      if (cksum != G->queue_cur->exec_cksum) {
        eff_map[EFF_APOS(G->stage_cur)] = 1;
        eff_cnt++;
      }

    }

    out_buf[G->stage_cur] ^= 0xFF;

  }

  /* If the effector map is more than EFF_MAX_PERC dense, just flag the
     whole thing as worth fuzzing, since we wouldn't be saving much time
     anyway. */

  if (eff_cnt != EFF_ALEN(len) &&
      eff_cnt * 100 / EFF_ALEN(len) > EFF_MAX_PERC) {

    memset(eff_map, 1, EFF_ALEN(len));

    G->blocks_eff_select += EFF_ALEN(len);

  } else {

    G->blocks_eff_select += eff_cnt;

  }

  G->blocks_eff_total += EFF_ALEN(len);

  new_hit_cnt = G->queued_paths + G->unique_crashes;

  G->stage_finds[STAGE_FLIP8]  += new_hit_cnt - orig_hit_cnt;
  G->stage_cycles[STAGE_FLIP8] += G->stage_max;

  /* Two walking bytes. */

  if (len < 2) goto skip_bitflip;

  G->stage_name  = "bitflip 16/8";
  G->stage_short = "flip16";
  G->stage_cur   = 0;
  G->stage_max   = len - 1;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 1; i++) {

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)]) {
      G->stage_max--;
      continue;
    }

    G->stage_cur_byte = i;

    *(u16*)(out_buf + i) ^= 0xFFFF;

    if (common_fuzz_stuff(G, argv, out_buf, len)) goto abandon_entry;
    G->stage_cur++;

    *(u16*)(out_buf + i) ^= 0xFFFF;


  }

  new_hit_cnt = G->queued_paths + G->unique_crashes;

  G->stage_finds[STAGE_FLIP16]  += new_hit_cnt - orig_hit_cnt;
  G->stage_cycles[STAGE_FLIP16] += G->stage_max;

  if (len < 4) goto skip_bitflip;

  /* Four walking bytes. */

  G->stage_name  = "bitflip 32/8";
  G->stage_short = "flip32";
  G->stage_cur   = 0;
  G->stage_max   = len - 3;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 3; i++) {

    /* Let's consult the effector map... */
    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)] &&
        !eff_map[EFF_APOS(i + 2)] && !eff_map[EFF_APOS(i + 3)]) {
      G->stage_max--;
      continue;
    }

    G->stage_cur_byte = i;

    *(u32*)(out_buf + i) ^= 0xFFFFFFFF;

    if (common_fuzz_stuff(G, argv, out_buf, len)) goto abandon_entry;
    G->stage_cur++;

    *(u32*)(out_buf + i) ^= 0xFFFFFFFF;

  }

  new_hit_cnt = G->queued_paths + G->unique_crashes;

  G->stage_finds[STAGE_FLIP32]  += new_hit_cnt - orig_hit_cnt;
  G->stage_cycles[STAGE_FLIP32] += G->stage_max;

skip_bitflip:

  /**********************
   * ARITHMETIC INC/DEC *
   **********************/

  /* 8-bit arithmetics. */

  G->stage_name  = "arith 8/8";
  G->stage_short = "arith8";
  G->stage_cur   = 0;
  G->stage_max   = 2 * len * ARITH_MAX;

  G->stage_val_type = STAGE_VAL_LE;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len; i++) {

    u8 orig = out_buf[i];

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)]) {
      G->stage_max -= 2 * ARITH_MAX;
      continue;
    }

    G->stage_cur_byte = i;

    for (j = 1; j <= ARITH_MAX; j++) {

      u8 r = orig ^ (orig + j);

      /* Do arithmetic operations only if the result couldn't be a product
         of a bitflip. */

      if (!could_be_bitflip(r)) {

        G->stage_cur_val = j;
        out_buf[i] = orig + j;

        if (common_fuzz_stuff(G, argv, out_buf, len)) goto abandon_entry;
        G->stage_cur++;

      } else G->stage_max--;

      r =  orig ^ (orig - j);

      if (!could_be_bitflip(r)) {

        G->stage_cur_val = -j;
        out_buf[i] = orig - j;

        if (common_fuzz_stuff(G, argv, out_buf, len)) goto abandon_entry;
        G->stage_cur++;

      } else G->stage_max--;

      out_buf[i] = orig;

    }

  }

  new_hit_cnt = G->queued_paths + G->unique_crashes;

  G->stage_finds[STAGE_ARITH8]  += new_hit_cnt - orig_hit_cnt;
  G->stage_cycles[STAGE_ARITH8] += G->stage_max;

  /* 16-bit arithmetics, both endians. */

  if (len < 2) goto skip_arith;

  G->stage_name  = "arith 16/8";
  G->stage_short = "arith16";
  G->stage_cur   = 0;
  G->stage_max   = 4 * (len - 1) * ARITH_MAX;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 1; i++) {

    u16 orig = *(u16*)(out_buf + i);

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)]) {
      G->stage_max -= 4 * ARITH_MAX;
      continue;
    }

    G->stage_cur_byte = i;

    for (j = 1; j <= ARITH_MAX; j++) {

      u16 r1 = orig ^ (orig + j),
          r2 = orig ^ (orig - j),
          r3 = orig ^ SWAP16(SWAP16(orig) + j),
          r4 = orig ^ SWAP16(SWAP16(orig) - j);

      /* Try little endian addition and subtraction first. Do it only
         if the operation would affect more than one byte (hence the 
         & 0xff overflow checks) and if it couldn't be a product of
         a bitflip. */

      G->stage_val_type = STAGE_VAL_LE; 

      if ((orig & 0xff) + j > 0xff && !could_be_bitflip(r1)) {

        G->stage_cur_val = j;
        *(u16*)(out_buf + i) = orig + j;

        if (common_fuzz_stuff(G, argv, out_buf, len)) goto abandon_entry;
        G->stage_cur++;
 
      } else G->stage_max--;

      if ((orig & 0xff) < j && !could_be_bitflip(r2)) {

        G->stage_cur_val = -j;
        *(u16*)(out_buf + i) = orig - j;

        if (common_fuzz_stuff(G, argv, out_buf, len)) goto abandon_entry;
        G->stage_cur++;

      } else G->stage_max--;

      /* Big endian comes next. Same deal. */

      G->stage_val_type = STAGE_VAL_BE;


      if ((orig >> 8) + j > 0xff && !could_be_bitflip(r3)) {

        G->stage_cur_val = j;
        *(u16*)(out_buf + i) = SWAP16(SWAP16(orig) + j);

        if (common_fuzz_stuff(G, argv, out_buf, len)) goto abandon_entry;
        G->stage_cur++;

      } else G->stage_max--;

      if ((orig >> 8) < j && !could_be_bitflip(r4)) {

        G->stage_cur_val = -j;
        *(u16*)(out_buf + i) = SWAP16(SWAP16(orig) - j);

        if (common_fuzz_stuff(G, argv, out_buf, len)) goto abandon_entry;
        G->stage_cur++;

      } else G->stage_max--;

      *(u16*)(out_buf + i) = orig;

    }

  }

  new_hit_cnt = G->queued_paths + G->unique_crashes;

  G->stage_finds[STAGE_ARITH16]  += new_hit_cnt - orig_hit_cnt;
  G->stage_cycles[STAGE_ARITH16] += G->stage_max;

  /* 32-bit arithmetics, both endians. */

  if (len < 4) goto skip_arith;

  G->stage_name  = "arith 32/8";
  G->stage_short = "arith32";
  G->stage_cur   = 0;
  G->stage_max   = 4 * (len - 3) * ARITH_MAX;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 3; i++) {

    u32 orig = *(u32*)(out_buf + i);

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)] &&
        !eff_map[EFF_APOS(i + 2)] && !eff_map[EFF_APOS(i + 3)]) {
      G->stage_max -= 4 * ARITH_MAX;
      continue;
    }

    G->stage_cur_byte = i;

    for (j = 1; j <= ARITH_MAX; j++) {

      u32 r1 = orig ^ (orig + j),
          r2 = orig ^ (orig - j),
          r3 = orig ^ SWAP32(SWAP32(orig) + j),
          r4 = orig ^ SWAP32(SWAP32(orig) - j);

      /* Little endian first. Same deal as with 16-bit: we only want to
         try if the operation would have effect on more than two bytes. */

      G->stage_val_type = STAGE_VAL_LE; 

      if ((orig & 0xffff) + j > 0xffff && !could_be_bitflip(r1)) {

        G->stage_cur_val = j;
        *(u32*)(out_buf + i) = orig + j;

        if (common_fuzz_stuff(G, argv, out_buf, len)) goto abandon_entry;
        G->stage_cur++;

      } else G->stage_max--;

      if ((orig & 0xffff) < j && !could_be_bitflip(r2)) {

        G->stage_cur_val = -j;
        *(u32*)(out_buf + i) = orig - j;

        if (common_fuzz_stuff(G, argv, out_buf, len)) goto abandon_entry;
        G->stage_cur++;

      } else G->stage_max--;

      /* Big endian next. */

      G->stage_val_type = STAGE_VAL_BE;

      if ((SWAP32(orig) & 0xffff) + j > 0xffff && !could_be_bitflip(r3)) {

        G->stage_cur_val = j;
        *(u32*)(out_buf + i) = SWAP32(SWAP32(orig) + j);

        if (common_fuzz_stuff(G, argv, out_buf, len)) goto abandon_entry;
        G->stage_cur++;

      } else G->stage_max--;

      if ((SWAP32(orig) & 0xffff) < j && !could_be_bitflip(r4)) {

        G->stage_cur_val = -j;
        *(u32*)(out_buf + i) = SWAP32(SWAP32(orig) - j);

        if (common_fuzz_stuff(G, argv, out_buf, len)) goto abandon_entry;
        G->stage_cur++;

      } else G->stage_max--;

      *(u32*)(out_buf + i) = orig;

    }

  }

  new_hit_cnt = G->queued_paths + G->unique_crashes;

  G->stage_finds[STAGE_ARITH32]  += new_hit_cnt - orig_hit_cnt;
  G->stage_cycles[STAGE_ARITH32] += G->stage_max;

skip_arith:

  /**********************
   * INTERESTING VALUES *
   **********************/

  G->stage_name  = "interest 8/8";
  G->stage_short = "int8";
  G->stage_cur   = 0;
  G->stage_max   = len * sizeof(interesting_8);

  G->stage_val_type = STAGE_VAL_LE;

  orig_hit_cnt = new_hit_cnt;

  /* Setting 8-bit integers. */

  for (i = 0; i < len; i++) {

    u8 orig = out_buf[i];

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)]) {
      G->stage_max -= sizeof(interesting_8);
      continue;
    }

    G->stage_cur_byte = i;

    for (j = 0; j < sizeof(interesting_8); j++) {

      /* Skip if the value could be a product of bitflips or arithmetics. */

      if (could_be_bitflip(orig ^ (u8)interesting_8[j]) ||
          could_be_arith(orig, (u8)interesting_8[j], 1)) {
        G->stage_max--;
        continue;
      }

      G->stage_cur_val = interesting_8[j];
      out_buf[i] = interesting_8[j];

      if (common_fuzz_stuff(G, argv, out_buf, len)) goto abandon_entry;

      out_buf[i] = orig;
      G->stage_cur++;

    }

  }

  new_hit_cnt = G->queued_paths + G->unique_crashes;

  G->stage_finds[STAGE_INTEREST8]  += new_hit_cnt - orig_hit_cnt;
  G->stage_cycles[STAGE_INTEREST8] += G->stage_max;

  /* Setting 16-bit integers, both endians. */

  if (len < 2) goto skip_interest;

  G->stage_name  = "interest 16/8";
  G->stage_short = "int16";
  G->stage_cur   = 0;
  G->stage_max   = 2 * (len - 1) * (sizeof(interesting_16) >> 1);

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 1; i++) {

    u16 orig = *(u16*)(out_buf + i);

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)]) {
      G->stage_max -= sizeof(interesting_16);
      continue;
    }

    G->stage_cur_byte = i;

    for (j = 0; j < sizeof(interesting_16) / 2; j++) {

      G->stage_cur_val = interesting_16[j];

      /* Skip if this could be a product of a bitflip, arithmetics,
         or single-byte interesting value insertion. */

      if (!could_be_bitflip(orig ^ (u16)interesting_16[j]) &&
          !could_be_arith(orig, (u16)interesting_16[j], 2) &&
          !could_be_interest(orig, (u16)interesting_16[j], 2, 0)) {

        G->stage_val_type = STAGE_VAL_LE;

        *(u16*)(out_buf + i) = interesting_16[j];

        if (common_fuzz_stuff(G, argv, out_buf, len)) goto abandon_entry;
        G->stage_cur++;

      } else G->stage_max--;

      if ((u16)interesting_16[j] != SWAP16(interesting_16[j]) &&
          !could_be_bitflip(orig ^ SWAP16(interesting_16[j])) &&
          !could_be_arith(orig, SWAP16(interesting_16[j]), 2) &&
          !could_be_interest(orig, SWAP16(interesting_16[j]), 2, 1)) {

        G->stage_val_type = STAGE_VAL_BE;

        *(u16*)(out_buf + i) = SWAP16(interesting_16[j]);
        if (common_fuzz_stuff(G, argv, out_buf, len)) goto abandon_entry;
        G->stage_cur++;

      } else G->stage_max--;

    }

    *(u16*)(out_buf + i) = orig;

  }

  new_hit_cnt = G->queued_paths + G->unique_crashes;

  G->stage_finds[STAGE_INTEREST16]  += new_hit_cnt - orig_hit_cnt;
  G->stage_cycles[STAGE_INTEREST16] += G->stage_max;

  if (len < 4) goto skip_interest;

  /* Setting 32-bit integers, both endians. */

  G->stage_name  = "interest 32/8";
  G->stage_short = "int32";
  G->stage_cur   = 0;
  G->stage_max   = 2 * (len - 3) * (sizeof(interesting_32) >> 2);

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 3; i++) {

    u32 orig = *(u32*)(out_buf + i);

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)] &&
        !eff_map[EFF_APOS(i + 2)] && !eff_map[EFF_APOS(i + 3)]) {
      G->stage_max -= sizeof(interesting_32) >> 1;
      continue;
    }

    G->stage_cur_byte = i;

    for (j = 0; j < sizeof(interesting_32) / 4; j++) {

      G->stage_cur_val = interesting_32[j];

      /* Skip if this could be a product of a bitflip, arithmetics,
         or word interesting value insertion. */

      if (!could_be_bitflip(orig ^ (u32)interesting_32[j]) &&
          !could_be_arith(orig, interesting_32[j], 4) &&
          !could_be_interest(orig, interesting_32[j], 4, 0)) {

        G->stage_val_type = STAGE_VAL_LE;

        *(u32*)(out_buf + i) = interesting_32[j];

        if (common_fuzz_stuff(G, argv, out_buf, len)) goto abandon_entry;
        G->stage_cur++;

      } else G->stage_max--;

      if ((u32)interesting_32[j] != SWAP32(interesting_32[j]) &&
          !could_be_bitflip(orig ^ SWAP32(interesting_32[j])) &&
          !could_be_arith(orig, SWAP32(interesting_32[j]), 4) &&
          !could_be_interest(orig, SWAP32(interesting_32[j]), 4, 1)) {

        G->stage_val_type = STAGE_VAL_BE;

        *(u32*)(out_buf + i) = SWAP32(interesting_32[j]);
        if (common_fuzz_stuff(G, argv, out_buf, len)) goto abandon_entry;
        G->stage_cur++;

      } else G->stage_max--;

    }

    *(u32*)(out_buf + i) = orig;

  }

  new_hit_cnt = G->queued_paths + G->unique_crashes;

  G->stage_finds[STAGE_INTEREST32]  += new_hit_cnt - orig_hit_cnt;
  G->stage_cycles[STAGE_INTEREST32] += G->stage_max;

skip_interest:

  /********************
   * DICTIONARY STUFF *
   ********************/

  if (!G->extras_cnt) goto skip_user_extras;

  /* Overwrite with user-supplied G->extras. */

  G->stage_name  = "user G->extras (over)";
  G->stage_short = "ext_UO";
  G->stage_cur   = 0;
  G->stage_max   = G->extras_cnt * len;

  G->stage_val_type = STAGE_VAL_NONE;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len; i++) {

    u32 last_len = 0;

    G->stage_cur_byte = i;

    /* Extras are sorted by size, from smallest to largest. This means
       that we don't have to worry about restoring the buffer in
       between writes at a particular offset determined by the outer
       loop. */

    for (j = 0; j < G->extras_cnt; j++) {

      /* Skip G->extras probabilistically if G->extras_cnt > MAX_DET_EXTRAS. Also
         skip them if there's no room to insert the payload, if the token
         is redundant, or if its entire span has no bytes set in the effector
         map. */

      if ((G->extras_cnt > MAX_DET_EXTRAS && UR(G, G->extras_cnt) >= MAX_DET_EXTRAS) ||
          G->extras[j].len > len - i ||
          !memcmp(G->extras[j].data, out_buf + i, G->extras[j].len) ||
          !memchr(eff_map + EFF_APOS(i), 1, EFF_SPAN_ALEN(i, G->extras[j].len))) {

        G->stage_max--;
        continue;

      }

      last_len = G->extras[j].len;
      memcpy(out_buf + i, G->extras[j].data, last_len);

      if (common_fuzz_stuff(G, argv, out_buf, len)) goto abandon_entry;

      G->stage_cur++;

    }

    /* Restore all the clobbered memory. */
    memcpy(out_buf + i, in_buf + i, last_len);

  }

  new_hit_cnt = G->queued_paths + G->unique_crashes;

  G->stage_finds[STAGE_EXTRAS_UO]  += new_hit_cnt - orig_hit_cnt;
  G->stage_cycles[STAGE_EXTRAS_UO] += G->stage_max;

  /* Insertion of user-supplied G->extras. */

  G->stage_name  = "user G->extras (insert)";
  G->stage_short = "ext_UI";
  G->stage_cur   = 0;
  G->stage_max   = G->extras_cnt * len;

  orig_hit_cnt = new_hit_cnt;

  ex_tmp = ck_alloc(len + MAX_DICT_FILE);

  for (i = 0; i < len; i++) {

    G->stage_cur_byte = i;

    for (j = 0; j < G->extras_cnt; j++) {

      /* Insert token */
      memcpy(ex_tmp + i, G->extras[j].data, G->extras[j].len);

      /* Copy tail */
      memcpy(ex_tmp + i + G->extras[j].len, out_buf + i, len - i);

      if (common_fuzz_stuff(G, argv, ex_tmp, len + G->extras[j].len)) {
        ck_free(ex_tmp);
        goto abandon_entry;
      }

      G->stage_cur++;

    }

    /* Copy head */
    ex_tmp[i] = out_buf[i];

  }

  ck_free(ex_tmp);

  new_hit_cnt = G->queued_paths + G->unique_crashes;

  G->stage_finds[STAGE_EXTRAS_UI]  += new_hit_cnt - orig_hit_cnt;
  G->stage_cycles[STAGE_EXTRAS_UI] += G->stage_max;

skip_user_extras:

  if (!G->a_extras_cnt) goto skip_extras;

  G->stage_name  = "auto G->extras (over)";
  G->stage_short = "ext_AO";
  G->stage_cur   = 0;
  G->stage_max   = MIN(G->a_extras_cnt, USE_AUTO_EXTRAS) * len;

  G->stage_val_type = STAGE_VAL_NONE;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len; i++) {

    u32 last_len = 0;

    G->stage_cur_byte = i;

    for (j = 0; j < MIN(G->a_extras_cnt, USE_AUTO_EXTRAS); j++) {

      /* See the comment in the earlier code; G->extras are sorted by size. */

      if (G->a_extras[j].len > len - i ||
          !memcmp(G->a_extras[j].data, out_buf + i, G->a_extras[j].len) ||
          !memchr(eff_map + EFF_APOS(i), 1, EFF_SPAN_ALEN(i, G->a_extras[j].len))) {

        G->stage_max--;
        continue;

      }

      last_len = G->a_extras[j].len;
      memcpy(out_buf + i, G->a_extras[j].data, last_len);

      if (common_fuzz_stuff(G, argv, out_buf, len)) goto abandon_entry;

      G->stage_cur++;

    }

    /* Restore all the clobbered memory. */
    memcpy(out_buf + i, in_buf + i, last_len);

  }

  new_hit_cnt = G->queued_paths + G->unique_crashes;

  G->stage_finds[STAGE_EXTRAS_AO]  += new_hit_cnt - orig_hit_cnt;
  G->stage_cycles[STAGE_EXTRAS_AO] += G->stage_max;

skip_extras:

  /* If we made this to here without jumping to havoc_stage or abandon_entry,
     we're properly done with deterministic steps and can mark it as such
     in the .state/ directory. */

  if (!G->queue_cur->passed_det) mark_as_det_done(G, G->queue_cur);

  /****************
   * RANDOM HAVOC *
   ****************/

havoc_stage:

  G->stage_cur_byte = -1;

  /* The havoc stage mutation code is also invoked when splicing files; if the
     splice_cycle variable is set, generate different descriptions and such. */

  if (!splice_cycle) {

    G->stage_name  = "havoc";
    G->stage_short = "havoc";
    G->stage_max   = HAVOC_CYCLES * perf_score / G->havoc_div / 100;

  } else {

    static u8 tmp[32];

    perf_score = orig_perf;

    sprintf(tmp, "splice %u", splice_cycle);
    G->stage_name  = tmp;
    G->stage_short = "splice";
    G->stage_max   = SPLICE_HAVOC * perf_score / G->havoc_div / 100;

  }

  if (G->stage_max < HAVOC_MIN) G->stage_max = HAVOC_MIN;

  temp_len = len;

  orig_hit_cnt = G->queued_paths + G->unique_crashes;

  havoc_queued = G->queued_paths;

  /* We essentially just do several thousand runs (depending on perf_score)
     where we take the input file and make random stacked tweaks. */

  for (G->stage_cur = 0; G->stage_cur < G->stage_max; G->stage_cur++) {

    u32 use_stacking = 1 << (1 + UR(G, HAVOC_STACK_POW2));

    G->stage_cur_val = use_stacking;
 
    for (i = 0; i < use_stacking; i++) {

      switch (UR(G, 15 + ((G->extras_cnt + G->a_extras_cnt) ? 2 : 0))) {

        case 0:

          /* Flip a single bit somewhere. Spooky! */

          FLIP_BIT(out_buf, UR(G, temp_len << 3));
          break;

        case 1: 

          /* Set byte to interesting value. */

          out_buf[UR(G, temp_len)] = interesting_8[UR(G, sizeof(interesting_8))];
          break;

        case 2:

          /* Set word to interesting value, randomly choosing endian. */

          if (temp_len < 2) break;

          if (UR(G, 2)) {

            *(u16*)(out_buf + UR(G, temp_len - 1)) =
              interesting_16[UR(G, sizeof(interesting_16) >> 1)];

          } else {

            *(u16*)(out_buf + UR(G, temp_len - 1)) = SWAP16(
              interesting_16[UR(G, sizeof(interesting_16) >> 1)]);

          }

          break;

        case 3:

          /* Set dword to interesting value, randomly choosing endian. */

          if (temp_len < 4) break;

          if (UR(G, 2)) {
  
            *(u32*)(out_buf + UR(G, temp_len - 3)) =
              interesting_32[UR(G, sizeof(interesting_32) >> 2)];

          } else {

            *(u32*)(out_buf + UR(G, temp_len - 3)) = SWAP32(
              interesting_32[UR(G, sizeof(interesting_32) >> 2)]);

          }

          break;

        case 4:

          /* Randomly subtract from byte. */

          out_buf[UR(G, temp_len)] -= 1 + UR(G, ARITH_MAX);
          break;

        case 5:

          /* Randomly add to byte. */

          out_buf[UR(G, temp_len)] += 1 + UR(G, ARITH_MAX);
          break;

        case 6:

          /* Randomly subtract from word, random endian. */

          if (temp_len < 2) break;

          if (UR(G, 2)) {

            u32 pos = UR(G, temp_len - 1);

            *(u16*)(out_buf + pos) -= 1 + UR(G, ARITH_MAX);

          } else {

            u32 pos = UR(G, temp_len - 1);
            u16 num = 1 + UR(G, ARITH_MAX);

            *(u16*)(out_buf + pos) =
              SWAP16(SWAP16(*(u16*)(out_buf + pos)) - num);

          }

          break;

        case 7:

          /* Randomly add to word, random endian. */

          if (temp_len < 2) break;

          if (UR(G, 2)) {

            u32 pos = UR(G, temp_len - 1);

            *(u16*)(out_buf + pos) += 1 + UR(G, ARITH_MAX);

          } else {

            u32 pos = UR(G, temp_len - 1);
            u16 num = 1 + UR(G, ARITH_MAX);

            *(u16*)(out_buf + pos) =
              SWAP16(SWAP16(*(u16*)(out_buf + pos)) + num);

          }

          break;

        case 8:

          /* Randomly subtract from dword, random endian. */

          if (temp_len < 4) break;

          if (UR(G, 2)) {

            u32 pos = UR(G, temp_len - 3);

            *(u32*)(out_buf + pos) -= 1 + UR(G, ARITH_MAX);

          } else {

            u32 pos = UR(G, temp_len - 3);
            u32 num = 1 + UR(G, ARITH_MAX);

            *(u32*)(out_buf + pos) =
              SWAP32(SWAP32(*(u32*)(out_buf + pos)) - num);

          }

          break;

        case 9:

          /* Randomly add to dword, random endian. */

          if (temp_len < 4) break;

          if (UR(G, 2)) {

            u32 pos = UR(G, temp_len - 3);

            *(u32*)(out_buf + pos) += 1 + UR(G, ARITH_MAX);

          } else {

            u32 pos = UR(G, temp_len - 3);
            u32 num = 1 + UR(G, ARITH_MAX);

            *(u32*)(out_buf + pos) =
              SWAP32(SWAP32(*(u32*)(out_buf + pos)) + num);

          }

          break;

        case 10:

          /* Just set a random byte to a random value. Because,
             why not. We use XOR with 1-255 to eliminate the
             possibility of a no-op. */

          out_buf[UR(G, temp_len)] ^= 1 + UR(G, 255);
          break;

        case 11 ... 12: {

            /* Delete bytes. We're making this a bit more likely
               than insertion (the next option) in hopes of keeping
               files reasonably small. */

            u32 del_from, del_len;

            if (temp_len < 2) break;

            /* Don't delete too much. */

            del_len = choose_block_len(G, temp_len - 1);

            del_from = UR(G, temp_len - del_len + 1);

            memmove(out_buf + del_from, out_buf + del_from + del_len,
                    temp_len - del_from - del_len);

            temp_len -= del_len;

            break;

          }

        case 13:

          if (temp_len + HAVOC_BLK_LARGE < MAX_FILE) {

            /* Clone bytes (75%) or insert a block of constant bytes (25%). */

            u32 clone_from, clone_to, clone_len;
            u8* new_buf;

            clone_len  = choose_block_len(G, temp_len);

            clone_from = UR(G, temp_len - clone_len + 1);
            clone_to   = UR(G, temp_len);

            new_buf = ck_alloc_nozero(temp_len + clone_len);

            /* Head */

            memcpy(new_buf, out_buf, clone_to);

            /* Inserted part */

            if (UR(G, 4))
              memcpy(new_buf + clone_to, out_buf + clone_from, clone_len);
            else
              memset(new_buf + clone_to, UR(G, 256), clone_len);

            /* Tail */
            memcpy(new_buf + clone_to + clone_len, out_buf + clone_to,
                   temp_len - clone_to);

            ck_free(out_buf);
            out_buf = new_buf;
            temp_len += clone_len;

          }

          break;

        case 14: {

            /* Overwrite bytes with a randomly selected chunk (75%) or fixed
               bytes (25%). */

            u32 copy_from, copy_to, copy_len;

            if (temp_len < 2) break;

            copy_len  = choose_block_len(G, temp_len - 1);

            copy_from = UR(G, temp_len - copy_len + 1);
            copy_to   = UR(G, temp_len - copy_len + 1);

            if (UR(G, 4)) {

              if (copy_from != copy_to)
                memmove(out_buf + copy_to, out_buf + copy_from, copy_len);

            } else memset(out_buf + copy_to, UR(G, 256), copy_len);

            break;

          }

        /* Values 16 and 17 can be selected only if there are any G->extras
           present in the dictionaries. */

        case 16: {

            /* Overwrite bytes with an extra. */

            if (!G->extras_cnt || (G->a_extras_cnt && UR(G, 2))) {

              /* No user-specified G->extras or odds in our favor. Let's use an
                 auto-detected one. */

              u32 use_extra = UR(G, G->a_extras_cnt);
              u32 extra_len = G->a_extras[use_extra].len;
              u32 insert_at;

              if (extra_len > temp_len) break;

              insert_at = UR(G, temp_len - extra_len + 1);
              memcpy(out_buf + insert_at, G->a_extras[use_extra].data, extra_len);

            } else {

              /* No auto G->extras or odds in our favor. Use the dictionary. */

              u32 use_extra = UR(G, G->extras_cnt);
              u32 extra_len = G->extras[use_extra].len;
              u32 insert_at;

              if (extra_len > temp_len) break;

              insert_at = UR(G, temp_len - extra_len + 1);
              memcpy(out_buf + insert_at, G->extras[use_extra].data, extra_len);

            }

            break;

          }

        case 17: {

            u32 use_extra, extra_len, insert_at = UR(G, temp_len);
            u8* new_buf;

            /* Insert an extra. Do the same dice-rolling stuff as for the
               previous case. */

            if (!G->extras_cnt || (G->a_extras_cnt && UR(G, 2))) {

              use_extra = UR(G, G->a_extras_cnt);
              extra_len = G->a_extras[use_extra].len;

              if (temp_len + extra_len >= MAX_FILE) break;

              new_buf = ck_alloc_nozero(temp_len + extra_len);

              /* Head */
              memcpy(new_buf, out_buf, insert_at);

              /* Inserted part */
              memcpy(new_buf + insert_at, G->a_extras[use_extra].data, extra_len);

            } else {

              use_extra = UR(G, G->extras_cnt);
              extra_len = G->extras[use_extra].len;

              if (temp_len + extra_len >= MAX_FILE) break;

              new_buf = ck_alloc_nozero(temp_len + extra_len);

              /* Head */
              memcpy(new_buf, out_buf, insert_at);

              /* Inserted part */
              memcpy(new_buf + insert_at, G->extras[use_extra].data, extra_len);

            }

            /* Tail */
            memcpy(new_buf + insert_at + extra_len, out_buf + insert_at,
                   temp_len - insert_at);

            ck_free(out_buf);
            out_buf   = new_buf;
            temp_len += extra_len;

            break;

          }

      }

    }

    if (common_fuzz_stuff(G, argv, out_buf, temp_len))
      goto abandon_entry;

    /* out_buf might have been mangled a bit, so let's restore it to its
       original size and shape. */

    if (temp_len < len) out_buf = ck_realloc(out_buf, len);
    temp_len = len;
    memcpy(out_buf, in_buf, len);

    /* If we're finding new stuff, let's run for a bit longer, limits
       permitting. */

    if (G->queued_paths != havoc_queued) {

      if (perf_score <= HAVOC_MAX_MULT * 100) {
        G->stage_max  *= 2;
        perf_score *= 2;
      }

      havoc_queued = G->queued_paths;

    }

  }

  new_hit_cnt = G->queued_paths + G->unique_crashes;

  if (!splice_cycle) {
    G->stage_finds[STAGE_HAVOC]  += new_hit_cnt - orig_hit_cnt;
    G->stage_cycles[STAGE_HAVOC] += G->stage_max;
  } else {
    G->stage_finds[STAGE_SPLICE]  += new_hit_cnt - orig_hit_cnt;
    G->stage_cycles[STAGE_SPLICE] += G->stage_max;
  }

#ifndef IGNORE_FINDS

  /************
   * SPLICING *
   ************/

  /* This is a last-resort strategy triggered by a full round with no findings.
     It takes the current input file, randomly selects another input, and
     splices them together at some offset, then relies on the havoc
     code to mutate that blob. */

retry_splicing:

  if (G->use_splicing && splice_cycle++ < SPLICE_CYCLES &&
      G->queued_paths > 1 && G->queue_cur->len > 1) {

    struct queue_entry* target;
    u32 tid, split_at;
    u8* new_buf;
    s32 f_diff, l_diff;

    /* First of all, if we've modified in_buf for havoc, let's clean that
       up... */

    if (in_buf != orig_in) {
      ck_free(in_buf);
      in_buf = orig_in;
      len = G->queue_cur->len;
    }

    /* Pick a random queue entry and seek to it. Don't splice with yourself. */

    do { tid = UR(G, G->queued_paths); } while (tid == G->current_entry);

    G->splicing_with = tid;
    target = G->queue;

    while (tid >= 100) { target = target->next_100; tid -= 100; }
    while (tid--) target = target->next;

    /* Make sure that the target has a reasonable length. */

    while (target && (target->len < 2 || target == G->queue_cur)) {
      target = target->next;
      G->splicing_with++;
    }

    if (!target) goto retry_splicing;

    /* Read the testcase into a new buffer. */

    fd = open(target->fname, O_RDONLY);

    if (fd < 0) PFATAL("Unable to open '%s'", target->fname);

    new_buf = ck_alloc_nozero(target->len);

    ck_read(fd, new_buf, target->len, target->fname);

    close(fd);

    /* Find a suitable splicing location, somewhere between the first and
       the last differing byte. Bail out if the difference is just a single
       byte or so. */

    locate_diffs(in_buf, new_buf, MIN(len, target->len), &f_diff, &l_diff);

    if (f_diff < 0 || l_diff < 2 || f_diff == l_diff) {
      ck_free(new_buf);
      goto retry_splicing;
    }

    /* Split somewhere between the first and last differing byte. */

    split_at = f_diff + UR(G, l_diff - f_diff);

    /* Do the thing. */

    len = target->len;
    memcpy(new_buf, in_buf, split_at);
    in_buf = new_buf;

    ck_free(out_buf);
    out_buf = ck_alloc_nozero(len);
    memcpy(out_buf, in_buf, len);

    goto havoc_stage;

  }

#endif /* !IGNORE_FINDS */

  ret_val = 0;

abandon_entry:

  G->splicing_with = -1;

  /* Update G->pending_not_fuzzed count if we made it through the calibration
     cycle and have not seen this entry before. */

  if (!G->stop_soon && !G->queue_cur->cal_failed && !G->queue_cur->was_fuzzed) {
    G->queue_cur->was_fuzzed = 1;
    G->pending_not_fuzzed--;
    if (G->queue_cur->favored) G->pending_favored--;
  }

  munmap(orig_in, G->queue_cur->len);

  if (in_buf != orig_in) ck_free(in_buf);
  ck_free(out_buf);
  ck_free(eff_map);

  return ret_val;

#undef FLIP_BIT

}
