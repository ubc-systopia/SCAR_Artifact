#include "v8_runtime.h"

extern "C" {
#include "log.h"
#include "arch.h"
#include "shared_memory.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "fs.h"

sync_ctx_t sync_ctx;
}

// Extracts a C string from a V8 Utf8Value.
const char *ToCString(const v8::String::Utf8Value &value) {
	return *value ? *value : "<string conversion failed>";
}

void ReportException(v8::Isolate *isolate, v8::TryCatch *try_catch) {
	v8::HandleScope handle_scope(isolate);
	v8::String::Utf8Value exception(isolate, try_catch->Exception());
	const char *exception_string = ToCString(exception);
	v8::Local<v8::Message> message = try_catch->Message();
	if (message.IsEmpty()) {
		// V8 didn't provide any extra information about this error; just
		// print the exception.
		fprintf(stderr, "%s\n", exception_string);
	} else {
		// Print (filename):(line number): (message).
		v8::String::Utf8Value filename(
		    isolate, message->GetScriptOrigin().ResourceName());
		v8::Local<v8::Context> context(isolate->GetCurrentContext());
		const char *filename_string = ToCString(filename);
		int linenum = message->GetLineNumber(context).FromJust();
		fprintf(
		    stderr, "%s:%i: %s\n", filename_string, linenum, exception_string);
		// Print line of source code.
		v8::String::Utf8Value sourceline(
		    isolate, message->GetSourceLine(context).ToLocalChecked());
		const char *sourceline_string = ToCString(sourceline);
		fprintf(stderr, "%s\n", sourceline_string);
		// Print wavy underline (GetUnderline is deprecated).
		int start = message->GetStartColumn(context).FromJust();
		for (int i = 0; i < start; i++) {
			fprintf(stderr, " ");
		}
		int end = message->GetEndColumn(context).FromJust();
		for (int i = start; i < end; i++) {
			fprintf(stderr, "^");
		}
		fprintf(stderr, "\n");
		v8::Local<v8::Value> stack_trace_string;
		if (try_catch->StackTrace(context).ToLocal(&stack_trace_string) &&
		    stack_trace_string->IsString() &&
		    stack_trace_string.As<v8::String>()->Length() > 0) {
			v8::String::Utf8Value stack_trace(isolate, stack_trace_string);
			const char *err = ToCString(stack_trace);
			fprintf(stderr, "%s\n", err);
		}
	}
}

char *ReadChars(const char *name, int *size_out) {
	FILE *file = fopen(name, "rb");
	if (file == nullptr)
		return nullptr;

	fseek(file, 0, SEEK_END);
	size_t size = ftell(file);
	rewind(file);

	char *chars = new char[size + 1];
	chars[size] = '\0';
	for (size_t i = 0; i < size;) {
		i += fread(&chars[i], 1, size - i, file);
		if (ferror(file)) {
			fclose(file);
			delete[] chars;
			return nullptr;
		}
	}
	fclose(file);
	*size_out = static_cast<int>(size);
	return chars;
}

void ReadBuffer(const v8::FunctionCallbackInfo<v8::Value> &info) {
	// DCHECK(i::ValidateCallbackInfo(info));
	static_assert(sizeof(char) == sizeof(uint8_t),
	              "char and uint8_t should both have 1 byte");
	v8::Isolate *isolate = info.GetIsolate();
	v8::String::Utf8Value filename(isolate, info[0]);
	int length;
	if (*filename == nullptr) {
		log_error("Error loading file");
		return;
	}

	uint8_t *data = reinterpret_cast<uint8_t *>(ReadChars(*filename, &length));
	if (data == nullptr) {
		log_error("Error reading file");
		return;
	}
	v8::Local<v8::ArrayBuffer> buffer = v8::ArrayBuffer::New(isolate, length);
	memcpy(buffer->GetBackingStore()->Data(), data, length);
	delete[] data;

	info.GetReturnValue().Set(buffer);
}

// The callback that is invoked by v8 whenever the JavaScript 'print'
// function is called.  Prints its arguments on stdout separated by
// spaces and ending with a newline.
void Print(const v8::FunctionCallbackInfo<v8::Value> &info) {
	bool first = true;
	for (int i = 0; i < info.Length(); i++) {
		v8::HandleScope handle_scope(info.GetIsolate());
		if (first) {
			first = false;
		} else {
			printf(" ");
		}
		v8::String::Utf8Value str(info.GetIsolate(), info[i]);
		const char *cstr = ToCString(str);
		printf("%s", cstr);
	}
	printf("\n");
	fflush(stdout);
}

// Reads a file into a v8 string.
v8::MaybeLocal<v8::String> ReadFile(v8::Isolate *isolate, const char *name) {
	FILE *file = fopen(name, "rb");
	if (file == nullptr)
		return {};

	fseek(file, 0, SEEK_END);
	size_t size = ftell(file);
	rewind(file);

	char *chars = new char[size + 1];
	chars[size] = '\0';
	for (size_t i = 0; i < size;) {
		i += fread(&chars[i], 1, size - i, file);
		if (ferror(file)) {
			fclose(file);
			return {};
		}
	}
	fclose(file);
	v8::MaybeLocal<v8::String> result = v8::String::NewFromUtf8(
	    isolate, chars, v8::NewStringType::kNormal, static_cast<int>(size));
	delete[] chars;
	return result;
}

void Read(const v8::FunctionCallbackInfo<v8::Value> &info) {
	if (info.Length() != 1) {
		info.GetIsolate()->ThrowError("Bad parameters");
		return;
	}
	v8::String::Utf8Value file(info.GetIsolate(), info[0]);
	if (*file == nullptr) {
		info.GetIsolate()->ThrowError("Error loading file");
		return;
	}
	v8::Local<v8::String> source;
	if (!ReadFile(info.GetIsolate(), *file).ToLocal(&source)) {
		info.GetIsolate()->ThrowError("Error loading file");
		return;
	}

	info.GetReturnValue().Set(source);
}

void Rdtscp(const v8::FunctionCallbackInfo<v8::Value> &info) {
	v8::Isolate *isolate = info.GetIsolate();
	v8::Local<v8::BigInt> tsc = v8::BigInt::NewFromUnsigned(isolate, rdtscp());
	info.GetReturnValue().Set(tsc);
}

/* Match a tag-prefixed JIT event name ("BytecodeHandler:NegateHandler") against
 * a bare builtin name: strip through the first ':' then compare exactly so
 * "NegateHandler" does not also catch "NegateWideHandler". */
static bool jit_name_is(const v8::JitCodeEvent *event, const char *base) {
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

/* The bundles used here are self-contained (no imports); fail loudly if a
 * module tries to import a specifier. */
static v8::MaybeLocal<v8::Module> v8_resolve_module(
    v8::Local<v8::Context> context,
    v8::Local<v8::String> specifier,
    v8::Local<v8::FixedArray> import_attributes,
    v8::Local<v8::Module> referrer) {
	(void)specifier;
	(void)import_attributes;
	(void)referrer;
	context->GetIsolate()->ThrowError(
	    "module imports are not supported by this embedder");
	return v8::MaybeLocal<v8::Module>();
}

/* Compile/instantiate/evaluate <source_str> as an ES module and return its
 * module namespace object (the bag of exports). */
static v8::MaybeLocal<v8::Value> v8_eval_module(v8::Local<v8::Context> context,
                                                const char *name,
                                                const char *source_str) {
	v8::Isolate *isolate = context->GetIsolate();
	v8::Local<v8::String> source =
	    v8::String::NewFromUtf8(isolate, source_str).ToLocalChecked();
	v8::ScriptOrigin origin(
	    v8::String::NewFromUtf8(isolate, name).ToLocalChecked(),
	    0,
	    0,
	    false,
	    -1,
	    v8::Local<v8::Value>(),
	    false,
	    false,
	    true /* is_module */);
	v8::ScriptCompiler::Source module_source(source, origin);
	v8::Local<v8::Module> module;
	if (!v8::ScriptCompiler::CompileModule(isolate, &module_source)
	         .ToLocal(&module)) {
		return {};
	}
	if (module->InstantiateModule(context, v8_resolve_module).IsNothing()) {
		return {};
	}
	v8::Local<v8::Value> result;
	if (!module->Evaluate(context).ToLocal(&result)) {
		return {};
	}
	isolate->PerformMicrotaskCheckpoint();
	return module->GetModuleNamespace();
}

void v8_run_loop(int argc, char *argv[]) {
	reset_sync_ctx(V8_PROJ_ID);

	/* Echo the parsed arguments; if the JS paths are missing (e.g. a broken
	 * shell line-continuation) this immediately shows argv[1..3] are flags. */
	log_info("v8_run_loop argc=%d source=%s repeat=%s template=%s",
	         argc,
	         argc > 1 ? argv[1] : "(none)",
	         argc > 2 ? argv[2] : "(none)",
	         argc > 3 ? argv[3] : "(none)");

	const char *source_str = read_file(argv[1]);
	if (!source_str) {
		log_error("cannot read source script '%s' (arg 1) -- is the path right "
		          "and passed before any --flags?",
		          argv[1] ? argv[1] : "(null)");
		return;
	}
	const char *repeat_str = read_file(argv[2]);
	if (!repeat_str) {
		log_error("cannot read repeat script '%s' (arg 2)",
		          argv[2] ? argv[2] : "(null)");
		return;
	}
	/* argv[3] (SET_KEY template) is optional: a pure profiling run that never
	 * issues SYNC_CTX_SET_KEY does not need it. */
	const char *set_keypair_template = nullptr;
	if (argc > 3) {
		set_keypair_template = read_file(argv[3]);
		if (!set_keypair_template) {
			log_error("cannot read set-keypair template '%s' (arg 3)", argv[3]);
			return;
		}
	}
	static uintptr_t jit_machine_code;
	/* Bytecode-handler builtins for the V8 constant-time-select victim; stay 0
	 * for other victims. Published alongside jit_machine_code. */
	static uintptr_t addr_negate;
	static uintptr_t addr_bitand;

	v8::V8::InitializeICUDefaultLocation(argv[0]);
	v8::V8::SetFlagsFromCommandLine(&argc, argv, true);
	std::unique_ptr<v8::Platform> platform = v8::platform::NewDefaultPlatform();
	v8::V8::InitializePlatform(platform.get());
	v8::V8::Initialize();

	v8::Isolate::CreateParams create_params;
	create_params.array_buffer_allocator =
	    v8::ArrayBuffer::Allocator::NewDefaultAllocator();
	v8::Isolate *isolate = v8::Isolate::New(create_params);
	{
		v8::Isolate::Scope iscope(isolate);
		v8::HandleScope scope(isolate);
		v8::TryCatch try_catch(isolate);

		/* Must run inside Isolate::Scope: the enum-existing pass walks the heap
		 * and needs a LocalHeap, else a debug CHECK (isolate.cc) fires. */
		isolate->SetJitCodeEventHandler(
		    static_cast<v8::JitCodeEventOptions>(
		        v8::kJitCodeEventDefault | v8::kJitCodeEventEnumExisting),
		    [](const v8::JitCodeEvent *event) {
			    if (event->type != v8::JitCodeEvent::CODE_ADDED)
				    return;
			    if (event->code_type != v8::JitCodeEvent::JIT_CODE)
				    return;
			    /* Bytecode-handler builtins have an empty script and load at
			     * isolate creation, so they arrive via the enum-existing pass;
			     * resolve them for the constant-time-select victim. */
			    if (jit_name_is(event, "NegateHandler")) {
				    addr_negate =
				        reinterpret_cast<uintptr_t>(event->code_start);
				    return;
			    }
			    if (jit_name_is(event, "BitwiseAndSmiWideHandler")) {
				    addr_bitand =
				        reinterpret_cast<uintptr_t>(event->code_start);
				    return;
			    }
			    if (event->script.IsEmpty())
				    return;
			    log_debug("JIT event %.*s: code_start=%p len=%zu",
			              event->name.len,
			              event->name.str,
			              event->code_start,
			              event->code_len);
			    const char target[] = "JS:*mul :6643:37";
			    if (event->name.len == sizeof(target) - 1 &&
			        memcmp(event->name.str, target, event->name.len) == 0) {
				    jit_machine_code =
				        reinterpret_cast<uintptr_t>(event->code_start);
				    log_info(LOG_BOLD_ON
				             "Get target address to %p" LOG_BOLD_OFF,
				             jit_machine_code);
			    }
		    });

		v8::Local<v8::ObjectTemplate> global = v8::ObjectTemplate::New(isolate);
		global->Set(
		    isolate, "rdtscp", v8::FunctionTemplate::New(isolate, Rdtscp));
		global->Set(isolate, "read", v8::FunctionTemplate::New(isolate, Read));
		global->Set(isolate,
		            "readbuffer",
		            v8::FunctionTemplate::New(isolate, ReadBuffer));
		global->Set(
		    isolate, "print", v8::FunctionTemplate::New(isolate, Print));
		v8::Local<v8::Context> context =
		    v8::Context::New(isolate, nullptr, global);
		v8::Context::Scope cscope(context);

		log_info("V8 runtime load script");
		if (getenv("V8_MODULE_SOURCE")) {
			/* The source is an ES module (e.g. the bundled openpgp used by the
			 * constant-time-select victim): evaluate it and expose its exports
			 * as the `openpgp` global so a classic repeat script reaches them. */
			v8::Local<v8::Value> ns;
			if (!v8_eval_module(context, "module_source", source_str)
			         .ToLocal(&ns)) {
				ReportException(isolate, &try_catch);
				log_error("failed to evaluate module source");
			} else {
				context->Global()
				    ->Set(context,
				          v8::String::NewFromUtf8Literal(isolate, "openpgp"),
				          ns)
				    .Check();
			}
		} else {
			v8::Local<v8::String> source =
			    v8::String::NewFromUtf8(isolate, source_str).ToLocalChecked();
			v8::Script::Compile(context, source)
			    .ToLocalChecked()
			    ->Run(context)
			    .ToLocalChecked();
		}

		v8::Local<v8::String> repeat_src =
		    v8::String::NewFromUtf8(isolate, repeat_str).ToLocalChecked();
		v8::Local<v8::Value> repeat_result =
		    v8::Script::Compile(context, repeat_src)
		        .ToLocalChecked()
		        ->Run(context)
		        .ToLocalChecked();
		v8::Local<v8::Function> repeat_func = repeat_result.As<v8::Function>();

		/* Default 1000 tiers up a fast victim (ecdh derive). Override via
		 * V8_WARMUP for a slow one: each CT warmup iteration is a full ~8s RSA
		 * sign, so 1000 would take hours -- a handful suffices to tier up the
		 * modexp under --always-turbofan while select stays interpreted. */
		int warmup_iters = getenv("V8_WARMUP") ? atoi(getenv("V8_WARMUP")) : 1000;
		log_info("V8 runtime JIT warmup (%d iters)", warmup_iters);
		for (int i = 0; i < warmup_iters; ++i) {
			repeat_func->Call(context, context->Global(), 0, nullptr)
			    .ToLocalChecked();
			/* Drain the microtask queue so async victims (e.g. the openpgp
			 * sign) actually run to completion; a no-op for sync victims. */
			isolate->PerformMicrotaskCheckpoint();
		}

		uintptr_t published[3] = { jit_machine_code, addr_negate, addr_bitand };
		memcpy(sync_ctx.data, published, sizeof(published));

		log_info("Pass jit code start %p (negate=%p bitand=%p)",
		         (void *)jit_machine_code,
		         (void *)addr_negate,
		         (void *)addr_bitand);

		log_info("V8 runtime ready");
		pthread_barrier_wait(sync_ctx.barrier); /* #1: init done */
		pthread_barrier_wait(sync_ctx.barrier); /* #2: wait for attacker LLCF */

		log_info("V8 runtime entering eval loop");
		do {
			pthread_barrier_wait(sync_ctx.barrier); /* A: wait for action */

			sync_ctx_action_t action = sync_ctx_get_action();
			if (action == SYNC_CTX_EXIT) {
				break;
			} else if (action == SYNC_CTX_START) {
				repeat_func->Call(context, context->Global(), 0, nullptr);
				/* Run the async body (openpgp sign) to completion inside the
				 * profiling window; no-op for sync victims (ecdh derive). */
				isolate->PerformMicrotaskCheckpoint();
			} else if (action == SYNC_CTX_SET_KEY && set_keypair_template) {
				char key_str[4096];
				snprintf(key_str,
				         sizeof(key_str),
				         set_keypair_template,
				         (const char *)sync_ctx.data);
				v8::Local<v8::String> key_src =
				    v8::String::NewFromUtf8(isolate, key_str).ToLocalChecked();
				v8::Script::Compile(context, key_src)
				    .ToLocalChecked()
				    ->Run(context);
			}

			sync_ctx_set_action(SYNC_CTX_PAUSE);
			pthread_barrier_wait(sync_ctx.barrier); /* B */
		} while (1);
	}
	isolate->Dispose();
	v8::V8::Dispose();
	v8::V8::DisposePlatform();
	delete create_params.array_buffer_allocator;
}

void v8_runtime_csi_victim_loop(v8::Isolate *isolate,
                                v8::Local<v8::Context> context,
                                v8::Local<v8::Function> repeat_func,
                                const char *set_keypair_template) {
	pthread_barrier_wait(sync_ctx.barrier); /* #2: victim in the loop */
	for (;;) {
		pthread_barrier_wait(sync_ctx.barrier); /* A */
		sync_ctx_action_t act = sync_ctx_get_action();
		if (act == SYNC_CTX_EXIT) {
			break;
		}
		if (act == SYNC_CTX_SET_KEY) {
			char key_script[4096];
			snprintf(key_script,
			         sizeof(key_script),
			         set_keypair_template,
			         (const char *)sync_ctx.data);
			v8::Local<v8::String> src =
			    v8::String::NewFromUtf8(isolate, key_script).ToLocalChecked();
			v8::Local<v8::Script> sc =
			    v8::Script::Compile(context, src).ToLocalChecked();
			(void)sc->Run(context);
		} else if (act == SYNC_CTX_START) {
			(void)repeat_func->Call(context, context->Global(), 0, nullptr);
			/* PS_profile_once warns at its end barrier if this has not been
			 * published, i.e. if the profiling window closed before the
			 * derive finished. Publishing it is what makes that check mean
			 * something. */
			sync_ctx_set_action(SYNC_CTX_PAUSE);
		}
		pthread_barrier_wait(sync_ctx.barrier); /* B */
	}
}
