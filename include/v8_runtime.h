#pragma once

#include "libplatform/libplatform.h"
#include "v8.h"

extern "C" {
void _Z25_v8_internal_Print_ObjectPv(void*);
void _Z33_v8_internal_Print_Object_MarkBitPv(void*);
void _Z35_v8_internal_Print_Object_To_StringB5cxx11Pv(void*);
}

const char* ToCString(const v8::String::Utf8Value& value);
void ReportException(v8::Isolate* isolate, v8::TryCatch* try_catch);
char* ReadChars(const char* name, int* size_out) ;
void ReadBuffer(const v8::FunctionCallbackInfo<v8::Value>& info) ;
void Print(const v8::FunctionCallbackInfo<v8::Value>& info);
v8::MaybeLocal<v8::String> ReadFile(v8::Isolate* isolate, const char* name);
void Read(const v8::FunctionCallbackInfo<v8::Value>& info) ;
void Rdtscp(const v8::FunctionCallbackInfo<v8::Value>& info) ;
void v8_run_loop(int argc, char *argv[]);

/* Victim side of the cache-set-identification handshake.
 *
 * The scanner runs on its own thread and owns the protocol; this runs on the
 * V8 thread because everything it touches -- isolate, context, the repeat
 * function -- is bound to it. One pre-loop barrier, then per request:
 * barrier A, act on sync_ctx_get_action(), barrier B. EXIT breaks after A
 * only, so the scanner must not wait on B for that one.
 *
 * Both v8_ecdh_key_pool.cc and v8_ctjs_ecdh.cc need exactly this loop. */
void v8_runtime_csi_victim_loop(v8::Isolate *isolate,
                                v8::Local<v8::Context> context,
                                v8::Local<v8::Function> repeat_func,
                                const char *set_keypair_template);
