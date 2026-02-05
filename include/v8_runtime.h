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
