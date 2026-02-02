#include "log.h"
#include "arch.h"
#include "v8_runtime.h"
#include "shared_memory.h"

sync_ctx_t sync_ctx;

// Extracts a C string from a V8 Utf8Value.
const char* ToCString(const v8::String::Utf8Value& value) {
	return *value ? *value : "<string conversion failed>";
}

void ReportException(v8::Isolate* isolate, v8::TryCatch* try_catch) {
	v8::HandleScope handle_scope(isolate);
	v8::String::Utf8Value exception(isolate, try_catch->Exception());
	const char* exception_string = ToCString(exception);
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
		const char* filename_string = ToCString(filename);
		int linenum = message->GetLineNumber(context).FromJust();
		fprintf(stderr, "%s:%i: %s\n", filename_string, linenum,
				exception_string);
		// Print line of source code.
		v8::String::Utf8Value sourceline(
			isolate, message->GetSourceLine(context).ToLocalChecked());
		const char* sourceline_string = ToCString(sourceline);
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
			const char* err = ToCString(stack_trace);
			fprintf(stderr, "%s\n", err);
		}
	}
}

char* ReadChars(const char* name, int* size_out) {
	FILE* file = fopen(name, "rb");
	if (file == nullptr)
		return nullptr;

	fseek(file, 0, SEEK_END);
	size_t size = ftell(file);
	rewind(file);

	char* chars = new char[size + 1];
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

void ReadBuffer(const v8::FunctionCallbackInfo<v8::Value>& info) {
	// DCHECK(i::ValidateCallbackInfo(info));
	static_assert(sizeof(char) == sizeof(uint8_t),
				  "char and uint8_t should both have 1 byte");
	v8::Isolate* isolate = info.GetIsolate();
	v8::String::Utf8Value filename(isolate, info[0]);
	int length;
	if (*filename == nullptr) {
		log_error("Error loading file");
		return;
	}

	uint8_t* data = reinterpret_cast<uint8_t*>(ReadChars(*filename, &length));
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
void Print(const v8::FunctionCallbackInfo<v8::Value>& info) {
	bool first = true;
	for (int i = 0; i < info.Length(); i++) {
		v8::HandleScope handle_scope(info.GetIsolate());
		if (first) {
			first = false;
		} else {
			printf(" ");
		}
		v8::String::Utf8Value str(info.GetIsolate(), info[i]);
		const char* cstr = ToCString(str);
		printf("%s", cstr);
	}
	printf("\n");
	fflush(stdout);
}

// Reads a file into a v8 string.
v8::MaybeLocal<v8::String> ReadFile(v8::Isolate* isolate, const char* name) {
	FILE* file = fopen(name, "rb");
	if (file == nullptr)
		return {};

	fseek(file, 0, SEEK_END);
	size_t size = ftell(file);
	rewind(file);

	char* chars = new char[size + 1];
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

void Read(const v8::FunctionCallbackInfo<v8::Value>& info) {
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

void Rdtscp(const v8::FunctionCallbackInfo<v8::Value>& info) {
	v8::Isolate* isolate = info.GetIsolate();
	v8::Local<v8::BigInt> tsc = v8::BigInt::NewFromUnsigned(isolate, rdtscp());
	info.GetReturnValue().Set(tsc);
}
