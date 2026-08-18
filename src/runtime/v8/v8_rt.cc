#include <cstdio>

#include "v8_runtime.h"

int main(int argc, char *argv[]) {
	if (argc < 3) {
		fprintf(stderr,
		        "Usage: %s <source.js> <repeat.js> [keypair_template.js]\n",
		        argv[0]);
		return 1;
	}
	v8_run_loop(argc, argv);
	return 0;
}
