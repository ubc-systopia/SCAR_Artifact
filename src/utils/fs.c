#include "fs.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "log.h"

int create_directory(const char* dir) {
    struct stat st = {0};
    if (strcmp(dir, "") == 0) {
        return 0;
    }
    if (stat(dir, &st) == -1) {
        char* parent = strdup(dir);
        char* slash = strrchr(parent, '/');
        if (slash) {
            *slash = '\0';
            if (strlen(parent) > 0 && create_directory(parent) != 0) {
                free(parent);
                return 1;
            }
        }
        log_trace("parent: %s", parent);
        free(parent);
        if (mkdir(dir, 0755) == 0) {
        } else {
            log_error("Error creating directory %s: %s", dir, strerror(errno));
            return 1;
        }
    } else {
        log_trace("Directory '%s' already exists", dir);
    }
    return 0;
}

const char* read_file(const char* filepath) {
    FILE* f = fopen(filepath, "rb");
    if (!f) {
        perror("fopen");
        return NULL;
    }

    // Determine file size
    if (fseek(f, 0, SEEK_END) != 0) {
        perror("fseek");
        fclose(f);
        return NULL;
    }
    long size = ftell(f);
    if (size < 0) {
        perror("ftell");
        fclose(f);
        return NULL;
    }
    rewind(f);

    // Allocate buffer
    char* buffer = malloc(size + 1);
    if (!buffer) {
        perror("malloc");
        fclose(f);
        return NULL;
    }

    // Read file content
    size_t read_size = fread(buffer, 1, size, f);
    if (read_size != (size_t)size) {
        perror("fread");
        free(buffer);
        fclose(f);
        return NULL;
    }
    buffer[size] = '\0';

    fclose(f);
    return buffer;
}

int path_exists(const char* path) {
    struct stat buffer;
    return (stat(path, &buffer) == 0);
}
