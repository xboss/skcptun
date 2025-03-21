#include "ssconfig.h"

#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define _OK 0
#define _ERR -1

#define SSCF_MAX_LINE_SIZE 256

size_t g_max_line_size = SSCF_MAX_LINE_SIZE;

inline static char* trim(char* str) {
    char* end;
    if (str == NULL || *str == '\0') return str;
    while (isspace((unsigned char)*str) && *str != '\0') str++;
    if (*str == '\0') return str;
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    *(end + 1) = '\0';
    return str;
}

inline static int parse_line(char* line, size_t line_no, sscf_cb_t handler, void* user) {
    char* eqp = strchr(line, '=');
    if (eqp == NULL) {
        fprintf(stderr, "ERROR: config file line:%zu format error. must be in the format of 'key=value'\n",
                line_no + 1);
        return _ERR;
    }
    int key_len = eqp - line;
    assert(key_len > 0);
    int value_len = line + strlen(line) - eqp;
    assert(value_len > 0);
    line[eqp - line] = '\0';
    char* key = trim(line);
    char* value = trim(eqp + 1);
    if (key == NULL || value == NULL || strlen(key) == 0 || strlen(value) == 0) {
        fprintf(stderr, "ERROR: config file line:%zu format error. must be in the format of 'key=value'\n",
                line_no + 1);
        return _ERR;
    }
    if (handler != NULL) handler(key, value, line_no + 1, user);
    return _OK;
}

static int parse_file(FILE* fp, sscf_cb_t handler, void* user) {
    int ret = _OK;
    size_t sl = 0;
    char* p = NULL;
    char* line = (char*)calloc(g_max_line_size + 2, sizeof(char));
    if (!line) {
        fprintf(stderr, "Memory allocation failed\n");
        return _ERR;
    }
    for (size_t line_no = 0; fgets(line, g_max_line_size + 2, fp) != NULL; line_no++) {
        sl = strlen(line);
        if (sl > g_max_line_size && line[sl - 1] != '\n') {
            fprintf(stderr, "ERROR: config file line:%zu is too long. must be less than %zu\n", line_no + 1,
                    g_max_line_size);
            ret = _ERR;
            break;
        }
        p = trim(line);
        if (p[0] == '\0' || p[0] == '#' || p[0] == '\n' || strlen(p) == 0) continue;
        if (p[0] == '=' || p[strlen(p) - 1] == '=') {
            fprintf(stderr, "ERROR: config file line:%zu format error. must be in the format of 'key=value'\n",
                    line_no + 1);
            ret = _ERR;
            break;
        }
        if (parse_line(p, line_no, handler, user) == _ERR) {
            ret = _ERR;
            break;
        }
    }
    free(line);
    return ret;
}

void sscf_setup(size_t max_line_size) {
    if (max_line_size > 0) g_max_line_size = max_line_size;
}

int sscf_parse(const char* filename, sscf_cb_t handler, void* user) {
    FILE* file;
    file = fopen(filename, "r");
    if (!file) {
        perror("fopen failed");
        return _ERR;
    }
    int ret = parse_file(file, handler, user);
    fclose(file);
    return ret;
}