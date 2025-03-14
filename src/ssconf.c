#include "ssconf.h"

#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define _OK 0
#define _ERR -1

typedef struct {
    char *key;
    char *value;
} ssconf_item_t;

struct ssconf_s {
    ssconf_item_t **items;
    int items_cnt;
    int max_line_size;
    int max_rows;
    int max_key_size;
    int max_value_size;
};

inline static char *trim(char *str) {
    char *end;
    // 如果字符串为空或仅包含空白字符，则返回空指针
    if (str == NULL || *str == '\0') {
        return str;
    }
    // 跳过字符串前面的所有空白字符
    while (isspace((unsigned char)*str)) str++;
    // 如果整个字符串都是空白字符
    if (*str == '\0') {
        return str;
    }
    // 找到字符串末尾
    end = str + strlen(str) - 1;
    // 移动到最后一个非空白字符
    while (end > str && isspace((unsigned char)*end)) end--;
    // 将最后一个非空白字符后的字符设为结束符
    *(end + 1) = '\0';
    return str;
}

inline static int parse_line(ssconf_t *conf, char *line, int rows) {
    char *eqp = strchr(line, '=');
    if (eqp == NULL) {
        fprintf(stderr, "config file line:%d format error. must be in the format of 'key=value'\n", rows + 1);
        return _ERR;
    }
    int key_len = eqp - line;
    if (key_len > conf->max_key_size) {
        fprintf(stderr, "config file line:%d 'key' is too long. must be less than %d\n", rows + 1, conf->max_key_size);
        return _ERR;
    }
    int value_len = line + strlen(line) - eqp;
    if (value_len > conf->max_value_size) {
        fprintf(stderr, "config file line:%d 'value' is too long. must be less than %d\n", rows + 1,
                conf->max_value_size);
        return _ERR;
    }

    ssconf_item_t *item = (ssconf_item_t *)calloc(1, sizeof(ssconf_item_t));
    if (!item) {
        fprintf(stderr, "alloc error in config.\n");
        return _ERR;
    }
    item->key = (char *)calloc(1, key_len + 1);
    if (!item->key) {
        fprintf(stderr, "alloc error in config.\n");
        free(item);
        return _ERR;
    }
    item->value = (char *)calloc(1, value_len + 1);
    if (!item->value) {
        fprintf(stderr, "alloc error in config.\n");
        free(item->key);
        free(item);
        return _ERR;
    }
    memcpy(item->key, line, key_len);
    memcpy(item->value, eqp + 1, value_len);
    conf->items[conf->items_cnt++] = item;
    return _OK;
}

int ssconf_load(ssconf_t *conf, const char *file) {
    FILE *fp;
    if ((fp = fopen(file, "r")) == NULL) {
        fprintf(stderr, "can't open config file %s\n", file);
        return _ERR;
    }
    int ret = _OK;
    // char line[MAX_LINE_SIZE + 1] = {0};
    char *line = (char *)calloc(conf->max_line_size + 1, sizeof(char));
    int rows = 0;
    char *p = NULL;
    for (; fgets(line, conf->max_line_size, fp) != NULL; rows++) {
        if (rows > conf->max_rows) {
            fprintf(stderr, "too many lines in config file:%s, must be less than %d\n", file, conf->max_rows);
            ret = _ERR;
            break;
        }

        if (line[conf->max_line_size] != '\0') {
            fprintf(stderr, "config file line:%d is too long. must be less than %d\n", rows + 1, conf->max_line_size);
            ret = _ERR;
            break;
        }
        if (line[0] == '\0' || line[0] == '#' || line[0] == '\n') continue;
        p = trim(line);
        if (p == NULL || strlen(p) == 0) continue;
        if (p[0] == '=' || p[strlen(p) - 1] == '=') {
            fprintf(stderr, "config file line:%d format error. must be in the format of 'key=value'\n", rows + 1);
            ret = _ERR;
            break;
        }
        if (parse_line(conf, p, rows) == _ERR) {
            ret = _ERR;
            break;
        }
    }
    free(line);
    fclose(fp);
    return ret;
}

char *ssconf_get_value(ssconf_t *conf, char *key) {
    if (!conf || !key) return NULL;
    for (int i = 0; i < conf->items_cnt; i++) {
        if (strcmp(key, trim(conf->items[i]->key)) == 0) return trim(conf->items[i]->value);
    }
    return NULL;
}

ssconf_t *ssconf_init(int max_line_size, int max_rows) {
    ssconf_t *conf = (ssconf_t *)calloc(1, sizeof(ssconf_t));
    if (!conf) {
        fprintf(stderr, "alloc error in ssconf_init.\n");
        return NULL;
    }
    conf->max_line_size = max_line_size;
    conf->max_rows = max_rows;
    conf->max_key_size = max_line_size / 2 - 1;
    conf->max_value_size = max_line_size / 2 - 1;
    conf->items = (ssconf_item_t **)calloc(max_rows, sizeof(ssconf_item_t *));
    if (!conf->items) {
        fprintf(stderr, "alloc error in ssconf_init.\n");
        ssconf_free(conf);
        return NULL;
    }
    return conf;
}

void ssconf_free(ssconf_t *conf) {
    if (!conf) return;
    if (conf->items_cnt > 0) {
        for (int i = 0; i < conf->items_cnt; i++) {
            if (!conf->items[i]) continue;
            if (conf->items[i]->key) free(conf->items[i]->key);
            if (conf->items[i]->value) free(conf->items[i]->value);
            free(conf->items[i]);
        }
        free(conf->items);
    }
    free(conf);
}
