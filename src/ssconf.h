#ifndef _SSCONF_H
#define _SSCONF_H

typedef struct ssconf_s ssconf_t;

ssconf_t *ssconf_init(int max_line_size, int max_rows);
void ssconf_free(ssconf_t *conf);
int ssconf_load(ssconf_t *conf, const char *file);
char *ssconf_get_value(ssconf_t *conf, char *key);

#endif /* SSCONF_H */