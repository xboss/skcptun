#ifndef _SSCONFIG_H
#define _SSCONFIG_H

#include <stddef.h>

typedef int (*sscf_cb_t)(const char* key, const char* value, size_t line_no, void* user);

void sscf_setup(size_t max_line_size);
int sscf_parse(const char* filename, sscf_cb_t handler, void* user);



#endif /* SSCONFIG_H */