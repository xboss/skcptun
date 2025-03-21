#ifndef _SSCONFIG_H
#define _SSCONFIG_H

#include <stddef.h>


void sscf_setup(size_t max_line_size);
int sscf_parse(const char* filename, sscf_cb_t handler, void* user);



#endif /* SSCONFIG_H */