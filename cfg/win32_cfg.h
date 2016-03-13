#ifndef WIN32_CFG_H
#define WIN32_CFG_H

#include "../pe/pelib_extend/pelib_extend.h"

/* Build Control Flow Graph recursively from binaries text code section */
int cfg_build (PEExtend *PE, char *path);

#endif
