#include "byte.h"
#include "stralloc.h"

int stralloc_cat(stralloc *sato,const stralloc *safrom)
{
  return stralloc_catb(sato,safrom->s,safrom->len);
}

int stralloc_len(const stralloc *safrom)
{
	return safrom->len;
}
