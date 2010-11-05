#include "pin.h"
#include "syscall.h"

void
PIN_InvalidateCodeCache(ulong start, ulong len)
{
   /* XXX: should only be done if PIN is detected */
   const int SYS_pin_smc = 1000;
   /* Tell PIN that we'vre modified the code -- it needs
    * to invalidate the code cache for this region. */
   syscall(SYS_pin_smc, start, start+len);
}
