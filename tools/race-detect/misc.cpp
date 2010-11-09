#include "misc.h"
#include "syncops.h"
#include "sharedarea.h"

SHAREDAREA struct SynchLock eventLock;

char* 
use_xed(ADDRINT pc, char* buf, size_t bufSz) 
{
#if defined(TARGET_IA32E)
    static const xed_state_t dstate = {XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b};
#else
    static const xed_state_t dstate = { XED_MACHINE_MODE_LEGACY_32, XED_ADDRESS_WIDTH_32b, XED_ADDRESS_WIDTH_32b};
#endif
    xed_decoded_inst_t xedd;
    xed_decoded_inst_zero_set_mode(&xedd,&dstate);

    //FIXME: pass in the proper length...
    const unsigned int max_inst_len = 15;
    xed_error_enum_t xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(pc), max_inst_len);
    BOOL xed_ok = (xed_code == XED_ERROR_NONE);
    if (xed_ok) {
        xed_decoded_inst_dump_intel_format(&xedd, buf, bufSz, 0);
        return buf;
    }

    return NULL;
}
