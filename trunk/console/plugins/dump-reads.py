#####
# Load the replay group
#
load file:///home/galtekar/test*


#####
# Setup a simple probe

py sys_count = 0
probe-add syscall:::return
import syscall, binascii

sys_name = syscall.get_name(__SYSNO__)
if sys_name == "read":
    buf_addr = __ARGS__[1]
    ret_val = __SYS_RETVAL__
    if ret_val > 0:
      bytes = __TASK__.get_mem_bytes( buf_addr, ret_val )
      assert( len(bytes) == ret_val )
      print "PROBE -- %3d: Task(%d) Read(0x%x, %d) = %s..."%(sys_count, __TASK__.index, buf_addr, ret_val, binascii.hexlify(bytes[0:16]))
    else:
      print "PROBE -- Read %d on task %d failed"%(sys_count, __TASK__.index)
    sys_count += 1
cont
end

continue
