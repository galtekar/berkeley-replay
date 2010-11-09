#####
# Load the replay group
load --debug-level=0 file:/tmp/bdr-galtekar/recordings/*

#####
# Setup a taint flow probe

py msg_map = {}

#probe-add syscall:::return
###print "syscall!"
#end


probe-add io:ipc:write:return
if __MSG__.id:
    print "Task", __TASK__.index, "sent:", (__MSG__.id, __MSG__.len)
    msg_map[__MSG__.id] = __MSG__.len
end

probe-add io:ipc:peek,dequeue:return
if __MSG__.id:
    print "Task", __TASK__.index, "received:", (__MSG__.id, __MSG__.len)
    if __MSG__.id not in msg_map:
        print "Message received before it was sent!"
    else:
        if __EVENT__.func_name != "peek":
            msg_map[__MSG__.id] -= __MSG__.len
            if msg_map[__MSG__.id] == 0:
                del msg_map[__MSG__.id]
end

continue
exit
