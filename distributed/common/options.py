######################################################################
# 
# Copyright (C) 2010 The Regents of the University of California. 
# All rights reserved.
#
# Author: Gautam Altekar
#
# vim:ts=4:sw=4:expandtab
#
######################################################################
import sys, getopt
import misc

class Options:
    def __init__(self, opt_map):
        self.opt_map = opt_map
        if "help" not in self.opt_map:
            self.opt_map["help"] = (None, "provide help with commands", self.__help)

    def parse(self):
        #short_opts = ''.join(["%s%s"%(opt[0], ":" if opt[2] else "") for opt in options_list])
        short_opts = ""
        long_opts = ["%s%s"%(k, "=" if v[0] else "") for (k, v) in self.opt_map.items()]
        try:
            opts, args = getopt.getopt(sys.argv[1:], short_opts, long_opts)
        except getopt.GetoptError, ge:
            misc.die( str(ge) )

        for opt, arg in opts:
            if opt.startswith("--") and opt[2:] in self.opt_map:
                v = self.opt_map[opt[2:]]
                func = v[2]
                if v[0]:
                    func(arg)
                else:
                    func()
        return args

    def usage(self):
        print "\nOptions:"
        for (k,v) in sorted(self.opt_map.items()):
            opt_str = "--%s%s"%(k, "=%s"%(v[0]) if v[0] else "")
            print "  %-30s %s"%(opt_str, v[1])
        return

    def __help(self):
        self.usage()
        sys.exit(-1)
