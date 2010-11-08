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

class OptionSection:
    def __init__(self, name, desc, opts):
        self.name = name
        self.desc = desc
        self.opts = opts

class Option:
    def __init__(self, argname, arglist, defarg, desc, func):
        self.argname = argname
        self.arglist = arglist
        self.defarg = defarg
        self.desc = desc
        self.func = func

class ListOption(Option):
    def __init__(self, argname, arglist, defarg, desc, func):
        Option.__init__(self, argname, arglist, defarg, desc, func)

class ArglessOption(Option):
    def __init__(self, desc, func):
        Option.__init__(self, None, None, None, desc, func)

class ArgOption(Option):
    def __init__(self, argname, desc, func):
        Option.__init__(self, argname, None, None, desc, func)


class Options:
    def __get_opt_name(self, secname, k):
        if secname == "base":
            return k
        else:
            return "%s-%s"%(secname, k)

    def __init__(self, basesec, optsecs):
        self.basesec = basesec
        self.optsecs = optsecs
        self.flat_opts = {}

        def addsec(secname, sec):
            for (k, v) in sec.opts.items():
                self.flat_opts[self.__get_opt_name(secname, k)] = v

        addsec("base", basesec)
        if self.optsecs:
            for (secname, sec) in self.optsecs.items():
                addsec(secname, sec)

    def parse(self):
        #short_opts = ''.join(["%s%s"%(opt[0], ":" if opt[2] else "") for opt in options_list])
        short_opts = ""

        #print self.flat_opts
        long_opts = [ "%s%s"%(k, "=" if v.argname else "") for (k, v) in self.flat_opts.items() ]
        #print "Long opts:", long_opts
        try:
            opts, args = getopt.getopt(sys.argv[1:], short_opts, long_opts)
        except getopt.GetoptError, ge:
            misc.die( str(ge) )

        optset = set()
        for (l, s) in opts:
            optset.add(l)

        for (k, v) in self.flat_opts.items():
            #print (k, v, v.argname)
            opt_k = "--%s"%k
            if v.argname:
                if opt_k in optset:
                    v.func(opts[opt_k])
                elif v.defarg:
                    v.func(v.defarg)
            else:
                if opt_k in optset:
                    v.func()
#        for optname, arg in opts:
#            if optname.startswith("--") and optname[2:] in self.flat_opts:
#                v = self.flat_opts[optname[2:]]
#                func = v[2]
#                if v[0]:
#                    func(arg)
#                else:
#                    func()
        return args

    def usage(self):
        def do_sec(secname, sec):
            print "\n%s:"%(sec.desc)
            for (k,v) in sorted(sec.opts.items()):
                opt_str = "--%s%s"%(self.__get_opt_name(secname, k), "=%s"%(v.argname) if v.argname else "")
                descstr = v.desc
                if v.argname and v.defarg:
                    descstr += " [%s]"%(v.defarg)
                print "  %-30s %s"%(opt_str, descstr)


        do_sec("base", self.basesec)
        if self.optsecs:
            for (secname, sec) in sorted(self.optsecs.items()):
                do_sec(secname, sec)
        return

class HelpOptions(Options):
   def __init__(self, basesec, optsecs):
      #assert("help" not in opt_map)
      basesec.opts["help"] = ArglessOption("provide help with commands", self.__help)
      Options.__init__(self, basesec, optsecs)
      return

   def __help(self):
      self.usage()
      sys.exit(-1)
      return
