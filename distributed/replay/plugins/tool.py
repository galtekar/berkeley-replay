######################################################################
# 
# Copyright (C) 2010 The Regents of the University of California. 
# All rights reserved.
#
# Author: Gautam Altekar
#
# vim:ts=4:sw=4:expandtab
#
# Summary:
#
#   The tool abstraction. Shold be dervied from by all replay tool.
#   
######################################################################

tools = {}

class Tool():
    def __init__(self, name, optsec, desc):
        self.name = name
        self.optsec = optsec
        self.desc = desc
        return

    #def print( *args, **kwargs ):
        #string = my_name + ": " + ' '.join( map( str, args ) )
        #print( string )


def register(tool):
    if tool.name not in tools:
        tools[tool.name] = tool
    else:
        raise Exception
