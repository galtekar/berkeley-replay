#!/usr/bin/env python2.6

import sys

nr_chunkservers = int(sys.argv[1])

##########
## Meta server config
print """
[metaserver]
node: localhost
rundir: /tmp/kfs-galtekar/meta
baseport: 20000
clusterkey: test-cluster
"""

##########
## Chunk server(s) config
for i in xrange(nr_chunkservers):
   chunk_dir = "chunk-%d"%(i)
   chunk_port = 30000 + i

   print "[chunkserver%d]"%(i)
   print "node: localhost"
   print "rundir: /tmp/kfs-galtekar/%s"%(chunk_dir)
   print "chunkDir: /tmp/kfs-galtekar/%s/bin/kfschunk1 /tmp/kfs-galtekar/%s/bin/kfschunk2"%(chunk_dir, chunk_dir)
   print "baseport:", chunk_port
   print "space: 20 G"
