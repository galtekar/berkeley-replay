# vim:ts=4:sw=4:expandtab

import os, dbhash
import misc, controllee, events, recording, split
import progressbar as pb
import urlparse, urlparse_custom

class FormDB:
    def __init__( self, rec_uuid_str ):
        # Download the dbs to this machine
        # XXX: we could have all nodes dump the db into
        # mysql/hbase, but this requires more setup on the part of
        # the user
       
        local_dir = misc.app_base_dir + "/replay-cache/" + rec_uuid_str

        for x in xrange(2):
            try:
                self.form_db = dbhash.open(local_dir + "/comp-subform.db")
                self.var_db = dbhash.open(local_dir + "/var-comp.db")
            except:
                if x == 0:
                    self._generate_jit_db( local_dir )
                else:
                    misc.error( "db tables not found, could not generate formula" )
                    raise
            else:
                break
        assert( self.form_db )
        assert( self.var_db )

    def _generate_formula( self, rec_dir ):
        opt_list = ["DCGen.OutputFormula=true", "DCGen.AssumeUnknown=%s"%(misc.unknowns)]

        url = urlparse.urlparse( "file:///%s"%(rec_dir) )
        rec = recording.Recording( url )
        rec.cache_url = url
        ctrl = controllee.start( rec, "Replay,DCGen", opt_list, quiet=True )
        (begin_vclock, end_vclock, is_value_det) = ctrl.get_status()

        widgets = ['FormGen:', pb.Percentage(), ' ', pb.Bar(marker=pb.RotatingMarker()),\
              ' ']
        pbar = pb.ProgressBar(widgets=widgets, maxval=end_vclock-begin_vclock).start()

        curr_vclock = begin_vclock
        while True:
            ctrl.advance( curr_vclock + (1000000 / 5) )
            event = ctrl.wait()

            if isinstance(event, events.StopEvent):
                curr_vclock = ctrl.get_status()[0]
                misc.debug( "curr_vclock:", curr_vclock )
                misc.debug( "end_vclock:", end_vclock )
                assert( curr_vclock >= 0 )
                assert( curr_vclock >= begin_vclock )
                pbar.update( curr_vclock - begin_vclock )
            elif isinstance(event, events.ShutdownEvent):
                pbar.finish()
                break
        ctrl.kill( "end" )
        return

    def _split_formula( self, rec_dir ):
        split.split( rec_dir )
        return
        
    def _generate_jit_db( self, rec_dir ):
        self._generate_formula( rec_dir )
        self._split_formula( rec_dir ) 
        return

    def __del__( self ):
        self.form_db.close()
        self.var_db.close()

    def lookup( self, var_name ):
        comp_id = self.var_db[var_name]
        form_str = self.form_db[comp_id]
        return form_str

    def lookup_list( self, var_name_list ):
        form_str_list = []
        comp_set = set()
        for var_name in var_name_list:
            try:
                comp_id = self.var_db[var_name]
            except KeyError:
                continue
            else:
                comp_set.add(comp_id)
        for id in comp_set:
            form_str_list.append(self.form_db[id])
        return form_str_list
