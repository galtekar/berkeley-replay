

class SshRecording(Recording):
    def __init__( self, url, in_situ ):
        Recording.__init__( self, url )
        self.in_situ = in_situ

    def read_uuid( self ):
        assert( 0 )
        return

class LocalRecording(Recording):
    def __init__( self, url ):
        Recording.__init__( self, url )

    def read_uuid( self ):
        # Read the uuid
        f = hdfs.open( self.url.path + "/uuid" )
        content_str = f.read()
        f.close()
        return content_str.strip()


class HdfsRecording(Recording):
    def __init__( self, url ):
        Recording.__init__( self, url )

    def read_uuid( self ):
        # Read the uuid
        hdfs = dfs.Hdfs( self.url.hostname, self.url.port )
        f = hdfs.open( self.url.path + "/uuid" )
        content_str = f.read()
        f.close()
        return content_str.strip()

    def _add_task( self, ctrl, tid ):
        index = self._nr_tasks_created
        self._nr_tasks_created = self._nr_tasks_created + 1
        task = Task( index, ctrl, tid )
        self.replay_tasks[index] = task
        ctrl.task_by_tid[tid] = task
        self._current_task_ids.add(index)


##############3
