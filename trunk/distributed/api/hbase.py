
from thrift import Thrift
from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol
 
from hbase import Hbase
from hbase.ttypes import *


def HbaseMakeNewTable(client, tableName, columnName):
   # Get rid of the existing table, if any.
   try:
      client.disableTable(tableName)
      client.deleteTable(tableName)
   except IOError:
      print "Can't delete table: " + tableName


   # Create the table.
   try:
      desc = ColumnDescriptor(name=columnName)
      client.createTable(tableName, [desc])
      print client.getTableNames()
   except AlreadyExists, tx:
      print '%s' % (tx.message)


def HbaseWriteFormulas(hb, formMap):
   tableName = "FormulaTable"
   columnName = "body"

   HbaseMakeNewTable(hb, tableName, columnName)

   # Put split formulas into table.
   widgets = ['FormTable: ', Percentage(), ' ', Bar(marker=RotatingMarker()), ' ']
   pbar = ProgressBar(widgets=widgets, maxval=len(formMap)).start()
   count = 0
   batchList = []
   for k in formMap:
      mut = Mutation()
      mut.column = columnName
      mut.value = formMap[k]
      batch = BatchMutation()
      batch.row = str(k)
      batch.mutations = [mut]
      batchList.append(batch)

      count = count + 1

      if count % 1000 == 0:
         hb.mutateRows(tableName, batchList)
         pbar.update(count)
         batchList = []

   pbar.finish()

def HbaseWriteVars(hb, nodeMap):
   tableName = "VariableTable"
   columnName = "formula_id"

   HbaseMakeNewTable(hb, tableName, columnName)

   widgets = ['VarTable: ', Percentage(), ' ', Bar(marker=RotatingMarker()), ' ']
   pbar = ProgressBar(widgets=widgets, maxval=len(nodeMap)).start()
   count = 0
   batchList = []
   for k in nodeMap:
      mut = Mutation()
      mut.column = columnName
      mut.value = str(nodeMap[k].componentNr)
      batch = BatchMutation()
      batch.row = str(k)
      batch.mutations = [mut]
      batchList.append(batch)

      count = count + 1

      if count % 1000 == 0:
         hb.mutateRows(tableName, batchList)
         pbar.update(count)
         batchList = []
   
   pbar.finish()



def SaveMapsToHbase(formMap, nodeMap):
   print "Saving maps to Hbase."

   # Make socket
   transport = TSocket.TSocket('ph0.local', 9090)
 
   # Buffering is critical. Raw sockets are very slow
   transport = TTransport.TBufferedTransport(transport)
 
   # Wrap in a protocol
   protocol = TBinaryProtocol.TBinaryProtocol(transport)

   hb = Hbase.Client(protocol)
 
   transport.open()

   HbaseWriteFormulas(hb, formMap)
   HbaseWriteVars(hb, nodeMap)
   

   transport.close()

def TestHbase():
   print "Testing Hbase"

   # Make socket
   transport = TSocket.TSocket('ph0', 9090)
 
   # Buffering is critical. Raw sockets are very slow
   transport = TTransport.TBufferedTransport(transport)
 
   # Wrap in a protocol
   protocol = TBinaryProtocol.TBinaryProtocol(transport)

   client = Hbase.Client(protocol)
 
   transport.open()

   try:
      desc = ColumnDescriptor(name='body')
      client.createTable('formulas', [desc])
      print client.getTableNames()
   except AlreadyExists, tx:
      print "Thrift exception"
      print '%s' % (tx.message)

   transport.close()

TestHbase()
