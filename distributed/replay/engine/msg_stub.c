/*
 * Copyright (C) 2010 Regents of the University of California
 * All rights reserved.
 *
 * Author: Gautam Altekar
 */

#include <python2.6/Python.h>

#include <include/vk.h>
#include <libcommon/public.h>

#if 0
static int
parse_msg_tag(PyObject *args)
{
   PyObject *first_arg = NULL;
   int msg_kind = 0;

   if (args && PyTuple_Size(args) > 0) {
      first_arg = PyTuple_GetItem(args, 0);
      if (first_arg/* && PyInt_Check(first_arg)*/) {
         msg_kind = PyInt_AsLong(first_arg);

         //printf("msg_kind=%d\n", msg_kind);
      } 
   } 

   return msg_kind;
}

static PyObject *
py_pack(PyObject *self, PyObject *args)
{
   struct VkReqMsg msg;
   int msg_kind;

   if (!(msg_kind = parse_msg_tag(args))) {
      return NULL;
   }

   memset(&msg, 0, sizeof(msg));
   msg.tag = msg_kind; 

   switch (msg_kind) {
   case VK_REQ_CONT: 
      {
         uint64_t next_vclock;
         if (!PyArg_ParseTuple(args, "iL", &msg_kind, &next_vclock)) {
            return NULL;
         }

         msg.Body.Cont.next_vclock = next_vclock;
      }
      break;
   case VK_REQ_STATUS:
      break;
   default:
      assert(0);
      return NULL;
      break;
   }

   char string[sizeof(msg)+1];
   memset(string, 0, sizeof(string));
   memcpy(string, &msg, sizeof(msg));

   return Py_BuildValue("s#", string, sizeof(string));
}

static PyObject *
py_unpack(PyObject *self, PyObject *args)
{
   struct VkReplyMsg msg;
   const char *str;

   if (!PyArg_ParseTuple(args, "s", &str)) {
      return NULL;
   }

   assert(strlen(str) == sizeof(msg));
   memcpy(&msg, str, strlen(str));

   switch (msg.tag) {
   case VkReplyMsg_Event:
      return Py_BuildValue("i", msg.Body.Event.tag);
      break;
   case VkReplyMsg_Status:
      return Py_BuildValue("");
   default:
      return NULL;
      break;
   }
}
#endif

static PyMethodDef StubMethods[] = {
#if 0
   { "pack", py_pack, METH_VARARGS, "Packs a message." },
   { "unpack", py_unpack, METH_VARARGS, "Unpacks a message." },
#endif

   { NULL, NULL, 0, NULL }
};

static void
PyDefInt(PyObject *m, const char *name, int val)
{
   PyObject *tmp, *d;
   d = PyModule_GetDict(m);

   tmp = PyInt_FromLong(val);
   PyDict_SetItemString(d, name, tmp);
   Py_DECREF(tmp);
}

PyMODINIT_FUNC
initmsg_stub(void)
{
   PyObject *m;

   m = Py_InitModule("msg_stub", StubMethods);

   PyDefInt(m, "MSG_REQ_STATUS", VK_REQ_STATUS);
   PyDefInt(m, "MSG_REQ_CONT", VK_REQ_CONT);
   PyDefInt(m, "MSG_REQ_READMEM", VK_REQ_READMEM);
   PyDefInt(m, "MSG_REQ_READREG", VK_REQ_READREG);
   PyDefInt(m, "MSG_REQ_TASKLIST", VK_REQ_TASKLIST);
   PyDefInt(m, "MSG_REQ_TASKINFO", VK_REQ_TASKINFO);
   PyDefInt(m, "MSG_REQ_SET_BRKPT", VK_REQ_SET_BRKPT);
   PyDefInt(m, "MSG_REQ_DEL_BRKPT", VK_REQ_DEL_BRKPT);
   PyDefInt(m, "MSG_REQ_GET_MSG_TAINT", VK_REQ_GET_MSG_TAINT);
   PyDefInt(m, "MSG_REQ_SET_MSG_TAINT", VK_REQ_SET_MSG_TAINT);
   PyDefInt(m, "MSG_REQ_GET_FILENAME_BY_FD", VK_REQ_GET_FILENAME_BY_FD);
   PyDefInt(m, "MSG_REQ_SET_PLANE_BY_FD", VK_REQ_SET_PLANE_BY_FD);
   PyDefInt(m, "MSG_REQ_SET_FILE_PLANE", VK_REQ_SET_FILE_PLANE);
   PyDefInt(m, "MSG_REQ_GET_FILE_NAME", VK_REQ_GET_FILE_NAME);
   PyDefInt(m, "MSG_REQ_GET_MSG_INFO", VK_REQ_GET_MSG_INFO);
   PyDefInt(m, "MSG_REQ_GET_FILE_INFO", VK_REQ_GET_FILE_INFO);

   PyDefInt(m, "EVENT_STOP", VK_EVENT_STOP);
   PyDefInt(m, "EVENT_SHUTDOWN", VK_EVENT_SHUTDOWN);
   PyDefInt(m, "EVENT_BRKPT_HIT", VK_EVENT_BRKPT_HIT);
   PyDefInt(m, "EVENT_TASK_START", VK_EVENT_TASK_START);
   PyDefInt(m, "EVENT_TASK_EXIT", VK_EVENT_TASK_EXIT);
   PyDefInt(m, "EVENT_SYSCALL", VK_EVENT_SYSCALL);
   PyDefInt(m, "EVENT_FILE_WRITE", VK_EVENT_FILE_WRITE);
   PyDefInt(m, "EVENT_FILE_DEQUEUE", VK_EVENT_FILE_DEQUEUE);
   PyDefInt(m, "EVENT_FILE_PEEK", VK_EVENT_FILE_PEEK);
   PyDefInt(m, "EVENT_FILE_OPEN", VK_EVENT_FILE_OPEN);
   PyDefInt(m, "EVENT_FILE_CLOSE", VK_EVENT_FILE_CLOSE);
   PyDefInt(m, "EVENT_FILE_PUT", VK_EVENT_FILE_PUT);

   PyDefInt(m, "BRKPT_INSN_ENTRY", VK_BRKPT_INSN_ENTRY);
   PyDefInt(m, "BRKPT_SYSCALL", VK_BRKPT_SYSCALL);
   PyDefInt(m, "BRKPT_FILE_WRITE", VK_BRKPT_FILE_WRITE);
   PyDefInt(m, "BRKPT_FILE_PEEK", VK_BRKPT_FILE_PEEK);
   PyDefInt(m, "BRKPT_FILE_DEQUEUE", VK_BRKPT_FILE_DEQUEUE);
   PyDefInt(m, "BRKPT_FILE_OPEN", VK_BRKPT_FILE_OPEN);
   PyDefInt(m, "BRKPT_FILE_CLOSE", VK_BRKPT_FILE_CLOSE);
   PyDefInt(m, "BRKPT_FILE_PUT", VK_BRKPT_FILE_PUT);

   PyDefInt(m, "INODE_SOCKET", InodeMajor_Sock);
   PyDefInt(m, "INODE_PIPE", InodeMajor_Pipe);
   PyDefInt(m, "INODE_FILE", InodeMajor_File);
   PyDefInt(m, "INODE_DEVICE", InodeMajor_Device);
   PyDefInt(m, "SOCK_FAMILY_UNIX", AF_UNIX);
   PyDefInt(m, "SOCK_FAMILY_INET", AF_INET);
   PyDefInt(m, "SOCK_PROTO_TCP", SOCK_STREAM);
   PyDefInt(m, "SOCK_PROTO_UDP", SOCK_DGRAM);
}
