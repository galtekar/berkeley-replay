#pragma once

#include <vk-client-call.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#define VK_PROC_DIR "/tmp/" RELEASE_NAME





struct SymVar {
   int byte;
   int is_origin;
   unsigned long long name;
   unsigned long long bb_exec_count;
};

struct StateByte {
   int is_symbolic;
   union {
      struct SymVar var;
      unsigned char val;
   } un;
};

/* -------------------- Controlelr Requests ---------------------- */

typedef enum { 
   /* System context */
   VK_REQ_STATUS = 0xc001,
   VK_REQ_CONT,
   VK_REQ_READMEM,
   VK_REQ_READREG,
   VK_REQ_TASKLIST,
   VK_REQ_TASKINFO,
   VK_REQ_SET_BRKPT,
   VK_REQ_DEL_BRKPT,
   VK_REQ_GET_FILENAME_BY_FD,
   VK_REQ_SET_PLANE_BY_FD,

   /* Io context */
   VK_REQ_GET_MSG_TAINT,
   VK_REQ_SET_MSG_TAINT,
   VK_REQ_GET_FILE_NAME,
   VK_REQ_SET_FILE_PLANE,
   VK_REQ_GET_MSG_INFO,
   VK_REQ_GET_FILE_INFO,

   VK_REQ_LAST_DUMMY, /* For debugging checks. */
} VkReqTag;

typedef enum {
   VK_BRKPT_SYSCALL = 0xc001,
   VK_BRKPT_FILE_WRITE,
   VK_BRKPT_FILE_PEEK,
   VK_BRKPT_FILE_DEQUEUE,
   VK_BRKPT_FILE_OPEN,
   VK_BRKPT_FILE_CLOSE,
   VK_BRKPT_FILE_PUT,
   VK_BRKPT_INSN_ENTRY,
} VkBrkptTag;

typedef enum {
   InodeMajor_File,
   InodeMajor_Pipe,
   InodeMajor_Sock,
   InodeMajor_Epoll,
   InodeMajor_Shm,
   InodeMajor_Device,
   InodeMajor_Event,
} InodeMajor;

typedef enum {
   VK_EVENT_STOP = 0xc001,
   VK_EVENT_SHUTDOWN,
   VK_EVENT_BRKPT_HIT,
   VK_EVENT_TASK_START,
   VK_EVENT_TASK_EXIT,
   VK_EVENT_SYSCALL,
   VK_EVENT_FILE_WRITE,
   VK_EVENT_FILE_DEQUEUE,
   VK_EVENT_FILE_PEEK,
   VK_EVENT_FILE_OPEN,
   VK_EVENT_FILE_CLOSE,
   VK_EVENT_FILE_PUT,
} VkEventTag;


typedef
   enum {
      VK_USERREQ__MARK_MEMORY = VG_USERREQ_TOOL_BASE('M', 'G'),
      VK_USERREQ__MARK_FILE_BY_INO,
      VK_USERREQ__MARK_FILE_BY_FD,
      VK_USERREQ__MARK_ASSERT_MEMORY,

      VK_USERREQ__CG_ADD_PTR_REGION = VG_USERREQ_TOOL_BASE('M','C'),
      VK_USERREQ__CG_RM_PTR_REGION,
      VK_USERREQ__CG_ASSERT_SYMBOLIC,
      VK_USERREQ__CG_ASSERT_CONCRETE,
   } Vk_ClientRequest;

/* ----- Generic client requests ----- */

typedef enum {
    VK_PLANE_UNKNOWN = 0xc001,
    VK_PLANE_CONTROL,
    VK_PLANE_DATA,
} VkPlaneTag;


#define VK_MARK_MEMORY(_qzz_addr,_qzz_len,_qzz_kind)            \
   (__extension__({unsigned long _qzz_res;                       \
    VALGRIND_DO_CLIENT_REQUEST(_qzz_res, 0 /* default return */, \
                            VK_USERREQ__MARK_MEMORY,        \
                            _qzz_addr, _qzz_len, _qzz_kind, 0, 0);       \
    _qzz_res;                                                    \
   }))

#define VK_MARK_FILE_BY_INO(_qzz_kind,_qzz_dev,_qzz_ino)            \
   (__extension__({unsigned long _qzz_res;                       \
    VALGRIND_DO_CLIENT_REQUEST(_qzz_res, 0 /* default return */, \
                            VK_USERREQ__MARK_FILE_BY_INO,        \
                            _qzz_kind, _qzz_dev, _qzz_ino, 0, 0);       \
    _qzz_res;                                                    \
   }))

#define VK_MARK_FILE_BY_NAME(name,kind) { \
   struct stat buf; \
   int err = stat(name,&buf); \
   if (!err) { \
      VK_MARK_FILE_BY_INO(kind,buf.st_dev,buf.st_ino); \
   } \
}

#define VK_MARK_FILE_BY_FD(_qzz_fd,_qzz_kind) \
   (__extension__({unsigned long _qzz_res;                       \
    VALGRIND_DO_CLIENT_REQUEST(_qzz_res, 0 /* default return */, \
                            VK_USERREQ__MARK_FILE_BY_FD,        \
                            _qzz_fd, _qzz_kind, 0, 0, 0);       \
    _qzz_res;                                                    \
   }))

#define VK_MARK_ASSERT_MEMORY(_qzz_addr,_qzz_len,_qzz_kind)            \
   (__extension__({unsigned long _qzz_res;                       \
    VALGRIND_DO_CLIENT_REQUEST(_qzz_res, 0 /* default return */, \
                            VK_USERREQ__MARK_ASSERT_MEMORY,        \
                            _qzz_addr, _qzz_len, _qzz_kind, 0, 0);       \
    _qzz_res;                                                    \
   }))


/* ----- DcGen-specific client requests ----- */
   
#if 0
#define VK_MAKE_MEM_ARRAY(_qzz_addr,_qzz_len)          \
   (__extension__({unsigned long _qzz_res;                       \
    VALGRIND_DO_CLIENT_REQUEST(_qzz_res, 0 /* default return */, \
                            VK_USERREQ__MAKE_MEM_ARRAY,      \
                            _qzz_addr, _qzz_len, 0, 0, 0);       \
    _qzz_res;                                                    \
   }))

#define VK_RM_MEM_ARRAY(_qzz_id)            \
   (__extension__({unsigned long _qzz_res;                       \
    VALGRIND_DO_CLIENT_REQUEST(_qzz_res, 0 /* default return */, \
                            VK_USERREQ__RM_MEM_ARRAY,        \
                            _qzz_id, 0, 0, 0, 0);       \
    _qzz_res;                                                    \
   }))
#endif

#define VK_CG_ASSERT_CONCRETE(_qzz_addr,_qzz_len)            \
   (__extension__({unsigned long _qzz_res;                       \
    VALGRIND_DO_CLIENT_REQUEST(_qzz_res, 0 /* default return */, \
                            VK_USERREQ__CG_ASSERT_CONCRETE,        \
                            _qzz_addr, _qzz_len, 0, 0, 0);       \
    _qzz_res;                                                    \
   }))

#define VK_CG_ASSERT_SYMBOLIC(_qzz_addr,_qzz_len)            \
   (__extension__({unsigned long _qzz_res;                       \
    VALGRIND_DO_CLIENT_REQUEST(_qzz_res, 0 /* default return */, \
                            VK_USERREQ__CG_ASSERT_SYMBOLIC,        \
                            _qzz_addr, _qzz_len, 0, 0, 0);       \
    _qzz_res;                                                    \
   }))
