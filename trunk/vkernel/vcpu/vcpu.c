/*
 * Copyright (C) 2004-2010 Regents of the University of California.
 * All rights reserved.
 *
 * Author: Gautam Altekar
 */
#include "vkernel/public.h"
#include "private.h"

#include <msp/msp.h>

/* 
 * We must record the results of CPUID so that we can replay
 * the same results during BT-mode execution.
 * Unfortunately, the CPUID results depends on the processor
 * on which the instruction is issued. Namely, CPUID returns
 * the APIC ID of the processor in EBX[31:24] when CPUID op=0x1.
 * And because each VCPU may be mapped to a different physical 
 * processor, we record CPUID results for each VCPU.
 *
 * XXX: We still don't know how to replay results in DE-mode
 * execution on another machine. It's hard since CPUID doesn't
 * trap (in CPL 0 nor 3).
 *
 * Record the CPUID results in the config file and not the log,
 * since we'll need to get to it when resuming from a checkpoint.
 *
 * XXX: CPUID, depending on leaf param, may return non-determnistic
 * results.
 *
 */

/* From Intel CPUID docs... */

#define DEF_LEAF_ARG() \
   const uint leafArg[NUM_LEAFS] = \
   {  0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0xa, \
      0x80000000, 0x80000001, 0x8000002, 0x80000003, \
      0x80000004, 0x80000005, 0x8000006, 0x80000007, \
      0x80000008 \
   };

SHAREDAREA struct VCPU vcpuArray[MAX_NR_VCPU] = { { 0 } };

uint NR_CPU = 0, NR_VCPU = MAX_NR_VCPU;

// XXX: vcpuMode should really be moved into struct Session
#if 0
/* XXX: Direct execution is disabled until we fix BUG 42. */
int vcpuMode = VCPU_MODE_DE_ENABLED;
#else
int vcpuMode = 0;
#endif

#define DRIVER_PATH ("/dev/" MSP_DEVICE_NAME)


#if DEBUG
static void
VCPUShowCPUIDLeafs(struct VCPU *vcpu)
{
   int i;
   DEF_LEAF_ARG();

   DEBUG_MSG(5, "Cpuid results:\n");

   for (i = 0; i < NUM_LEAFS; i++) {
      uint *p = vcpu->cpuidMatrix[i];
      uint *eax = &p[0], *ebx = &p[1], *ecx = &p[2], *edx = &p[3];
      QUIET_DEBUG_MSG(5, "LEAF: 0x%8.8x\n", leafArg[i]);
      QUIET_DEBUG_MSG(5, 
            "  EAX: 0x%8.8x  EBX: 0x%8.8x  ECX: 0x%8.8x  EDX: 0x%8.8x\n",
            *eax, *ebx, *ecx, *edx);
   }
}
#endif

static void
VCPUSaveRestoreCPUIDInfo(struct VCPU *vcpu, int isSave)
{
   int fd, res;
   char filename[128];

   snprintf(filename, sizeof(filename), "%s/vcpu-cpuid.%d",
         session.dir, vcpu->id);

   fd = open(filename, isSave ? (O_RDWR | O_CREAT) : O_RDONLY, 
         S_IRUSR);
   if (fd < 0) {
      FATAL("Can't open %s: %s\n", filename, strerror(SYSERR_ERRNO(fd)));
   }

   if (isSave) {
      res = write(fd, vcpu->cpuidMatrix, sizeof(vcpu->cpuidMatrix));
   } else {
      res = read(fd, vcpu->cpuidMatrix, sizeof(vcpu->cpuidMatrix));
   }
   ASSERT(res == sizeof(vcpu->cpuidMatrix));

   DEBUG_ONLY(VCPUShowCPUIDLeafs(vcpu);)

   close(fd);
}

static void
VCPUDoCPUID(struct VCPU *vcpu)
{
   int i, err;

   if (!VCPU_IsReplaying()) {
      DEF_LEAF_ARG();
      /* Must be scheduled on CPU assigned to VCPU in order to get
       * the CPUID results for that CPU. Hence we ask the kernel to
       * momentarily migrate the current task (the init task) 
       * to the corresponding CPU. */
      err = CpuOps_Migrate(0, vcpu->phys_id);
      if (err) {
         FATAL("%d is not a valid CPU id -- valid range is [0, %d]\n",
               vcpu->phys_id, NR_CPU-1);
      }

      for (i = 0; i < NUM_LEAFS; i++) {
         uint *p = vcpu->cpuidMatrix[i];
         uint *eax = &p[0], *ebx = &p[1], *ecx = &p[2], *edx = &p[3];

         X86_cpuid(leafArg[i], eax, ebx, ecx, edx);
      }

      VCPUSaveRestoreCPUIDInfo(vcpu, 1);
   } else {
      VCPUSaveRestoreCPUIDInfo(vcpu, 0);
   }
}

void
VCPU_Fork(struct Task *tsk)
{
   int err;

   /* Make @tsk run on the CPU assigned to its VCPU. 
    * This ensures CPUID determinism. */
   err = CpuOps_Migrate(tsk->realPid, tsk->vcpu->phys_id);
   ASSERT(!err);
}

static void
safe_fcntl(int fd, int cmd, int arg)
{
   int err;

   ASSERT(fd >= 0);

   err = fcntl(fd, cmd, arg);
   if (err < 0) {
      FATAL("fcntl error (%d), cmd=0x%x arg=0x%x\n", err, cmd, arg);
   }
}

static void
config_msp_driver(int fd)
{
   int err;
   struct msp_config_struct cfg;

   ASSERT(fd >= 0);

   safe_fcntl(fd, F_SETFL, O_ASYNC | O_NONBLOCK);
   safe_fcntl(fd, F_SETOWN, gettid());
   safe_fcntl(fd, F_SETSIG, SIG_RESERVED_TRAP);

   cfg.signo = SIG_RESERVED_TRAP;
   cfg.vkernel_start = __IMAGE_START;
   cfg.vkernel_len = __IMAGE_END - __IMAGE_START;

   err = SysOps_ioctl(fd, MSP_IOCTL_SETUP, &cfg);
   ASSERT_UNIMPLEMENTED(!err);
}

static void
connect_to_msp_driver()
{
   int fd, err = 0;

   /* Register with the MSP, hence letting it know we want notification of
    * sharing. */
   fd = SysOps_Open(DRIVER_PATH, O_RDONLY | O_NONBLOCK, 0);
   if (fd < 0) {
      FATAL("Memory Sharing Protocol (MSP) driver not detected "
            "(cannot open %s)\n", DRIVER_PATH);
   }

   config_msp_driver(fd);

   err = SysOps_ioctl(fd, MSP_IOCTL_START, 0);
   if (err != 0) {
      FATAL("cannot start memory sharing: err=%d\n", err);
   }

   current->msp_fd = fd;
}

void
VCPU_SelfInit()
{
   if (NR_VCPU > 1) {
      connect_to_msp_driver();
   }
}

void
VCPU_SelfExit()
{
   ASSERT(current->msp_fd >= 0);

   SysOps_Close(current->msp_fd);
   current->msp_fd = -1;
}

static int
detect_msp_driver()
{
   int fd, found;
   fd = SysOps_Open(DRIVER_PATH, O_RDONLY, 0);

   /* XXX: query the version just to be sure we have the right driver. */

   found = fd >= 0 ? 1 : 0;

   SysOps_Close(fd);

   return found;
}

static int
VCPU_Init()
{
   int i, err;

   NR_CPU = CpuOps_GetNumCpus();
   DEBUG_MSG(5, "NR_CPU=%d MAX_NR_VCPU=%d\n", NR_CPU, MAX_NR_VCPU);
   ASSERT(NR_CPU > 0);
   ASSERT(MAX_NR_VCPU > 0);
   ASSERT(NR_VCPU > 0 && NR_VCPU <= MAX_NR_VCPU);

   /* How many VCPUs can we use? */
   if (NR_VCPU > 1 && !detect_msp_driver()) {
      /* Without the MSP, we have no idea about the ordering/contents of
       * accesses; hence we cannot support multiprocessor operations. */
      LOG("Memory Sharing Protocol (MSP) driver not detected "
          "(cannot open %s).\n", DRIVER_PATH);
      LOG("Falling back to 1 VCPU.\n");
      NR_VCPU = 1;
   }

   /* Init the VCPUs. */
   for (i = 0; i < NR_VCPU; i++) {
      struct VCPU *vcpu = &vcpuArray[i];
      struct RunQueue *rq = &vcpu->runq;
      struct BlockedQueue *bq = &vcpu->blockq;

      vcpu->id = i;
      vcpu->isActive = 0;

      rq->count = 0;
      List_Init(&rq->list);

      bq->count = 0;
      List_Init(&bq->list);

      ORDERED_LOCK_INIT(&vcpu->queueLock, SCHEDQUEUE_IDSTR);

      RepSynch_LockInit(&vcpu->cpuLock, VCPU_IDSTR);

      /* Default policy: assign modulo NUM_CPUS, but config
       * file may change it, so process the config options
       * before dealing with CPUID info (as that's cpu dependent). */
      vcpu->phys_id = vcpu->id % NR_CPU;

      VCPUDoCPUID(vcpu);

      vcpu->msg_idx = 0;
      MiscOps_GenerateUUID(&vcpu->uuid);

      vcpu->vclock = vcpu->last_clock = env.start_vclock;
      vcpu->wall_clock = env.start_vclock;
      ASSERT_UNIMPLEMENTED_MSG(vcpu->vclock > 0, 
            "BUG or something's wrong with the system time.\n");
   }

   /* Migrate the init task (ie., @current) to its assigned CPU. */
   err = CpuOps_Migrate(0, curr_vcpu->phys_id);

   Log_Init();

   /* First VCPU always starts locked. */
   /* XXX: Do this statically? */
   VCPU_Lock(&vcpuArray[0]);
   VCPU_Activate(&vcpuArray[0]);

   return 0;
}

CORE_INITCALL(VCPU_Init);
