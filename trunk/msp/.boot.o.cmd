cmd_drivers/msp/boot.o := gcc -Wp,-MD,drivers/msp/.boot.o.d  -nostdinc -isystem /usr/lib/gcc/i486-linux-gnu/4.1.3/include -Iinclude  -I/scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include -include include/linux/autoconf.h -D__KERNEL__ -Wall -Wundef -Wstrict-prototypes -Wno-trigraphs -fno-strict-aliasing -fno-common -Werror-implicit-function-declaration -Os -m32 -msoft-float -mregparm=3 -freg-struct-return -mpreferred-stack-boundary=2 -march=i686 -mtune=generic -Wa,-mtune=generic32 -ffreestanding -DCONFIG_AS_CFI=1 -DCONFIG_AS_CFI_SIGNAL_FRAME=1 -pipe -Wno-sign-compare -fno-asynchronous-unwind-tables -mno-sse -mno-mmx -mno-sse2 -mno-3dnow -Iarch/x86/include/asm/mach-default -fno-stack-protector -fno-omit-frame-pointer -fno-optimize-sibling-calls -g -Wdeclaration-after-statement -Wno-pointer-sign -fwrapv  -D"KBUILD_STR(s)=\#s" -D"KBUILD_BASENAME=KBUILD_STR(boot)"  -D"KBUILD_MODNAME=KBUILD_STR(msp)"  -c -o drivers/msp/.tmp_boot.o drivers/msp/boot.c

deps_drivers/msp/boot.o := \
  drivers/msp/boot.c \
  include/linux/module.h \
    $(wildcard include/config/modules.h) \
    $(wildcard include/config/modversions.h) \
    $(wildcard include/config/unused/symbols.h) \
    $(wildcard include/config/generic/bug.h) \
    $(wildcard include/config/kallsyms.h) \
    $(wildcard include/config/markers.h) \
    $(wildcard include/config/tracepoints.h) \
    $(wildcard include/config/module/unload.h) \
    $(wildcard include/config/smp.h) \
    $(wildcard include/config/sysfs.h) \
  include/linux/list.h \
    $(wildcard include/config/debug/list.h) \
  include/linux/stddef.h \
  include/linux/compiler.h \
    $(wildcard include/config/trace/branch/profiling.h) \
    $(wildcard include/config/profile/all/branches.h) \
    $(wildcard include/config/enable/must/check.h) \
    $(wildcard include/config/enable/warn/deprecated.h) \
  include/linux/compiler-gcc.h \
    $(wildcard include/config/arch/supports/optimized/inlining.h) \
    $(wildcard include/config/optimize/inlining.h) \
  include/linux/compiler-gcc4.h \
  include/linux/poison.h \
  include/linux/prefetch.h \
  include/linux/types.h \
    $(wildcard include/config/uid16.h) \
    $(wildcard include/config/lbd.h) \
    $(wildcard include/config/phys/addr/t/64bit.h) \
    $(wildcard include/config/64bit.h) \
  include/linux/posix_types.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/posix_types.h \
    $(wildcard include/config/x86/32.h) \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/posix_types_32.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/types.h \
    $(wildcard include/config/x86/64.h) \
    $(wildcard include/config/highmem64g.h) \
  include/asm-generic/int-ll64.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/processor.h \
    $(wildcard include/config/x86/vsmp.h) \
    $(wildcard include/config/x86/ds.h) \
    $(wildcard include/config/x86/ptrace/bts.h) \
    $(wildcard include/config/paravirt.h) \
    $(wildcard include/config/x86/debugctlmsr.h) \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/processor-flags.h \
    $(wildcard include/config/vm86.h) \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/vm86.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/ptrace.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/ptrace-abi.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/segment.h \
  include/linux/init.h \
    $(wildcard include/config/hotplug.h) \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/math_emu.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/sigcontext.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/current.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/percpu.h \
  include/asm-generic/percpu.h \
    $(wildcard include/config/debug/preempt.h) \
    $(wildcard include/config/have/setup/per/cpu/area.h) \
  include/linux/threads.h \
    $(wildcard include/config/nr/cpus.h) \
    $(wildcard include/config/base/small.h) \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/cpufeature.h \
    $(wildcard include/config/x86/invlpg.h) \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/required-features.h \
    $(wildcard include/config/x86/minimum/cpu/family.h) \
    $(wildcard include/config/math/emulation.h) \
    $(wildcard include/config/x86/pae.h) \
    $(wildcard include/config/x86/cmpxchg64.h) \
    $(wildcard include/config/x86/cmov.h) \
    $(wildcard include/config/x86/use/3dnow.h) \
    $(wildcard include/config/x86/p6/nop.h) \
  include/linux/bitops.h \
    $(wildcard include/config/generic/find/first/bit.h) \
    $(wildcard include/config/generic/find/last/bit.h) \
    $(wildcard include/config/generic/find/next/bit.h) \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/bitops.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/alternative.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/asm.h \
  include/asm-generic/bitops/sched.h \
  include/asm-generic/bitops/hweight.h \
  include/asm-generic/bitops/fls64.h \
  include/asm-generic/bitops/ext2-non-atomic.h \
  include/asm-generic/bitops/le.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/byteorder.h \
  include/linux/byteorder/little_endian.h \
  include/linux/swab.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/swab.h \
    $(wildcard include/config/x86/bswap.h) \
  include/linux/byteorder/generic.h \
  include/asm-generic/bitops/minix.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/system.h \
    $(wildcard include/config/ia32/emulation.h) \
    $(wildcard include/config/x86/ppro/fence.h) \
    $(wildcard include/config/x86/oostore.h) \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/cmpxchg.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/cmpxchg_32.h \
    $(wildcard include/config/x86/cmpxchg.h) \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/nops.h \
    $(wildcard include/config/mk7.h) \
  include/linux/kernel.h \
    $(wildcard include/config/preempt/voluntary.h) \
    $(wildcard include/config/debug/spinlock/sleep.h) \
    $(wildcard include/config/prove/locking.h) \
    $(wildcard include/config/printk.h) \
    $(wildcard include/config/dynamic/printk/debug.h) \
    $(wildcard include/config/numa.h) \
    $(wildcard include/config/ftrace/mcount/record.h) \
  /usr/lib/gcc/i486-linux-gnu/4.1.3/include/stdarg.h \
  include/linux/linkage.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/linkage.h \
    $(wildcard include/config/x86/alignment/16.h) \
  include/linux/log2.h \
    $(wildcard include/config/arch/has/ilog2/u32.h) \
    $(wildcard include/config/arch/has/ilog2/u64.h) \
  include/linux/typecheck.h \
  include/linux/ratelimit.h \
  include/linux/param.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/param.h \
    $(wildcard include/config/hz.h) \
  include/linux/dynamic_printk.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/bug.h \
    $(wildcard include/config/bug.h) \
    $(wildcard include/config/debug/bugverbose.h) \
  include/asm-generic/bug.h \
    $(wildcard include/config/generic/bug/relative/pointers.h) \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/div64.h \
  include/linux/irqflags.h \
    $(wildcard include/config/trace/irqflags.h) \
    $(wildcard include/config/irqsoff/tracer.h) \
    $(wildcard include/config/preempt/tracer.h) \
    $(wildcard include/config/trace/irqflags/support.h) \
    $(wildcard include/config/x86.h) \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/irqflags.h \
    $(wildcard include/config/debug/lock/alloc.h) \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/paravirt.h \
    $(wildcard include/config/x86/local/apic.h) \
    $(wildcard include/config/highpte.h) \
    $(wildcard include/config/paravirt/debug.h) \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/page.h \
  include/linux/const.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/page_32.h \
    $(wildcard include/config/highmem4g.h) \
    $(wildcard include/config/page/offset.h) \
    $(wildcard include/config/4kstacks.h) \
    $(wildcard include/config/hugetlb/page.h) \
    $(wildcard include/config/debug/virtual.h) \
    $(wildcard include/config/flatmem.h) \
    $(wildcard include/config/x86/3dnow.h) \
  include/linux/string.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/string.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/string_32.h \
  include/asm-generic/pgtable-nopmd.h \
  include/asm-generic/pgtable-nopud.h \
  include/asm-generic/memory_model.h \
    $(wildcard include/config/discontigmem.h) \
    $(wildcard include/config/sparsemem/vmemmap.h) \
    $(wildcard include/config/sparsemem.h) \
  include/asm-generic/page.h \
  include/linux/cpumask.h \
    $(wildcard include/config/disable/obsolete/cpumask/functions.h) \
    $(wildcard include/config/hotplug/cpu.h) \
    $(wildcard include/config/cpumask/offstack.h) \
    $(wildcard include/config/debug/per/cpu/maps.h) \
  include/linux/bitmap.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/kmap_types.h \
    $(wildcard include/config/debug/highmem.h) \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/desc_defs.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/msr.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/msr-index.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/errno.h \
  include/asm-generic/errno.h \
  include/asm-generic/errno-base.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/ds.h \
  include/linux/err.h \
  include/linux/personality.h \
  include/linux/cache.h \
    $(wildcard include/config/arch/has/cache/line/size.h) \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/cache.h \
    $(wildcard include/config/x86/l1/cache/shift.h) \
  include/linux/stat.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/stat.h \
  include/linux/time.h \
  include/linux/seqlock.h \
  include/linux/spinlock.h \
    $(wildcard include/config/debug/spinlock.h) \
    $(wildcard include/config/generic/lockbreak.h) \
    $(wildcard include/config/preempt.h) \
  include/linux/preempt.h \
    $(wildcard include/config/preempt/notifiers.h) \
  include/linux/thread_info.h \
    $(wildcard include/config/compat.h) \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/thread_info.h \
    $(wildcard include/config/debug/stack/usage.h) \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/ftrace.h \
    $(wildcard include/config/function/tracer.h) \
    $(wildcard include/config/dynamic/ftrace.h) \
    $(wildcard include/config/function/graph/tracer.h) \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/atomic.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/atomic_32.h \
    $(wildcard include/config/m386.h) \
  include/asm-generic/atomic.h \
  include/linux/stringify.h \
  include/linux/bottom_half.h \
  include/linux/spinlock_types.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/spinlock_types.h \
  include/linux/lockdep.h \
    $(wildcard include/config/lockdep.h) \
    $(wildcard include/config/lock/stat.h) \
    $(wildcard include/config/generic/hardirqs.h) \
  include/linux/debug_locks.h \
    $(wildcard include/config/debug/locking/api/selftests.h) \
  include/linux/stacktrace.h \
    $(wildcard include/config/stacktrace.h) \
    $(wildcard include/config/user/stacktrace/support.h) \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/spinlock.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/rwlock.h \
  include/linux/spinlock_api_smp.h \
  include/linux/math64.h \
  include/linux/kmod.h \
  include/linux/gfp.h \
    $(wildcard include/config/zone/dma.h) \
    $(wildcard include/config/zone/dma32.h) \
    $(wildcard include/config/highmem.h) \
  include/linux/mmzone.h \
    $(wildcard include/config/force/max/zoneorder.h) \
    $(wildcard include/config/unevictable/lru.h) \
    $(wildcard include/config/memory/hotplug.h) \
    $(wildcard include/config/arch/populates/node/map.h) \
    $(wildcard include/config/flat/node/mem/map.h) \
    $(wildcard include/config/cgroup/mem/res/ctlr.h) \
    $(wildcard include/config/have/memory/present.h) \
    $(wildcard include/config/need/node/memmap/size.h) \
    $(wildcard include/config/need/multiple/nodes.h) \
    $(wildcard include/config/have/arch/early/pfn/to/nid.h) \
    $(wildcard include/config/sparsemem/extreme.h) \
    $(wildcard include/config/nodes/span/other/nodes.h) \
    $(wildcard include/config/holes/in/zone.h) \
  include/linux/wait.h \
  include/linux/numa.h \
    $(wildcard include/config/nodes/shift.h) \
  include/linux/nodemask.h \
  include/linux/pageblock-flags.h \
    $(wildcard include/config/hugetlb/page/size/variable.h) \
  include/linux/bounds.h \
  include/linux/memory_hotplug.h \
    $(wildcard include/config/have/arch/nodedata/extension.h) \
    $(wildcard include/config/memory/hotremove.h) \
  include/linux/notifier.h \
  include/linux/errno.h \
  include/linux/mutex.h \
    $(wildcard include/config/debug/mutexes.h) \
  include/linux/mutex-debug.h \
  include/linux/rwsem.h \
    $(wildcard include/config/rwsem/generic/spinlock.h) \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/rwsem.h \
  include/linux/srcu.h \
  include/linux/topology.h \
    $(wildcard include/config/sched/smt.h) \
    $(wildcard include/config/sched/mc.h) \
  include/linux/smp.h \
    $(wildcard include/config/use/generic/smp/helpers.h) \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/smp.h \
    $(wildcard include/config/x86/io/apic.h) \
    $(wildcard include/config/x86/32/smp.h) \
    $(wildcard include/config/x86/64/smp.h) \
    $(wildcard include/config/x86/has/boot/cpu/id.h) \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/mpspec.h \
    $(wildcard include/config/x86/numaq.h) \
    $(wildcard include/config/mca.h) \
    $(wildcard include/config/eisa.h) \
    $(wildcard include/config/x86/mpparse.h) \
    $(wildcard include/config/acpi.h) \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/mpspec_def.h \
  arch/x86/include/asm/mach-default/mach_mpspec.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/apic.h \
  include/linux/pm.h \
    $(wildcard include/config/pm/sleep.h) \
  include/linux/delay.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/delay.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/fixmap.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/fixmap_32.h \
    $(wildcard include/config/x86/visws/apic.h) \
    $(wildcard include/config/x86/f00f/bug.h) \
    $(wildcard include/config/x86/cyclone/timer.h) \
    $(wildcard include/config/pci/mmconfig.h) \
    $(wildcard include/config/provide/ohci1394/dma/init.h) \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/acpi.h \
    $(wildcard include/config/acpi/numa.h) \
  include/acpi/pdc_intel.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/numa.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/numa_32.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/mmu.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/apicdef.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/io_apic.h \
    $(wildcard include/config/pci.h) \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/irq_vectors.h \
    $(wildcard include/config/x86/voyager.h) \
    $(wildcard include/config/sparse/irq.h) \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/pda.h \
    $(wildcard include/config/cc/stackprotector.h) \
  arch/x86/include/asm/mach-default/mach_apicdef.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/topology.h \
    $(wildcard include/config/x86/ht.h) \
    $(wildcard include/config/x86/64/acpi/numa.h) \
  include/asm-generic/topology.h \
  include/linux/elf.h \
  include/linux/elf-em.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/elf.h \
    $(wildcard include/config/compat/vdso.h) \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/user.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/user_32.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/auxvec.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/vdso.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/desc.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/ldt.h \
  include/linux/kobject.h \
  include/linux/sysfs.h \
  include/linux/kref.h \
  include/linux/moduleparam.h \
    $(wildcard include/config/alpha.h) \
    $(wildcard include/config/ia64.h) \
    $(wildcard include/config/ppc64.h) \
  include/linux/marker.h \
  include/linux/tracepoint.h \
  include/linux/rcupdate.h \
    $(wildcard include/config/classic/rcu.h) \
    $(wildcard include/config/tree/rcu.h) \
    $(wildcard include/config/preempt/rcu.h) \
  include/linux/percpu.h \
  include/linux/slab.h \
    $(wildcard include/config/slab/debug.h) \
    $(wildcard include/config/debug/objects.h) \
    $(wildcard include/config/slub.h) \
    $(wildcard include/config/slob.h) \
    $(wildcard include/config/debug/slab.h) \
  include/linux/slab_def.h \
  include/linux/kmalloc_sizes.h \
  include/linux/completion.h \
  include/linux/rcuclassic.h \
    $(wildcard include/config/rcu/cpu/stall/detector.h) \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/local.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/module.h \
    $(wildcard include/config/m486.h) \
    $(wildcard include/config/m586.h) \
    $(wildcard include/config/m586tsc.h) \
    $(wildcard include/config/m586mmx.h) \
    $(wildcard include/config/mcore2.h) \
    $(wildcard include/config/m686.h) \
    $(wildcard include/config/mpentiumii.h) \
    $(wildcard include/config/mpentiumiii.h) \
    $(wildcard include/config/mpentiumm.h) \
    $(wildcard include/config/mpentium4.h) \
    $(wildcard include/config/mk6.h) \
    $(wildcard include/config/mk8.h) \
    $(wildcard include/config/x86/elan.h) \
    $(wildcard include/config/mcrusoe.h) \
    $(wildcard include/config/mefficeon.h) \
    $(wildcard include/config/mwinchipc6.h) \
    $(wildcard include/config/mwinchip3d.h) \
    $(wildcard include/config/mcyrixiii.h) \
    $(wildcard include/config/mviac3/2.h) \
    $(wildcard include/config/mviac7.h) \
    $(wildcard include/config/mgeodegx1.h) \
    $(wildcard include/config/mgeode/lx.h) \
  include/linux/io.h \
    $(wildcard include/config/mmu.h) \
    $(wildcard include/config/has/ioport.h) \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/io.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/io_32.h \
  include/asm-generic/iomap.h \
  include/linux/vmalloc.h \
  include/linux/mm.h \
    $(wildcard include/config/sysctl.h) \
    $(wildcard include/config/stack/growsup.h) \
    $(wildcard include/config/security.h) \
    $(wildcard include/config/swap.h) \
    $(wildcard include/config/shmem.h) \
    $(wildcard include/config/proc/fs.h) \
    $(wildcard include/config/debug/pagealloc.h) \
    $(wildcard include/config/hibernation.h) \
  include/linux/mmdebug.h \
    $(wildcard include/config/debug/vm.h) \
  include/linux/rbtree.h \
  include/linux/prio_tree.h \
  include/linux/mm_types.h \
    $(wildcard include/config/split/ptlock/cpus.h) \
    $(wildcard include/config/mm/owner.h) \
    $(wildcard include/config/mmu/notifier.h) \
  include/linux/auxvec.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/pgtable.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/pgtable_32.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/pgtable-2level-defs.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/pgtable-2level.h \
  include/asm-generic/pgtable.h \
  include/linux/page-flags.h \
    $(wildcard include/config/pageflags/extended.h) \
    $(wildcard include/config/ia64/uncached/allocator.h) \
    $(wildcard include/config/s390.h) \
  include/linux/vmstat.h \
    $(wildcard include/config/vm/event/counters.h) \
  include/linux/cpu.h \
    $(wildcard include/config/pm/sleep/smp.h) \
  include/linux/sysdev.h \
  include/linux/node.h \
  include/linux/freezer.h \
    $(wildcard include/config/freezer.h) \
    $(wildcard include/config/cgroup/freezer.h) \
  include/linux/sched.h \
    $(wildcard include/config/sched/debug.h) \
    $(wildcard include/config/no/hz.h) \
    $(wildcard include/config/detect/softlockup.h) \
    $(wildcard include/config/core/dump/default/elf/headers.h) \
    $(wildcard include/config/bsd/process/acct.h) \
    $(wildcard include/config/taskstats.h) \
    $(wildcard include/config/audit.h) \
    $(wildcard include/config/inotify/user.h) \
    $(wildcard include/config/epoll.h) \
    $(wildcard include/config/posix/mqueue.h) \
    $(wildcard include/config/keys.h) \
    $(wildcard include/config/user/sched.h) \
    $(wildcard include/config/schedstats.h) \
    $(wildcard include/config/task/delay/acct.h) \
    $(wildcard include/config/fair/group/sched.h) \
    $(wildcard include/config/rt/group/sched.h) \
    $(wildcard include/config/blk/dev/io/trace.h) \
    $(wildcard include/config/sysvipc.h) \
    $(wildcard include/config/auditsyscall.h) \
    $(wildcard include/config/rt/mutexes.h) \
    $(wildcard include/config/task/xacct.h) \
    $(wildcard include/config/cpusets.h) \
    $(wildcard include/config/cgroups.h) \
    $(wildcard include/config/futex.h) \
    $(wildcard include/config/fault/injection.h) \
    $(wildcard include/config/latencytop.h) \
    $(wildcard include/config/tracing.h) \
    $(wildcard include/config/have/unstable/sched/clock.h) \
    $(wildcard include/config/preempt/bkl.h) \
    $(wildcard include/config/group/sched.h) \
  include/linux/capability.h \
    $(wildcard include/config/security/file/capabilities.h) \
  include/linux/timex.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/timex.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/tsc.h \
    $(wildcard include/config/x86/tsc.h) \
  include/linux/jiffies.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/cputime.h \
  include/asm-generic/cputime.h \
  include/linux/sem.h \
  include/linux/ipc.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/ipcbuf.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/sembuf.h \
  include/linux/signal.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/signal.h \
  include/asm-generic/signal.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/siginfo.h \
  include/asm-generic/siginfo.h \
  include/linux/fs_struct.h \
  include/linux/path.h \
  include/linux/pid.h \
  include/linux/proportions.h \
  include/linux/percpu_counter.h \
  include/linux/seccomp.h \
    $(wildcard include/config/seccomp.h) \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/seccomp.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/seccomp_32.h \
  include/linux/unistd.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/unistd.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/unistd_32.h \
  include/linux/rtmutex.h \
    $(wildcard include/config/debug/rt/mutexes.h) \
  include/linux/plist.h \
    $(wildcard include/config/debug/pi/list.h) \
  include/linux/resource.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/resource.h \
  include/asm-generic/resource.h \
  include/linux/timer.h \
    $(wildcard include/config/timer/stats.h) \
    $(wildcard include/config/debug/objects/timers.h) \
  include/linux/ktime.h \
    $(wildcard include/config/ktime/scalar.h) \
  include/linux/debugobjects.h \
    $(wildcard include/config/debug/objects/free.h) \
  include/linux/hrtimer.h \
    $(wildcard include/config/high/res/timers.h) \
  include/linux/task_io_accounting.h \
    $(wildcard include/config/task/io/accounting.h) \
  include/linux/latencytop.h \
  include/linux/cred.h \
  include/linux/key.h \
  include/linux/sysctl.h \
  include/linux/aio.h \
    $(wildcard include/config/aio.h) \
  include/linux/workqueue.h \
  include/linux/aio_abi.h \
  include/linux/uio.h \
  include/linux/highmem.h \
  include/linux/fs.h \
    $(wildcard include/config/dnotify.h) \
    $(wildcard include/config/quota.h) \
    $(wildcard include/config/inotify.h) \
    $(wildcard include/config/debug/writecount.h) \
    $(wildcard include/config/file/locking.h) \
    $(wildcard include/config/block.h) \
    $(wildcard include/config/fs/xip.h) \
    $(wildcard include/config/migration.h) \
  include/linux/limits.h \
  include/linux/ioctl.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/ioctl.h \
  include/asm-generic/ioctl.h \
  include/linux/kdev_t.h \
  include/linux/dcache.h \
  include/linux/rculist.h \
  include/linux/radix-tree.h \
  include/linux/semaphore.h \
  include/linux/fiemap.h \
  include/linux/quota.h \
  include/linux/dqblk_xfs.h \
  include/linux/dqblk_v1.h \
  include/linux/dqblk_v2.h \
  include/linux/dqblk_qtree.h \
  include/linux/nfs_fs_i.h \
  include/linux/nfs.h \
  include/linux/sunrpc/msg_prot.h \
  include/linux/fcntl.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/fcntl.h \
  include/asm-generic/fcntl.h \
  include/linux/uaccess.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/uaccess.h \
    $(wildcard include/config/x86/wp/works/ok.h) \
    $(wildcard include/config/x86/intel/usercopy.h) \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/uaccess_32.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/cacheflush.h \
    $(wildcard include/config/debug/rodata.h) \
    $(wildcard include/config/debug/rodata/test.h) \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/highmem.h \
  include/linux/interrupt.h \
    $(wildcard include/config/generic/irq/probe.h) \
  include/linux/irqreturn.h \
  include/linux/irqnr.h \
  include/linux/hardirq.h \
    $(wildcard include/config/virt/cpu/accounting.h) \
  include/linux/smp_lock.h \
    $(wildcard include/config/lock/kernel.h) \
  include/linux/ftrace_irq.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/hardirq.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/hardirq_32.h \
  include/linux/irq.h \
    $(wildcard include/config/irq/per/cpu.h) \
    $(wildcard include/config/irq/release/method.h) \
    $(wildcard include/config/intr/remap.h) \
    $(wildcard include/config/generic/pending/irq.h) \
    $(wildcard include/config/numa/migrate/irq/desc.h) \
    $(wildcard include/config/generic/hardirqs/no//do/irq.h) \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/irq.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/irq_regs.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/irq_regs_32.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/hw_irq.h \
    $(wildcard include/config/x86/smp.h) \
  include/linux/profile.h \
    $(wildcard include/config/profiling.h) \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/sections.h \
  include/asm-generic/sections.h \
  include/linux/irq_cpustat.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/tlbflush.h \
  /scratch/galtekar/src/logreplay/linux/linux-2.6.29.4-replay/arch/x86/include/asm/poll.h \
  include/asm-generic/poll.h \
  include/asm/asm-offsets.h \
  drivers/msp/msp_private.h \
  include/linux/hash.h \
  include/linux/msp.h \
    $(wildcard include/config/msp.h) \

drivers/msp/boot.o: $(deps_drivers/msp/boot.o)

$(deps_drivers/msp/boot.o):
