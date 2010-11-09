#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
 .name = KBUILD_MODNAME,
 .init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
 .exit = cleanup_module,
#endif
 .arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x9b3d5efd, "struct_module" },
	{ 0x5d70a0e8, "rcu_lock_map" },
	{ 0x647064df, "find_task_by_vpid" },
	{ 0x54f4aea9, "per_cpu__current_task" },
	{ 0x9b388444, "get_zeroed_page" },
	{ 0x752067c5, "sysdev_unregister" },
	{ 0x43067eeb, "vperfctr_stub" },
	{ 0xfeb7ae05, "mem_map" },
	{ 0xd0d8621b, "strlen" },
	{ 0x40583138, "kill_anon_super" },
	{ 0x3d830887, "disable_lapic_nmi_watchdog" },
	{ 0x154f1f61, "send_sig" },
	{ 0x7272c3c8, "cpu_online_mask" },
	{ 0x926a7612, "pid_vnr" },
	{ 0x74cc238d, "current_kernel_time" },
	{ 0x2855a26f, "malloc_sizes" },
	{ 0x472e1e07, "boot_cpu_data" },
	{ 0x88b70987, "get_sb_pseudo" },
	{ 0xd7dd777b, "reserve_perfctr_nmi" },
	{ 0x1a64678e, "_spin_lock" },
	{ 0x11bda074, "dput" },
	{ 0x438515c, "sysdev_class_register" },
	{ 0xb8a6cac2, "ptrace_check_attach" },
	{ 0x6729d3df, "__get_user_4" },
	{ 0xc928a1e0, "mutex_unlock" },
	{ 0xc810686b, "_spin_lock_irqsave" },
	{ 0x3c2c5af5, "sprintf" },
	{ 0x343a1a8, "__list_add" },
	{ 0xf831c8cc, "__spin_lock_init" },
	{ 0x797ab229, "lock_release" },
	{ 0x518eb764, "per_cpu__cpu_number" },
	{ 0x3b6bd16d, "misc_register" },
	{ 0x577ab7f0, "lock_acquire" },
	{ 0x4d8c750, "release_perfctr_nmi" },
	{ 0x99bfbe39, "get_unused_fd" },
	{ 0x740a1b95, "reserve_evntsel_nmi" },
	{ 0xb72397d5, "printk" },
	{ 0x7953445, "set_cpus_allowed_ptr" },
	{ 0x88bf983a, "sysdev_class_unregister" },
	{ 0xf29bccac, "_spin_unlock_irqrestore" },
	{ 0xa70fabbe, "release_evntsel_nmi" },
	{ 0x511f3e1f, "apic_ops" },
	{ 0x81e86eb7, "fput" },
	{ 0xce16a25e, "_spin_unlock" },
	{ 0x4497f74c, "vm_insert_page" },
	{ 0x3385c8cb, "per_cpu__this_cpu_off" },
	{ 0x44f548b6, "module_put" },
	{ 0x1e01ce78, "sysdev_register" },
	{ 0x36ef7048, "__perfctr_cpu_mask_interrupts" },
	{ 0xe7d32407, "nmi_active" },
	{ 0xcc3ea76b, "kmem_cache_alloc" },
	{ 0x56f494e0, "smp_call_function" },
	{ 0xb2fd5ceb, "__put_user_4" },
	{ 0x183871e2, "mntput_no_expire" },
	{ 0x284c89e8, "d_alloc" },
	{ 0xda928914, "nmi_watchdog" },
	{ 0xfb6af58d, "recalc_sigpending" },
	{ 0x49d9e320, "perfctr_cpu_set_ihandler" },
	{ 0x64938809, "pv_cpu_ops" },
	{ 0x3f4547a7, "put_unused_fd" },
	{ 0xa3948454, "perfctr_cpu_khz" },
	{ 0x1176e07f, "__per_cpu_offset" },
	{ 0xe52947e7, "__phys_addr" },
	{ 0x13570326, "register_filesystem" },
	{ 0x4302d0eb, "free_pages" },
	{ 0x2d0b25b7, "mutex_lock_nested" },
	{ 0x2beb418e, "might_fault" },
	{ 0x22267554, "iput" },
	{ 0x37a0cba, "kfree" },
	{ 0x2e60bace, "memcpy" },
	{ 0x988cac9c, "fd_install" },
	{ 0x89f2fbd7, "send_sig_info" },
	{ 0x6579c34f, "__perfctr_cpu_unmask_interrupts" },
	{ 0xe2e6130, "__put_task_struct" },
	{ 0xc49238e5, "unregister_filesystem" },
	{ 0xdbb8c489, "per_cpu__cpu_info" },
	{ 0x4cad5a34, "kern_mount_data" },
	{ 0x2fb523b1, "new_inode" },
	{ 0xdad5638d, "mmu_cr4_features" },
	{ 0xc33f6f4c, "on_each_cpu" },
	{ 0x408d398f, "get_empty_filp" },
	{ 0xf2a644fb, "copy_from_user" },
	{ 0x5f715be1, "misc_deregister" },
	{ 0x83bba092, "d_instantiate" },
	{ 0xdc8d292a, "enable_lapic_nmi_watchdog" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";

