#ifndef _LINUX_SHADOW_H
#define _LINUX_SHADOW_H

#ifdef CONFIG_MSP

#ifdef __KERNEL__
extern int
msp_on_page_fault(unsigned long vaddr, unsigned long error_code);

extern int __init 
msp_boot_init(void);
#endif /* __KERNEL__ */

#endif /* CONFIG_MSP */

struct msp_config_struct {
   int signo;
   unsigned long vkernel_start, vkernel_len; 
};

typedef enum { MSP_EV_UPGRADE = 0xc001beef, MSP_EV_DOWNGRADE } msp_event_kind_t;
typedef struct msp_event
{
   msp_event_kind_t kind;
   unsigned long vaddr;
   unsigned long pfn;
   unsigned long long timestamp;
   int cpu_id;
} msp_event_t;


/* These are helpful for userlevel access. */
#define MSP_DEVICE_NAME   "msp"
#define MSP_DEFAULT_SIG   SIGUSR1

/* XXX: arbitrarily chosen; choose more carefully */
#define _MSP_IOCTL           0xE0 
#define MSP_IOCTL_SETUP      _IOR(_MSP_IOCTL, 0, struct msp_config_struct)
#define MSP_IOCTL_START      _IO(_MSP_IOCTL, 1)
#define MSP_IOCTL_SMP_ID     _IO(_MSP_IOCTL, 2)

#endif /* _LINUX_SHADOW_H */
