#ifndef CKPT_H
#define CKPT_H

enum {
	CKPT_MAXNAME=1024,
	CKPT_NAME=(1<<1),
	CKPT_CONTINUE=(1<<3),
};

enum {
	IGNORE_SHAREDMEM=(0x1),
};

struct ckptconfig {
	/* For users */
	char name[CKPT_MAXNAME];
	unsigned int continues;
	int flags;
};

/* Must be called before using any of libckpt's functionality. */
void ckpt_init();	

/* Take a checkpoint and dump it in file CKPT_FILENAME. */
int ckpt_ckpt(char *ckpt_filename, int options);

/* Restart from the checkpoint give by file CKPT_FILENAME. */
void ckpt_restart(char *ckpt_filename);

/* Outputs info about the checkpoint file CKPT_FILENAME. */
void ckpt_info(char *ckpt_filename);

/* Sets configuration options. See struct ckptconfig for details. */
void ckpt_config(struct ckptconfig *cfg, struct ckptconfig *old);

/* Tell libckpt exclude this memory range in the checkpoint. */
void ckpt_mask_region(const void* addr, size_t size);

/* Tells libckpt to include this memory range in the checkpoint. */
void ckpt_unmask_region(const void* addr, size_t size);

typedef void (*fn_t)(void *);
void ckpt_on_preckpt(fn_t f, void *arg);
void ckpt_on_postckpt(fn_t f, void *arg);
void ckpt_on_restart(fn_t f, void *arg);

#endif
