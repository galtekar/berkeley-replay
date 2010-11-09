#include "sys.h"
#include "ckpt.h"
#include "ckptimpl.h"

static struct ckptconfig ckptconfig;

static void
cmdname(char *buf, unsigned long max)
{
	int fd, rv;

	fd = open("/proc/self/cmdline", O_RDONLY);
	if(0 > fd) {
		libckpt_fatal("cannot open /proc/self/cmdline");
	}
	rv = read(fd, buf, max-1);
	if(0 >= rv) {
		libckpt_fatal("cannot read /proc/self/cmdline");
	}
	close(fd);
}

static void
defaults(struct ckptconfig *cfg)
{
	char *p;
	int m;

	cmdname(cfg->name, sizeof(cfg->name));
	p = strrchr(cfg->name, '/');
	if(p != NULL){
		p++;
		m = strlen(p);
		memmove(cfg->name, p, m);
	}else
		m = strlen(cfg->name);
	snprintf(&cfg->name[m], sizeof(cfg->name)-m, ".ckpt");

	cfg->continues = 0;
}

static void
readenv(struct ckptconfig *cfg)
{
	char *p;

	p = getenv("CKPT_NAME");
	if(p){
		if(0 == strcmp(p, ""))
			libckpt_fatal("Empty CKPT_NAME\n");
		if(strlen(p) >= CKPT_MAXNAME)
			libckpt_fatal("CKPT_NAME too long\n");
		strncpy(cfg->name, p, CKPT_MAXNAME);
	}

	p = getenv("CKPT_CONTINUE");
	if(p){
		if(0 == strcmp(p, ""))
			libckpt_fatal("Empty CKPT_CONTINUE\n");
		if(0 == strcmp(p, "0"))
			cfg->continues = 0;
		else
			cfg->continues = 1;
	}
}

void
ckpt_initconfig()
{
	defaults(&ckptconfig);
	readenv(&ckptconfig);
}

void
ckpt_config(struct ckptconfig *cfg, struct ckptconfig *old)
{
	if(old)
		memcpy(old, &ckpt_config, sizeof(struct ckptconfig));

	if(cfg == NULL)
		return;

	if(cfg->flags&CKPT_NAME)
		memcpy(&ckptconfig.name, cfg->name, sizeof(ckptconfig.name));

	if(cfg->flags&CKPT_CONTINUE)
		ckptconfig.continues = cfg->continues;

}

int
ckpt_shouldcontinue()
{
	return ckptconfig.continues;
}

char *
ckpt_ckptname()
{
	return ckptconfig.name;
}

void
ckpt_rconfig(struct ckptconfig *cfg)
{
	ckpt_config(cfg, NULL);
}
