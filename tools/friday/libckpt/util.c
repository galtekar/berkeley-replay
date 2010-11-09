#include "sys.h"

int
xread(int sd, void *buf, size_t len)
{
	char *p = (char *)buf;
	size_t nrecv = 0;
	ssize_t rv;
	
	while (nrecv < len) {
		rv = read(sd, p, len - nrecv);
		if (0 > rv && errno == EINTR)
			continue;
		if (0 > rv)
			return -1;
		if (0 == rv)
			return 0;
		nrecv += rv;
		p += rv;
	}
	return nrecv;
}

int
xwrite(int sd, const void *buf, size_t len)
{
	char *p = (char *)buf;
	size_t nsent = 0;
	ssize_t rv;
	
	while (nsent < len) {
		rv = write(sd, p, len - nsent);
		if (0 > rv && (errno == EINTR || errno == EAGAIN))
			continue;
		if (0 > rv)
			return -1;
		nsent += rv;
		p += rv;
	}
	return nsent;
}

void
call_if_present(char *name, char *lib)
{
	void *h;
	void (*f)();

	printf("lib=%s\n", lib);
	h = dlopen(lib, RTLD_NOW);
	if (!h)
		return;
	f = dlsym(h, name);
	if (!f)
		return;
	f();
}

void 
libckpt_fatal(char *fmt, ...)
{
	char cmd_str[256];
	va_list args;
	va_start(args, fmt);
	printf("libckpt fatal: ");
	vfprintf(stderr, fmt, args);
	va_end(args);

	sprintf(cmd_str, "cat /proc/%d/maps\n", syscall(SYS_getpid));

	fprintf(stdout, "[Memory map for pid %d]\n", syscall(SYS_getpid));
	system(cmd_str);

	exit(1);
}

void 
libckpt_warning(char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	printf("libckpt warning: ");
	vfprintf(stderr, fmt, args);
	va_end(args);
}

char *
xstrdup(char *p)
{
	char *q;
	q = strdup(p);
	if(!q)
		libckpt_fatal("out of memory");
	return q;
}


struct sigmap_t {
	char *name;
	int num;
};

static struct sigmap_t map[] = {
	{ "0",          0         },
	{ "SIGHUP",     SIGHUP    },
	{ "SIGINT",     SIGINT    },
	{ "SIGQUIT",    SIGQUIT   },
	{ "SIGILL",     SIGILL    },
	{ "SIGTRAP",    SIGTRAP   },
	{ "SIGABRT",    SIGABRT   },
	{ "SIGIOT",     SIGIOT    },
	{ "SIGBUS",     SIGBUS    },
	{ "SIGFPE",     SIGFPE    },
	{ "SIGKILL",    SIGKILL   },
	{ "SIGUSR1",    SIGUSR1   },
	{ "SIGSEGV",    SIGSEGV   },
	{ "SIGUSR2",    SIGUSR2   },
	{ "SIGPIPE",    SIGPIPE   },
	{ "SIGALRM",    SIGALRM   },
	{ "SIGTERM",    SIGTERM   },
	{ "SIGSTKFLT",  SIGSTKFLT },
	{ "SIGCLD",     SIGCLD    },
	{ "SIGCHLD",    SIGCHLD   },
	{ "SIGCONT",    SIGCONT   },
	{ "SIGSTOP",    SIGSTOP   },
	{ "SIGTSTP",    SIGTSTP   },
	{ "SIGTTIN",    SIGTTIN   },
	{ "SIGTTOU",    SIGTTOU   },
	{ "SIGURG",     SIGURG    },
	{ "SIGXCPU",    SIGXCPU   },
	{ "SIGXFSZ",    SIGXFSZ   },
	{ "SIGVTALRM",  SIGVTALRM },
	{ "SIGPROF",    SIGPROF   },
	{ "SIGWINCH",   SIGWINCH  },
	{ "SIGPOLL",    SIGPOLL   },
	{ "SIGIO",      SIGIO     },
	{ "SIGPWR",     SIGPWR    },
	{ "SIGSYS",     SIGSYS    },
	{ NULL, 0 }
};

int
ckpt_mapsig(char *s)
{
	struct sigmap_t *p;
	p = map;
	while (p->name) {
		if (!strcmp(p->name, s))
			return p->num;
		p++;
	}
	return -1;
}
