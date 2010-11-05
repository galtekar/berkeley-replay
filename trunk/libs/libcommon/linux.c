#include "public.h"

#include <errno.h>

/* acceptable for old filesystems */
static inline int old_valid_dev(dev_t dev)
{
	return MAJOR(dev) < 256 && MINOR(dev) < 256;
}

static inline u16 old_encode_dev(dev_t dev)
{
	return (MAJOR(dev) << 8) | MINOR(dev);
}

static inline dev_t old_decode_dev(u16 val)
{
	return MKDEV((val >> 8) & 255, val & 255);
}

static inline int new_valid_dev(dev_t dev)
{
	return 1;
}

static inline u32 new_encode_dev(dev_t dev)
{
	unsigned major = MAJOR(dev);
	unsigned minor = MINOR(dev);
	return (minor & 0xff) | (major << 8) | ((minor & ~0xff) << 12);
}

static inline dev_t new_decode_dev(u32 dev)
{
	unsigned major = (dev & 0xfff00) >> 8;
	unsigned minor = (dev & 0xff) | ((dev >> 12) & 0xfff00);
	return MKDEV(major, minor);
}

#ifdef CONFIG_UID16
#error "XXX"
#else
#define __convert_uid(size, uid) (uid)
#define __convert_gid(size, gid) (gid)
#endif /* !CONFIG_UID16 */

/* uid/gid input should be always 32bit uid_t */
#define SET_UID(var, uid) do { (var) = __convert_uid(sizeof(var), (uid)); } while (0)
#define SET_GID(var, gid) do { (var) = __convert_gid(sizeof(var), (gid)); } while (0)

int 
Linux_cp_new_stat(struct kstat64 *kstat, struct stat __user *statbuf)
{
	struct stat tmp;

#if BITS_PER_LONG == 32
	if (!old_valid_dev(kstat->st_dev) || !old_valid_dev(kstat->st_rdev))
		return -EOVERFLOW;
#else
	if (!new_valid_dev(kstat->st_dev) || !new_valid_dev(kstat->st_rdev))
		return -EOVERFLOW;
#endif

	memset(&tmp, 0, sizeof(tmp));
#if BITS_PER_LONG == 32
	tmp.st_dev = old_encode_dev(kstat->st_dev);
#else
	tmp.st_dev = new_encode_dev(kstat->st_dev);
#endif
	tmp.st_ino = kstat->st_ino;
	if (sizeof(tmp.st_ino) < sizeof(kstat->st_ino) && tmp.st_ino != kstat->st_ino)
		return -EOVERFLOW;
	tmp.st_mode = kstat->st_mode;
	tmp.st_nlink = kstat->st_nlink;
	if (tmp.st_nlink != kstat->st_nlink)
		return -EOVERFLOW;
	SET_UID(tmp.st_uid, kstat->st_uid);
	SET_GID(tmp.st_gid, kstat->st_gid);
#if BITS_PER_LONG == 32
	tmp.st_rdev = old_encode_dev(kstat->st_rdev);
#else
	tmp.st_rdev = new_encode_dev(kstat->st_rdev);
#endif
#if BITS_PER_LONG == 32
	if (kstat->st_size > MAX_NON_LFS)
		return -EOVERFLOW;
#endif	
	tmp.st_size = kstat->st_size;
	tmp.st_atime = kstat->st_atime;
	tmp.st_mtime = kstat->st_mtime;
	tmp.st_ctime = kstat->st_ctime;
	tmp.st_blocks = kstat->st_blocks;
	tmp.st_blksize = kstat->st_blksize;
	return copy_to_user(statbuf,&tmp,sizeof(tmp)) ? -EFAULT : 0;
}
