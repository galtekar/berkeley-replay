/* Tests for fcntl.
   Copyright (C) 2000 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@cygnus.com>, 2000.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

#include <stdio.h>
#include <stdlib.h>

#include <errno.h>
#include <fcntl.h>
#include <paths.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>


/* Name of the temporary files.  */
static char name[] = "/tmp/fcntl.tmp.XXXXXX";

int main (int argc, char *argv[])
{
	int fd;
	int fd2;
	int fd3;
	struct stat st;
	int val;
	int result = 0;

	/* Create the temporary file.  */
	fd = mkstemp (name);
	if (fd == -1)
	{
		printf ("cannot open temporary file: %m\n");
		return 1;
	}
	if (fstat (fd, &st) != 0)
	{
		printf ("cannot stat test file: %m\n");
		return 1;
	}
	if (! S_ISREG (st.st_mode) || st.st_size != 0)
	{
		puts ("file not created correctly");
		return 1;
	}

	/* Get the flags with fcntl().  */
	val = fcntl (fd, F_GETFL);
	if (val == -1)
	{
		printf ("fcntl(fd, F_GETFL) failed: %m\n");
		result = 1;
	}
	else if ((val & O_ACCMODE) != O_RDWR)
	{
		puts ("temporary file not opened for read and write");
		result = 1;
	}

	/* Set the flags to something else.  */
	if (fcntl (fd, F_SETFL, O_RDONLY) == -1)
	{
		printf ("fcntl(fd, F_SETFL, O_RDONLY) failed: %m\n");
		result = 1;
	}

	val = fcntl (fd, F_GETFL);
	if (val == -1)
	{
		printf ("fcntl(fd, F_GETFL) after F_SETFL failed: %m\n");
		result = 1;
	}
	else if ((val & O_ACCMODE) != O_RDWR)
	{
		puts ("temporary file access mode changed");
		result = 1;
	}

	/* Set the flags to something else.  */
	if (fcntl (fd, F_SETFL, O_APPEND) == -1)
	{
		printf ("fcntl(fd, F_SETFL, O_APPEND) failed: %m\n");
		result = 1;
	}

	val = fcntl (fd, F_GETFL);
	if (val == -1)
	{
		printf ("fcntl(fd, F_GETFL) after second F_SETFL failed: %m\n");
		result = 1;
	}
	else if ((val & O_APPEND) == 0)
	{
		puts ("O_APPEND not set");
		result = 1;
	}

	val = fcntl (fd, F_GETFD);
	if (val == -1)
	{
		printf ("fcntl(fd, F_GETFD) failed: %m\n");
		result = 1;
	}
	else if (fcntl (fd, F_SETFD, val | FD_CLOEXEC) == -1)
	{
		printf ("fcntl(fd, F_SETFD, FD_CLOEXEC) failed: %m\n");
		result = 1;
	}
	else
	{
		val = fcntl (fd, F_GETFD);
		if (val == -1)
		{
			printf ("fcntl(fd, F_GETFD) after F_SETFD failed: %m\n");
			result = 1;
		}
		else if ((val & FD_CLOEXEC) == 0)
		{
			puts ("FD_CLOEXEC not set");
			result = 1;
		}
	}

	/* Get a number of a free descriptor.  If /dev/null is not available
	   don't continue testing.  */
	fd2 = open (_PATH_DEVNULL, O_RDWR);
	if (fd2 == -1)
		return result;
	close (fd2);

	fd3 = fcntl (fd, F_DUPFD, fd2 + 1);
	if (fd3 == -1)
	{
		printf ("fcntl(fd, F_DUPFD, %d) failed: %m\n", fd2 + 1);
		result = 1;
	}
	else if (fd3 <= fd2)
	{
		printf ("F_DUPFD returned %d which is not larger than %d\n", fd3, fd2);
		result = 1;
	}

	if (fd3 != -1)
	{
		val = fcntl (fd3, F_GETFD);
		if (val == -1)
		{
			printf ("fcntl(fd3, F_GETFD) after F_DUPFD failed: %m\n");
			result = 1;
		}
		else if ((val & FD_CLOEXEC) != 0)
		{
			puts ("FD_CLOEXEC still set");
			result = 1;
		}

		close (fd3);
	}

	return result;
}
