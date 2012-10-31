/* getdelim.c --- Implementation of replacement getdelim function.
   Copyright (C) 1994, 1996, 1997, 1998, 2001, 2003, 2005 Free
   Software Foundation, Inc.

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2, or (at
   your option) any later version.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
   02110-1301, USA.  */

/* Ported from glibc by Simon Josefsson. */
/* Adapted by Marco Sperini */


#include <stdio.h>
#include <limits.h>
#include <sys/types.h>
#include <stdlib.h>
#include <errno.h>

/* Read up to (and including) a delimiter from fp into *lineptr (and
   NUL-terminate it).  *lineptr is a pointer returned from malloc (or
   NULL), pointing to *n characters of space.  It is realloc'ed as
   necessary.  Returns the number of characters read (not including
   the null terminator), or -1 on error or EOF.  */
ssize_t getdelim (char **lineptr, size_t *n, int delimiter, FILE *fp) {
	ssize_t result;
	size_t i = 0;

	if (lineptr == NULL || n == NULL || fp == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (*lineptr == NULL || *n == 0) {
		char *new_lineptr;
		*n = 256;
		new_lineptr = (char *) realloc (*lineptr, *n);
		if (new_lineptr == NULL) {
			// unable to allocate memory, it is an error situation
			result = -1;
			return result;
		}
		*lineptr = new_lineptr;
	}


	for (;;) {
		int c;
		// get the next char from stream
		c = getc(fp);

		if (c == EOF) {
			result = -1;
			break;
		}

		/* Make enough space for i+1 (for final NUL) bytes.  */
		if (i+1 >= *n) {
			size_t needed = 2 * (*n) + 1;   /* Be generous. */
			char *new_lineptr = (char *) realloc (*lineptr, needed);

			if (new_lineptr == NULL) {
				result = -1;
				return result;
			}

			*lineptr = new_lineptr;
			*n = needed;
		}

		// storing the read value into the buffer
		(*lineptr)[i] = c;
		i++;

		// if the value is the delimiter, then the work is done
		if (c == delimiter)
			break;
	}

	(*lineptr)[i] = '\0';
	result = i ? i : result;

	return result;
}


/* Written by Simon Josefsson. */
ssize_t getline(char **lineptr, size_t *n, FILE *fp) {
	return getdelim(lineptr, n, '\n', fp);
}

