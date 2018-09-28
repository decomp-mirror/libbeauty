/*
 *  Copyright (C) 2004-2018 The libbeauty Team
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Library General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 *
 * 11-9-2004 Initial work.
 *   Copyright (C) 2004 James Courtier-Dutton James@superbug.co.uk
 * 10-11-2007 Updates.
 *   Copyright (C) 2007 James Courtier-Dutton James@superbug.co.uk
 * 27-09-2018 Updates.
 *   Copyright (C) 2018 James Courtier-Dutton James@superbug.co.uk
 */

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>
#include <rev.h>

static int skip_digits(const char *s)
{
	int i = 0;

	while (isdigit(s[i])) {
		i++;
	}
	return i;
}

int format_count_params(int length, uint8_t *format_string)
{
	int tmp;
	int count = 0;
	int n;
	for (n = 0; n < length; n++) {
		if (format_string[n] != '%') {
			continue;
		}

	repeat:
		n++;
		switch (format_string[n]) {
		case '-':
			goto repeat;
		case '+':
			goto repeat;
		case ' ':
			goto repeat;
		case '#':
			goto repeat;
		case '0':
			goto repeat;
		}

		/* get field width */
		if (isdigit(format_string[n])) {
			tmp = skip_digits(&(format_string[n]));
			n = n + tmp;
		} else if (format_string[n] == '*') {
			n++;
		}

		if (format_string[n] == '.') {
			n++;
			if (isdigit(format_string[n])) {
				tmp = skip_digits(&(format_string[n]));
				n = n + tmp;
			} else if (format_string[n] == '*') {
				n++;
			}
		}

		if (format_string[n] == 'h' || format_string[n] == 'l' || format_string[n] == 'L') {
			n++;
		}

		switch (format_string[n]) {
		case 'c':
			count++;
			break;

		case 's':
			count++;
			break;

		case 'p':
			count++;
			break;

		case 'n':
			count++;
			break;

		case '%':
			break;

		case 'o':
			count++;
			break;

		case 'x':
		case 'X':
			count++;
			break;

		case 'd':
		case 'i':
		case 'u':
			count++;
			break;

		default:
			break;
		}
	}
	return count;
}

