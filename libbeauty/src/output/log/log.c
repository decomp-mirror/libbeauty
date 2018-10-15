/*
 *  Copyright (C) 2018  The revenge Team
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
 * 11-9-2018 Initial work.
 *   Copyright (C) 2018 James Courtier-Dutton James@superbug.co.uk
 */

/* Handle logging. This outputs in a JSON format */

#define __STDC_LIMIT_MACROS
#define __STDC_CONSTANT_MACROS

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/time.h>
#include <fcntl.h>
#include <global_struct.h>

#include <log.h>

int log_open(struct self_s *self, char *filename)
{
	int fd;
	int tmp;
	self->log.logfile = -1;
	fd = open(filename, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		return 1;
	}
	self->log.logfile = fd;
	if (!self->log.part) {
		self->log.part = calloc(20, sizeof(struct type_value_s));
		if (!self->log.part) {
			return 1;
		}
		self->log.size_allocated = 20;
	}
	/* Clear the last message */
	self->log.size = 0;
	write(self->log.logfile, "[", 1);
	return 0;
}

int log_close(struct self_s *self, int handle)
{
	write(self->log.logfile, "]", 1);
	close(handle);
	self->log.size = 0;
	free(self->log.part);
	self->log.size_allocated = 0;
	self->log.part = NULL;
	return 0;
}

int log_new_entry(struct self_s *self, char *message_id, int level, char *source_file_name,
		uint64_t line, char *source_function, char *message)
{
	int tmp;
	struct timeval tv;
	struct timezone *tz = NULL;
	tmp = gettimeofday(&tv, tz);
	printf("message_id = %s\n", message_id);

	strncpy(&(self->log.part[0].name), "timestamp", 10);
	snprintf(&(self->log.part[0].value), 254, "%lu.%lu", tv.tv_sec, tv.tv_usec);
	strncpy(&(self->log.part[1].name), "message_id", 11);
	strncpy(&(self->log.part[1].value), message_id, 254);
	strncpy(&(self->log.part[2].name), "level", 6);
	snprintf(&(self->log.part[2].value), 254, "%d", level);
	strncpy(&(self->log.part[3].name), "source_file_name", 17);
	strncpy(&(self->log.part[3].value), source_file_name, 254);
	strncpy(&(self->log.part[4].name), "line", 5);
	snprintf(&(self->log.part[4].value), 254, "%d", line);
	strncpy(&(self->log.part[5].name), "source_function", 16);
	strncpy(&(self->log.part[5].value), source_function, 254);
	strncpy(&(self->log.part[6].name), "message", 8);
	strncpy(&(self->log.part[6].value), message, 254);
	self->log.size = 7;
	return 1;
}

int log_add_uint32(struct self_s *self, int message_handle, char *name, uint32_t value)
{
	snprintf(&(self->log.part[self->log.size].name), 254, "%s", name);
	snprintf(&(self->log.part[self->log.size].value), 254, "%u", value);
	self->log.size++;
	return 0;
}

int log_add_uint64(struct self_s *self, int message_handle, char *name, uint64_t value)
{
	snprintf(&(self->log.part[self->log.size].name), 254, "%s", name);
	snprintf(&(self->log.part[self->log.size].value), 254, "%lu", value);
	self->log.size++;
	return 0;
}

int log_add_string(struct self_s *self, int message_handle, char *name, char *value)
{
	snprintf(&(self->log.part[self->log.size].name), 254, "%s", name);
	snprintf(&(self->log.part[self->log.size].value), 254, "%s", value);
	self->log.size++;
	return 0;
}

int log_send(struct self_s *self, int message_handle)
{
	int n;
	printf("logfile %d\n", self->log.logfile);
	dprintf(self->log.logfile, "{ ");
	for (n = 0; n < self->log.size; n++) {
		if (n == 0) {
			dprintf(self->log.logfile, "\"%s\": \"%s\"", self->log.part[n].name, self->log.part[n].value);
		} else {
			dprintf(self->log.logfile, ", \"%s\": \"%s\"", self->log.part[n].name, self->log.part[n].value);
		}
	}
	dprintf(self->log.logfile, "}\n");
	/* Clear the last message */
	self->log.size = 0;
	return 0;
}


/* Flush any partial logs, and close the log file, and exit the programs. */
int log_exit(struct self_s *self)
{
	close(self->log.logfile);
	self->log.logfile = -1;
	self->log.size = 0;
	free(self->log.part);
	self->log.size_allocated = 0;
	self->log.part = NULL;
	exit(1);
}
