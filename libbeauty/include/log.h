/*
 *  Copyright (C) 2018 The libbeauty Team
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

#ifndef OUTPUT_LOG_H
#define OUTPUT_LOG_H

#ifdef __cplusplus
extern "C" int log_open(struct self_s *self, char *filename);
extern "C" int log_close(struct self_s *self, int handle);
extern "C" int log_new_entry(struct self_s *self, char *message_id, int level, char *source_file_name,
			uint64_t line, char *source_function, char *message);
extern "C" int log_add_uint32(struct self_s *self, int handle, char *name, uint32_t value);
extern "C" int log_add_uint64(struct self_s *self, int handle, char *name, uint64_t value);
extern "C" int log_add_string(struct self_s *self, int handle, char *name, char *value);
extern "C" int log_send(struct self_s *self, int handle);
extern "C" int log_exit(struct self_s *self);
#else
extern int log_open(struct self_s *self, char *filename);
extern int log_close(struct self_s *self, int handle);
extern int log_new_entry(struct self_s *self, char *message_id, int level, char *source_file_name,
			uint64_t line, char *source_function, char *message);
extern int log_add_uint32(struct self_s *self, int handle, char *name, uint32_t value);
extern int log_add_uint64(struct self_s *self, int handle, char *name, uint64_t value);
extern int log_add_string(struct self_s *self, int handle, char *name, char *value);
extern int log_send(struct self_s *self, int handle);
extern int log_exit(struct self_s *self);

#endif

#endif
