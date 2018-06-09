/*
 *  Copyright (C) 2014 The libbeauty Team
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
 * 29-03-2009 Updates.
 *   Copyright (C) 2009 James Courtier-Dutton James@superbug.co.uk
 * 29-12-2014 Updates.
 *   Copyright (C) 2014 James Courtier-Dutton James@superbug.co.uk
 */

#ifndef DEBUG_LLVM_H
#define DEBUG_LLVM_H

#define DEBUG_MAIN 1
#define DEBUG_INPUT_BFD 2
#define DEBUG_INPUT_DIS 3
#define DEBUG_OUTPUT 4
#define DEBUG_EXE 5
#define DEBUG_ANALYSE 6
#define DEBUG_ANALYSE_PATHS 7
#define DEBUG_ANALYSE_PHI 8
#define DEBUG_OUTPUT_LLVM 9
#define DEBUG_ANALYSE_TIP 10
#define DEBUG_INPUT_HEADER 11

#ifdef __cplusplus
extern "C" {
#endif /* !defined(__cplusplus) */

extern void dbg_print(const char* file, int line, const char* func, int module, int level, const char *format, ...) __attribute__((__format__ (printf, 6, 7)));
#define debug_print(module, level, format, ...) dbg_print(__FILE__, __LINE__, __FUNCTION__, module, level, format, ##__VA_ARGS__)

#ifdef __cplusplus
}
#endif /* !defined(__cplusplus) */

#endif /* DEBUG_LLVM_H */

