/*
 *  Copyright (C) 2012  The libbeauty Team
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
 * 06-05-2012 Initial work.
 *   Copyright (C) 2012 James Courtier-Dutton James@superbug.co.uk
 */

#ifndef INPUT_H
#define INPUT_H

#ifdef __cplusplus
#include "llvm-c/Types.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/StringMap.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/iterator_range.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/Comdat.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalAlias.h"
#include "llvm/IR/GlobalIFunc.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/SymbolTableListTraits.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/CBindingWrapping.h"
#include "llvm/Support/CodeGen.h"
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <memory>
#include <string>
#include <vector>

namespace llvm {

class Error;
class FunctionType;
class GVMaterializer;
class LLVMContext;
class MemoryBuffer;
class RandomNumberGenerator;
template <class PtrType> class SmallPtrSetImpl;
class StructType;
class Module;

class LLVM_input_header
{
	public:
		int dump_mod(struct self_s *self);
		int find_types(struct self_s *self, char *filename, struct input_find_types_s *find_types);
		int lookup_external_function(struct self_s *self, const char *symbol_name, int *result);
		int external_function_get_size(struct self_s *self, int function_index, int *fields_size);
		StringRef get_function_name(struct self_s *self, int function_index);
		int external_function_get_return_type(struct self_s *self, int function_index, int *lab_pointer, int *size_bits);
		FunctionType *get_function_type(int function_index);
		int load_data_hints(struct self_s *self, char *filename);
		struct hints2_s {
			std::string function_name;
			std::vector<int> type;
		};

	private:
		LLVMContext Context;
		std::unique_ptr<Module> Mod;
		int functions_size;
		Module::const_iterator *functions;
		int hints_size;
		std::unique_ptr<int[]> *hints;
		std::vector<hints2_s> hints2;

		struct hints2_type_s {
			int index;
			std::string type;
		};
		std::vector <hints2_type_s> hints2_type = {
				{0, "null"},
				{1, "string-zero"},
				{2, "format-string-zero"}
		};

};
} // end namespace llvm
extern "C" int input_find_types(struct self_s *self, char *filename, struct input_find_types_s *find_types);
extern "C" int input_dump_mod(struct self_s *self);
extern "C" int lookup_external_function(struct self_s *self, const char *symbol_name, int *result);
extern "C" int input_external_function_get_size(struct self_s *self, int function_index, int *fields_size);
extern "C" int input_external_function_get_name(struct self_s *self, int function_index, char **function_name);
extern "C" int input_external_function_get_return_type(struct self_s *self, int function_index, int *lab_pointer, int *size_bits);
extern "C" int input_load_data_hints(struct self_s *self, char *filename);
#else
int input_find_types(struct self_s *self, char *filename, struct input_find_types_s *find_types);
int input_dump_mod(struct self_s *self);
int lookup_external_function(struct self_s *self, const char *symbol_name, int *result);
int input_external_function_get_size(struct self_s *self, int function_index, int *fields_size);
int input_external_function_get_name(struct self_s *self, int function_index, char **function_name);
int input_external_function_get_return_type(struct self_s *self, int function_index, int *lab_pointer, int *size_bits);
int input_load_data_hints(struct self_s *self, char *filename);
#endif

#endif /* INPUT_H */
