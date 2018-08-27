
#ifndef EXE_H
#define EXE_H


extern struct memory_s *search_store(
        struct memory_s *memory, uint64_t index, int size);
extern struct memory_s *add_new_store(
	struct memory_s *memory, uint64_t index, int size);
extern int print_store(struct memory_s *memory);

extern uint64_t inst_log;      /* Pointer to the current free instruction log entry. */

#endif /* EXE_H */
