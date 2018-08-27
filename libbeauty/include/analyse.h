#ifndef ANALYSE_H
#define ANALYSE_H

struct relocation_s {
	int type; /* 0 = invalid, 1 = external_entry_point, 2 = data */
	uint64_t index; /* Index into the external_entry_point or data */
};

struct mid_start_s {
	uint64_t mid_start;
	uint64_t valid;
};

extern int tidy_inst_log(struct self_s *self);
extern int find_node_from_inst(struct self_s *self, struct control_flow_node_s *nodes, int nodes_size, int inst);
extern int node_mid_start_add(struct control_flow_node_s *node, struct node_mid_start_s *node_mid_start, int path, int step);
extern int path_loop_check(struct path_s *paths, int path, int step, int node, int limit);
extern int merge_path_into_loop(struct path_s *paths, struct loop_s *loop, int path);
extern int build_control_flow_loops(struct self_s *self, struct path_s *paths, int *paths_size, struct loop_s *loops, int *loop_size);
extern int build_control_flow_loops_multi_exit(struct self_s *self, struct control_flow_node_s *nodes, int nodes_size, struct loop_s *loops, int loops_size);
extern int build_control_flow_loops_node_members(struct self_s *self,
	struct control_flow_node_s *nodes, int nodes_size,
	struct loop_s *loops, int *loops_size);
extern int print_control_flow_loops(struct self_s *self, struct loop_s *loops, int *loops_size);
extern int add_path_to_node(struct control_flow_node_s *node, int path);
extern int add_looped_path_to_node(struct control_flow_node_s *node, int path);
extern int is_subset(int size_a, int *a, int size_b, int *b);
extern int build_node_dominance(struct self_s *self, struct control_flow_node_s *nodes, int nodes_size);
extern int build_node_type(struct self_s *self, struct control_flow_node_s *nodes, int nodes_size);
extern int build_node_if_tail(struct self_s *self, struct control_flow_node_s *nodes, int nodes_size);
extern int build_node_paths(struct self_s *self, struct control_flow_node_s *nodes, int nodes_size, struct path_s *paths, int *paths_size, int entry_point);
extern int build_control_flow_paths(struct self_s *self, struct control_flow_node_s *nodes, int nodes_size, struct path_s *paths, int *paths_size, int *paths_used, int node_start);
extern int print_control_flow_paths(struct self_s *self, struct path_s *paths, int *paths_size);
extern int build_control_flow_nodes(struct self_s *self, struct control_flow_node_s *nodes, int *nodes_size);
extern int build_control_flow_depth(struct self_s *self, struct control_flow_node_s *nodes, int nodes_size, struct path_s *paths, int *paths_size, int *paths_used, int node_start);
extern int print_control_flow_nodes(struct self_s *self, struct control_flow_node_s *nodes, int nodes_size);
extern int analyse_control_flow_node_links(struct self_s *self, struct control_flow_node_s *nodes, int nodes_size);
extern int analyse_multi_ret(struct self_s *self, struct path_s *paths, int *paths_size, int *multi_ret_size, int **multi_ret);
extern int analyse_merge_nodes(struct self_s *self, int function, int node_a, int node_b);
extern int get_value_from_index(struct operand_s *operand, uint64_t *index);
extern int log_to_label(int store, int indirect, uint64_t index, uint64_t size, uint64_t relocated, uint64_t value_scope, uint64_t value_id, int64_t indirect_offset_value, struct label_s *label);
extern int register_label(struct external_entry_point_s *entry_point, int inst, int operand, uint64_t value_id,
	struct inst_log_entry_s *inst_log_entry, struct label_redirect_s *label_redirect, struct label_s *labels);
extern int scan_for_labels_in_function_body(struct self_s *self, int entry_point_index);
extern int search_back_local_reg_stack(struct self_s *self, uint64_t mid_start_size, struct mid_start_s *mid_start, int reg_stack, uint64_t indirect_init_value, uint64_t indirect_offset_value, uint64_t *size, int *search_back_seen, uint64_t **inst_list);

/* In support.h */
extern int get_value_id_from_node_reg(struct self_s *self, int entry_point, int node, int reg, int *value_id);
extern int init_node_used_register_table(struct self_s *self, int entry_point);
extern int print_node_used_register_table(struct self_s *self, int entry_point);
extern int fill_node_used_register_table(struct self_s *self, int entry_point);
extern int search_back_for_join(struct control_flow_node_s *nodes, int nodes_size, int node, int *phi_node);
extern int add_phi_to_node(struct control_flow_node_s *node, int reg);
extern int path_node_to_base_path(struct self_s *self, struct path_s *paths, int paths_size, int path, int node, int *base_path, int *base_step);
extern int find_prev_path_step_node(struct self_s *self, struct path_s *paths, int paths_size, int path, int step, int node, int *prev_path, int *prev_step, int *prev_node);
extern int fill_node_phi_dst(struct self_s *self, struct control_flow_node_s *nodes, int nodes_size);
extern int find_phi_src_node_reg(struct self_s *self, struct control_flow_node_s *nodes, int nodes_size, struct path_s *paths, int paths_size, int path, int step, int node, int reg, int *src_node, int *first_prev_node);
extern int fill_node_phi_src(struct self_s *self, struct control_flow_node_s *nodes, int nodes_size);
extern int fill_phi_node_list(struct self_s *self, struct control_flow_node_s *nodes, int nodes_size);
extern int fill_phi_src_value_id(struct self_s *self, int entry_point);
extern int fill_phi_dst_size_from_src_size(struct self_s *self, int entry_point);
extern int find_reg_in_phi_list(struct self_s *self, struct control_flow_node_s *nodes, int nodes_size, int node, int reg, int *value_id);
extern int build_entry_point_node_members(struct self_s *self, struct external_entry_point_s *external_entry_point, int nodes_size);
extern int print_entry_point_node_members(struct self_s *self, struct external_entry_point_s *external_entry_point);
extern int search_back_for_register(struct self_s *self, int l, int node, int inst, int source,
	struct label_s *label, int *new_label);
extern int assign_id_label_dst(struct self_s *self, int function, int n, struct inst_log_entry_s *inst_log1, struct label_s *label);
extern int assign_labels_to_dst(struct self_s *self, int entry_point, int node);
extern int assign_labels_to_src(struct self_s *self, int entry_point, int node);
extern int check_domain(struct label_redirect_s *label_redirect);
extern int rule_add(struct self_s *self, int entry_point, int node, int inst, int phi, int operand,
	int label_index, int tipA_derived_from, int tipB_derived_from, int tip_derived_from_this, int pointer, int pointer_to_tip2, int size_bits);
extern int rule_print(struct self_s *self, int entry_point);
extern int tip_result_print(struct self_s *self, int entry_point);
extern int insert_nop_before(struct self_s *self, int inst, int *new_inst);
extern int insert_nop_after(struct self_s *self, int inst, int *new_inst);
extern int dis64_copy_operand(struct self_s *self, int inst_from, int operand_from, int inst_to, int operand_to, int size);
extern int tip_fixup1(struct self_s *self, int entry_point, int tip_index, int rule_index, int old_size, int new_size);
extern int tip_fixup_bit_width(struct self_s *self, int entry_point);
extern int tip_rules_process(struct self_s *self, int entry_point);
extern int is_pointer_reg(struct operand_s *operand);
extern int is_pointer_mem(struct label_s *labels, int value_id);
extern int build_tip2_table(struct self_s *self, int entry_point, int node);
extern int tip_process_label(struct self_s *self, int entry_point, int label_index);
extern int dis64_copy_operand(struct self_s *self, int inst_from, int operand_from, int inst_to, int operand_to, int size);
extern int tip_add_zext(struct self_s *self, int entry_point, int label_index);
extern int tip_print_label(struct self_s *self, int entry_point, int label_index);
extern int redirect_mov_reg_reg_labels(struct self_s *self, struct external_entry_point_s *external_entry_point, int node);
extern int change_add_to_gep1(struct self_s *self, struct external_entry_point_s *external_entry_point, int node);
extern int discover_pointer_types(struct self_s *self, struct external_entry_point_s *external_entry_point, int node);
extern int substitute_inst(struct self_s *self, int inst, int new_inst);
extern int build_flag_dependency_table(struct self_s *self);
extern int matcher_sbb(struct self_s *self, int inst, int *sbb_match, int *n1, int *n2, int *n3, int *flags_result_used);
extern int fix_flag_dependency_instructions(struct self_s *self);
extern int print_flag_dependency_table(struct self_s *self);
extern int create_function_node_members(struct self_s *self, struct external_entry_point_s *external_entry_point);
extern int assign_id_label_dst(struct self_s *self, int function, int inst, struct inst_log_entry_s *inst_log1, struct label_s *label);
extern int fill_reg_dependency_table(struct self_s *self, struct external_entry_point_s *external_entry_point, int n);
extern int dump_labels_table(struct self_s *self, char *buffer);
extern int call_params_to_locals(struct self_s *self, int entry_point, int node);
extern int find_function_simple_params_reg(struct self_s *self, int entry_point);
extern int fill_in_call_params(struct self_s *self, int entry_point);

#endif /* ANALYSE_H */
