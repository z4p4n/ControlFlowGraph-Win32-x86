#ifndef GRAPH_H
#define GRAPH_H

#define CHILD_BUFSIZ 1000

#include "../pe/pelib/pelib.h"
#include "../pe/pelib_extend/pelib_extend.h"

/* Basic node structure for Directed Graph */
typedef struct _node {

	int id; /* position in .text section data */
	int left, right;
	int *extra;

} t_node, *p_node;

/* Chained list of nodes */
typedef struct node_list {


	t_node           node;
	struct node_list *next;

} t_node_list, *p_node_list;

/* Return new allocated list of node properly initialized */
p_node_list new_node_list (int father, int child);

/* Add child to node */
void add_child_to_node (p_node node, int child);

/* Free structure list_node */
void free_node_list (p_node_list list);


/* Write directed graphe in file for GraphViz Format */
void write_directed_graph_from_list (PEExtend *PE, FILE *fd, p_node_list list);

/* Add node to list                      * 
 * ------------------------------------- *
 * If child < 0, don't add child to node */
p_node add_node_to_list (p_node_list list, int father, int child);

/* Search node, return node if present NULL else */
p_node search_node (p_node_list list, int id);

/* Transfer node1 to node2, node2 take children of node1 and node2 *
 * become child of node1                                           */
void transfer_branch (p_node_list list, int id1, int id2);

#endif
