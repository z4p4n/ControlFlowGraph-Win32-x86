#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>

#include "../hde28c/hde32.h"
#include "graph.h"
#include "../libdisasm/libdis.h"

#define DBG { fprintf (stdout, "%s %d\n", __FILE__, __LINE__); fflush (stdout); }

/* Free structure list_node */
void free_node_list (p_node_list list) {


	p_node_list tmp_list;

	while (list->next != NULL) {
		tmp_list = list;
		list = list->next;
		free (tmp_list);
	}

	free (list);

	return;
}

/* Add child to node */
void add_child_to_node (p_node node, int child) {

	int *children = NULL;

	if (node->left == -1) node->left = child;
	else if (node->right == -1) node->right = child;
	else {
		fprintf (stderr, "GRAPH ERROR : NODE HAVE YET TWO CHILDREN !!\n");
		fprintf (stderr, "NODE %d\nCHILD 1 : %X\nCHILD 2 %X\nCHILD ON %X\n", 
				node->id, node->left, node->right, child);
		exit (EXIT_FAILURE);
	}

	return;
}

/* Return new allocated list of node properly initialized */
p_node_list new_node_list (int father, int child) {

	p_node_list list = NULL;
	p_node node = NULL;

	list = (p_node_list) calloc (1, sizeof (t_node_list));
	if (list == NULL) return NULL;

	list->next = NULL;
	node = &(list->node);
	node->id = father;
	node->left = -1;
	node->right = -1;

	if (child >= 0) {
		add_child_to_node (node, child);
	}

	return list;
}


/* Search node, return node if present NULL else */
p_node search_node (p_node_list list, int id) {

	p_node node = NULL;

	while (list != NULL) {

		node = &(list->node);
		if (node->id == id) 
			return node;

		list = list->next;
	}

	return NULL;
}

/* Add node to list                      * 
 * ------------------------------------- *
 * If child < 0, don't add child to node */
p_node add_node_to_list (p_node_list list, int father, int child) {

	p_node node = NULL;

	if (list == NULL) return NULL;

	while (1) {

		node = &(list->node);
		if (node->id == father) {

			if (child >= 0)
				add_child_to_node (node, child);
			return node;
		}

		if (list->next == NULL) break;
		list = list->next;
	}

	list->next = new_node_list (father, child);

	return &(list->next->node);
}

/* Transfer node1 to node2, node2 take children of node1 and node2 *
 * become child of node1                                           */
void transfer_branch (p_node_list list, int id1, int id2) {

	p_node node1, node2;

	node1 = search_node (list, id1);
	if (node1 == NULL) {
		fprintf (stderr, "GRAPH ERROR : TRY TO TRANSFER ON A UNKNOWN NODE !! %X\n", id1);
		exit (EXIT_FAILURE);
		return;
	}

	node2 = add_node_to_list (list, id2, -1); 
	node2->left = node1->left;
	node2->right = node1->right;
	node1->left = node2->id;
	node1->right = -1;

	return;
}


/* Write directed graphe in file for GraphViz Format */
void write_directed_graph_from_list (PEExtend *PE, FILE *fd, p_node_list list) {

	p_node_list start = list;
	p_node node;
	int i, k, l, ret;

	DWORD RVA;

	char instr[BUFSIZ];
	char final_instr[BUFSIZ];
	LPCTSTR lpFunctionName;
	hde32s hde;
	x86_insn_t insn;

	RVA = PE->dwTextSectionVirtualAddress + PE->dwImageBase;

	/* Write header */
	fprintf (fd, "digraph G {\n"
		     "node [shape=record];\n");

	while (list != NULL) {

		node = &(list->node);

		fprintf (fd, "\tloc_%X [shape=record, fontname=\"Monospace\", "
				"label=\"{loc_%X :\\l|{{",
			     RVA + node->id, RVA + node->id);

		for (i = 0 ; i < PE->dwSizeOfRawData ; i++) {

			if (PE->lpdwColoredGraph[i] == node->id) {

				if (i == node->id)
					fprintf (fd, "%08X", RVA + i);
				else 
					fprintf (fd, "|%08X", RVA + i);
			}
		}

		fprintf (fd, "}|{");

		for (i = 0 ; i < PE->dwSizeOfRawData ; i++) {

			if (PE->lpdwColoredGraph[i] == node->id) {


				instr[0] = '?';
				instr[1] = '\0';
				/* Get opcode in an organized struct */
				hde32_disasm ((const void *) (PE->pbTextSection+i), &hde);

				lpFunctionName = 
				  PE->GetFunctionName (&hde, (DWORD) i, NULL);

				if (lpFunctionName != NULL) {
					if (i == node->id)
						fprintf (fd, 
							"call\\ \\ \\ \\ %s\\l", 
							lpFunctionName);
					else
						fprintf (fd,
							"|call\\ \\ \\ \\ %s\\l",
							lpFunctionName);
					continue;
				}

				/* Get full disassembly from opcode */
				if (x86_disasm (PE->pbTextSection+i,hde.len,0,0,&insn)) {
					if (x86_format_insn (&insn, instr, BUFSIZ,
							(x86_asm_format) 2)<=0) {
						instr[0] = '?';
						instr[1] = '\0';
					} else {

						/* Clean string */
						for (k = 0, l = 0 ; 
						     k < strlen (instr) + 1&& l<BUFSIZ-1 ;
						     k++, l++) {
							if (instr[k] == '\t') {
								final_instr[l] = '\\';
								final_instr[l + 1] = ' ';
								final_instr[l + 2] = '\\';
								final_instr[l + 3] = ' ';
								final_instr[l + 4] = '\\';
								final_instr[l + 5] = ' ';
								final_instr[l + 6] = '\\';
								final_instr[l + 7] = ' ';
								l+=7;
								if (k <= 3) {
								final_instr[l + 1] = '\\';
								final_instr[l + 2] = ' ';
								l+=2;
								}
								if (k <= 2) {
								final_instr[l + 1] = '\\';
								final_instr[l + 2] = ' ';
								l+=2;
								}
							} else if (instr[k] == '[') {
								final_instr[l] = '\\';
								final_instr[l+1] = '[';
								l++;
							} else if (instr[k] == ']') {
								final_instr[l] = '\\';
								final_instr[l+1] = ']';
								l++;
							} else
								final_instr[l] = instr[k];
						}
					}
				}
				if (i == node->id)
					fprintf (fd, "%s\\l", final_instr);
				else
					fprintf (fd, "|%s\\l", final_instr);

			}
		}

		fprintf (fd, "}}}\"];\n");

		list = list->next;
	}

	/* Reinit at start */
	list = start;

	/* Set graph link */
	while (list != NULL) {

		node = &(list->node);

		fprintf (fd, "\tloc_%X -> {", RVA + node->id);

		if (node->left >= 0)
			fprintf (fd, "loc_%X; ", RVA + node->left);
		if (node->right >= 0)
			fprintf (fd, "loc_%X; ", RVA + node->right);
		fprintf (fd, "}\n");
		list = list->next;
	}

	/* Write end */
	fprintf (fd, "}\n");

	return;
}
