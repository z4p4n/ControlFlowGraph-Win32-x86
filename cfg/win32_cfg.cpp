#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <winnt.h>

/* #include "ZDisasm.h" */
#include "../hde28c/hde32.h"
#include "../graph/graph.h"
#include "../pe/pelib_extend/pelib_extend.h"
#include "../dbglib/dbg.h"

#define GET_ID_TEXT(addr) get_id_text (PE, PE->lpdwColoredGraph, PE->dwSizeOfRawData, addr)
#define SET_ID_TEXT(addr, val) set_id_text (PE, list, PE->lpdwColoredGraph, \
		PE->dwSizeOfRawData, addr, val)
#define DBG_GRAPH dbg_directed_graph (PE, list);

void set_id_text (PEExtend *PE, p_node_list list, 
		DWORD *id_text, int size, int addr, int val) {

	if (addr < 0 || addr >= size) { 
		fprintf (stderr, "UNBOUND VALUE %X\n", addr); 
		delete PE;
		exit (EXIT_FAILURE); 
	}

	if (search_node (list, val) == NULL) {
		fprintf (stderr, "NODE DOES NOT EXIST %X\n", val); 
		delete PE;
		exit (EXIT_FAILURE); 
	}

	id_text[addr] = val; 

	return; 
}


int get_id_text (PEExtend *PE, DWORD *id_text, int size, int addr) {

	if (addr < 0 || addr >= size) { 
		fprintf (stderr, "Unbound value %d", __LINE__); 
		delete PE;
		exit (EXIT_FAILURE); 
	}

	return id_text[addr]; 
}



void dbg_directed_graph (PEExtend *PE, p_node_list list) {

	static int i = 0;
	FILE *fd;
	char path[BUFSIZ];

	snprintf (path, BUFSIZ, "dbg/dbg%d", i);

	fd = fopen (path, "w");
	write_directed_graph_from_list (PE, fd, list);
	fclose (fd);

	i++;
	return;
}
/*
int cgf_branch_builder (hde32s *hde,
                        BYTE *text,
                        p_node_list list,
			DWORD EndTextSection) {

	DWORD dwAddr;

	 CALL 
	} else if (hde->opcode == 0xE8) {

		if (hde->len == 3)
			dwAddr = (DWORD) hde->rel16 + text;
		else if (hde->len == 5) 
			dwAddr = (DWORD) text + (DWORD) hde->rel32;
		else {
			fprintf (stderr, "Error with Call 0xE8, len : %d\n", hde->len);
			return -1;
		}

		add_node_to_list (list, (int) text, dwAddr);
		add_node_to_list (list, dwAddr, -1);
		cfg_call_builder (text + hde->rel16, list, EndTextSection, (int) text);

	}

	return 0;
}
*/

void cfg_call_builder (PEExtend *PE,
                      p_node_list list, 
		      int start_position,
		      int actual_node) {

	/* Disassembly vars */
	hde32s hde;
	int i = start_position, j = 0;
	int ret = 0, rel_addr = 0;
	LPCSTR lpFunctionName = NULL;

	/* Graph vars */
	p_node node;
	int new_node = -1, old_node = -1, branch = 0;

	/* Construct Control Flow Graph */
	while (start_position < PE->dwSizeOfRawData) {

		
		ret = PE->DetectAlignmentBlock (i);
		if (ret) {
			fprintf (stdout, "[%x] Detecting alignment block\n", i);
			return;
		}

		hde32_disasm ((const void *) (PE->pbTextSection + i), &hde);

		/* If we catch an imported function */
		lpFunctionName = PE->GetFunctionName (&hde, (DWORD) i, NULL);

		/* Display light disassembly */
		fprintf (stdout, "[%x] OPCODE %02X", i, hde.opcode);
		if (hde.opcode2 != 0) fprintf (stdout, "%02X", hde.opcode2);
		if (hde.imm.imm32 != 0) fprintf (stdout, " %X",  hde.imm.imm32);
		if (hde.disp.disp32 != 0) fprintf (stdout, " (disp)%X",  hde.disp.disp32);
		if (lpFunctionName != NULL) fprintf (stdout," : %s", lpFunctionName);
		fprintf (stdout, " (len %d) \n", hde.len);

		/* Check if error in opcode */
		if ((hde.flags & F_ERROR) == F_ERROR ||
		    (hde.flags & F_ERROR_LENGTH) == F_ERROR_LENGTH ||
		    (hde.flags & F_ERROR_LOCK) == F_ERROR_LOCK ||
		    (hde.flags & F_ERROR_OPERAND) == F_ERROR_OPERAND) {

			fprintf (stdout,"ERROR WITH LAST OPCODE, Flags : %X\n", hde.flags);
			return;
		}
		
		/* If we jump on yet analyzed code */
		if (GET_ID_TEXT(i) != -1 && GET_ID_TEXT(i) != actual_node) {
			add_node_to_list (list, actual_node, GET_ID_TEXT(i));
			DBG_GRAPH;
			return;

		} else if (GET_ID_TEXT(i) != -1) {

			fprintf (stderr, "[!!] IMPOSSIBLE SITUATION\n");
			//exit (EXIT_FAILURE);
			return;
		}

		SET_ID_TEXT(i, actual_node);

		/* Detect function who terminates process */
		ret = PE->DetectExitProcedure (&hde, (DWORD) i);
		if (ret) return;

		/* Indirect CALL near procedure */
		if (hde.opcode == 0xFF && hde.len == 6) {

			
		/* CALL procedure */
		} else if (hde.opcode == 0xE8 && lpFunctionName == NULL) {

			new_node = i + hde.len;
			if (hde.len == 3) 
				new_node += (DWORD) ((signed short) hde.imm.imm16);
			else if (hde.len == 5) 
				new_node += (DWORD) hde.imm.imm32;

			if (GET_ID_TEXT (new_node) == -1) {
				add_node_to_list (list, new_node, -1);
				cfg_call_builder (PE, list, new_node, new_node);
			}

		/* RET */
		} else if (hde.opcode == 0xC3 || hde.opcode == 0xCB) {

			return;

		/* Conditional branch : JMP SHORT */
		} else if (hde.opcode >= 0x70 && hde.opcode < 0x80) {

			branch = 1;
			rel_addr = hde.imm.imm8;

		/* Conditional branch : JMP NEAR */
		} else if (hde.opcode == 0x0F && 
			   hde.opcode2 >= 0x80 && hde.opcode2 < 0x90) {

			branch = 1;
			if (hde.len == 4) rel_addr = hde.imm.imm16;
			else              rel_addr = hde.imm.imm32;

		/* JMP rel8 */
		} else if (hde.opcode == 0xEB) {
			
			branch = 2;
			rel_addr = (int) ((signed char) hde.imm.imm8);

		/* JMP rel16 or rel32 */
		} else if (hde.opcode == 0xE9) {

			branch = 2;
			if (hde.len == 3) rel_addr = hde.imm.imm16;
			else              rel_addr = hde.imm.imm32;

		/* Dynamic JMP */
		} else if (hde.opcode == 0xFF && hde.len == 2 && 
			hde.imm.imm8 >= 0xE0 && hde.imm.imm8 <= 0xE7) {

			return;
		}

		/* Particular case : a single instruction loop */
		if (branch != 0 && rel_addr == 0) {
			fprintf (stdout, "SKIP AUTO BRANCH\n");
			branch = 0;
		}

		i += hde.len;

		/* If we need update CFG because of branch */
		if (branch != 0) {

			/* We branch on data yet analyzed */
			if (GET_ID_TEXT(rel_addr + i) != -1) {

				node = search_node (list, rel_addr + i);

				/* We don't enter in the branch because *
				 * it's yet well computed               */
				if (node != NULL) {

					new_node = rel_addr + i;

					add_node_to_list (list, 
							  actual_node, 
							  new_node);
					DBG_GRAPH;

					/* If not conditionnal, *
					 * terminate here       */
					if (branch == 2) return;

					new_node = i;
					fprintf (stdout, "1-- BRANCH --> %x\n", new_node);
					add_node_to_list (list, actual_node, new_node);
					add_node_to_list (list, new_node, -1);
					DBG_GRAPH;

					actual_node = new_node;

				/* We need to recompute branch */
				} else {

					old_node = rel_addr + i;

					transfer_branch (list, 
					                 GET_ID_TEXT(old_node), 
					                 old_node);

					fprintf (stdout, "<-- BREAK -->\n");
					/* If rewrite on itself */
					if (GET_ID_TEXT(old_node) ==
							actual_node) {
						
						add_node_to_list (list, old_node,old_node);
						DBG_GRAPH;

						actual_node = old_node;
					} else  {
						add_node_to_list (list, 
							  actual_node, 
							  old_node);
						DBG_GRAPH;
					}

					/* update futur branch */
					for (j=old_node+1 ; j<PE->dwSizeOfRawData ; j++) {

					    	if (GET_ID_TEXT(j)==GET_ID_TEXT(old_node)) 
							SET_ID_TEXT(j, old_node);
					}
					SET_ID_TEXT(old_node, old_node);

					/* If not conditionnal, *
					 * terminate here       */
					if (branch == 2) return;

					new_node = i;
					fprintf (stdout, "2-- BRANCH --> %x\n", new_node);
					add_node_to_list (list, actual_node, new_node);
					add_node_to_list (list, new_node, -1);
					DBG_GRAPH;

					actual_node = new_node;

					if (GET_ID_TEXT(actual_node) != -1)
						return;
				}
				
			} else { 

				new_node = rel_addr + i;
				add_node_to_list (list, actual_node, new_node);
				add_node_to_list (list, new_node, -1);
				DBG_GRAPH;
				fprintf (stdout, "3-- BRANCH --> %x\n", new_node);
				cfg_call_builder (PE, list, rel_addr + i, new_node); 

				/* If not conditionnal, terminate here */
				if (branch == 2) return;

				/* Update identity if break in recurs */

				fprintf (stdout, "MEM %x ", actual_node, GET_ID_TEXT(i));
				actual_node = GET_ID_TEXT(i - hde.len);

				fprintf (stdout, " [%x] OPCODE %02X%02X %X\n", i - hde.len, hde.opcode, hde.opcode2, hde.imm.imm32);

			
				if (GET_ID_TEXT(i) == -1 && branch == 1) {
					new_node = i;
					fprintf (stdout, "4-- BRANCH --> %x\n", new_node);
					add_node_to_list (list, actual_node, new_node);
					add_node_to_list (list, new_node, -1);
					DBG_GRAPH;
					actual_node = new_node;
				}
			}

			branch = 0;
		}
	}

	return;
}


/* Build Control Flow Graph recursively from binaries text code section */
int cfg_build (PEExtend *PE, char *path) { 

	/* Graph vars */
	int first_node = PE->dwEntryPoint;
	p_node_list list = NULL;

	/* Misc. vars */
	int i;
	FILE *fd;

	/* memset the colored graph */
	for (i = 0 ; i < PE->dwSizeOfRawData ; i++) (PE->lpdwColoredGraph)[i] = -1;

	/* Open graph file (GraphViz format) */
	fd = fopen (path, "w");
	if (fd == NULL) {
		fprintf (stderr, "File %s cannot be open!\n", path);
		return 0;
	}

	/* Initialize list */
	list = new_node_list (first_node, -1);
	if (list == NULL) {
		fprintf (stderr, "Error with malloc function\n");
		fclose (fd);
		return 0;
	}

	/*GetInstLength ((DWORD *) text, &InstructionLength); 
	fprintf (stdout, "Instruction length : %d\n", InstructionLength); */

	cfg_call_builder (PE, list, (int) PE->dwEntryPoint, first_node);

	/* Save graph in file */
	write_directed_graph_from_list (PE, fd, list);

	/* release memory */
	free_node_list (list);
	fclose (fd);

	return 1;
}

