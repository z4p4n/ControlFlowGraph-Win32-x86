#ifndef DBGLIB_H
#define DBGLIB_H

#define DBG_FAIL(msg) { fprintf (stderr, "[DBG : %s]  %s %d\n", msg, __FILE__, __LINE__);\
                        fflush (stdout); \
                        exit (EXIT_FAILURE); }
#define DBG { fprintf (stderr, "%s %d\n", __FILE__, __LINE__); fflush (stdout); }

#endif

