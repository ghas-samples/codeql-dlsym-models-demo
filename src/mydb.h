/*
 * mydb.h - A custom database wrapper library.
 *
 * This library uses an internal driver table with function pointers that
 * are resolved at runtime.  Because CodeQL cannot follow function-pointer
 * indirection, it will NOT see through these wrappers to the underlying
 * fgets / snprintf / sqlite3_exec calls — making them perfect candidates
 * for models-as-data.
 */

#ifndef MYDB_H
#define MYDB_H

/* Opaque handle to our custom database connection */
typedef struct mydb_conn mydb_conn;

/* Initialise the driver — MUST be called before any other mydb_* function */
void mydb_init(void);

/* Open a connection to a SQLite database */
mydb_conn *mydb_open(const char *db_path);

/* Execute a SQL query string (THIS IS A SINK for sql-injection) */
int mydb_exec(mydb_conn *conn, const char *sql);

/* Close the database connection */
void mydb_close(mydb_conn *conn);

/* Read a line of user input into buf (THIS IS A SOURCE of remote/local data) */
int myapp_read_input(const char *prompt, char *buf, int bufsize);

/* Format a string, similar to snprintf (THIS IS A SUMMARY — taint flows through) */
int myapp_format(char *dst, int dstsize, const char *fmt, const char *value);

#endif /* MYDB_H */
