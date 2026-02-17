/*
 * main.c - A simple user lookup tool with a SQL injection vulnerability.
 *
 * This program uses custom wrapper functions (mydb.h) to read user input
 * and execute SQL queries. Because CodeQL doesn't recognise these custom
 * functions as sources, sinks, or summaries, it will NOT flag the SQL
 * injection vulnerability — until we provide models-as-data definitions.
 *
 * Vulnerability: user input from myapp_read_input() flows unsanitised
 * through myapp_format() into mydb_exec(), allowing SQL injection.
 *
 *   Example malicious input:  ' OR 1=1 --
 */

#include <stdio.h>
#include <stdlib.h>
#include "mydb.h"

int main(void) {
    /* Initialise the driver (loads function pointers at runtime) */
    mydb_init();

    /* Open (or create) the database */
    mydb_conn *conn = mydb_open("users.db");
    if (!conn) {
        return 1;
    }

    /* Set up a simple users table */
    mydb_exec(conn, "CREATE TABLE IF NOT EXISTS users ("
                     "  id INTEGER PRIMARY KEY,"
                     "  name TEXT NOT NULL,"
                     "  role TEXT NOT NULL"
                     ");");
    mydb_exec(conn, "INSERT OR IGNORE INTO users VALUES (1, 'alice', 'admin');");
    mydb_exec(conn, "INSERT OR IGNORE INTO users VALUES (2, 'bob',   'user');");

    /* ---- VULNERABILITY: SQL injection via custom wrapper functions ---- */

    char username[256];

    /* SOURCE: myapp_read_input reads untrusted user input into username */
    if (myapp_read_input("Enter username to look up: ", username, sizeof(username)) != 0) {
        fprintf(stderr, "Failed to read input\n");
        mydb_close(conn);
        return 1;
    }

    /* SUMMARY: myapp_format propagates the tainted data into the query */
    char query[512];
    myapp_format(query, sizeof(query),
                 "SELECT * FROM users WHERE name = '%s';", username);

    /* SINK: mydb_exec executes the tainted query — SQL injection! */
    printf("Running query: %s\n", query);
    mydb_exec(conn, query);

    mydb_close(conn);
    return 0;
}
