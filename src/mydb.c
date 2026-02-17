/*
 * mydb.c - Implementation of the custom database wrapper library.
 *
 * All calls to the real libc / sqlite3 functions go through function
 * pointers that are resolved at runtime via dlsym().  This means
 * CodeQL's static interprocedural analysis cannot see through the
 * wrappers — it has no idea that myapp_read_input calls fgets,
 * that myapp_format calls snprintf, or that mydb_exec calls
 * sqlite3_exec.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <dlfcn.h>
#include "mydb.h"

/* ── Internal driver table (resolved at runtime) ──────────────── */

typedef void *(*fn_db_open)(const char *, void **);
typedef int   (*fn_db_exec)(void *, const char *, void *, void *, char **);
typedef void  (*fn_db_close)(void *);
typedef void  (*fn_db_free)(void *);
typedef char *(*fn_db_errmsg)(void *);
typedef char *(*fn_read_line)(char *, int, void *);
typedef int   (*fn_formatter)(char *, unsigned long, const char *, ...);

static struct {
    fn_db_open    open;
    fn_db_exec    exec;
    fn_db_close   close;
    fn_db_free    freemem;
    fn_db_errmsg  errmsg;
    fn_read_line  readline;
    fn_formatter  format;
    void         *stdin_handle;
} driver;

/* ── Initialise the driver table via dlsym ─────────────────────── */

void mydb_init(void) {
    void *libsqlite = dlopen("libsqlite3.so", RTLD_NOW | RTLD_GLOBAL);
    if (!libsqlite)
        libsqlite = dlopen("libsqlite3.so.0", RTLD_NOW | RTLD_GLOBAL);

    driver.open    = (fn_db_open)   dlsym(libsqlite, "sqlite3_open");
    driver.exec    = (fn_db_exec)   dlsym(libsqlite, "sqlite3_exec");
    driver.close   = (fn_db_close)  dlsym(libsqlite, "sqlite3_close");
    driver.freemem = (fn_db_free)   dlsym(libsqlite, "sqlite3_free");
    driver.errmsg  = (fn_db_errmsg) dlsym(libsqlite, "sqlite3_errmsg");

    driver.readline    = (fn_read_line) dlsym(RTLD_DEFAULT, "fgets");
    driver.format      = (fn_formatter) dlsym(RTLD_DEFAULT, "snprintf");
    driver.stdin_handle = stdin;
}

/* ── Opaque connection handle ─────────────────────────────────── */

struct mydb_conn {
    void *db;   /* really sqlite3*, but opaque here */
};

/* ── Public API ───────────────────────────────────────────────── */

mydb_conn *mydb_open(const char *db_path) {
    mydb_conn *conn = malloc(sizeof(mydb_conn));
    if (!conn) return NULL;

    if (driver.open(db_path, &conn->db) != 0) {
        fprintf(stderr, "Cannot open database: %s\n",
                (char *)driver.errmsg(conn->db));
        free(conn);
        return NULL;
    }
    return conn;
}

int mydb_exec(mydb_conn *conn, const char *sql) {
    char *err_msg = NULL;
    int rc = driver.exec(conn->db, sql, NULL, NULL, &err_msg);
    if (rc != 0) {
        fprintf(stderr, "SQL error: %s\n", err_msg);
        driver.freemem(err_msg);
        return -1;
    }
    return 0;
}

void mydb_close(mydb_conn *conn) {
    if (conn) {
        driver.close(conn->db);
        free(conn);
    }
}

int myapp_read_input(const char *prompt, char *buf, int bufsize) {
    printf("%s", prompt);
    if (driver.readline(buf, bufsize, driver.stdin_handle) == NULL) {
        return -1;
    }
    /* Strip trailing newline */
    buf[strcspn(buf, "\n")] = '\0';
    return 0;
}

int myapp_format(char *dst, int dstsize, const char *fmt, const char *value) {
    return driver.format(dst, (unsigned long)dstsize, fmt, value);
}
