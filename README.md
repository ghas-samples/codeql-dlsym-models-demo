# Models-as-Data: SQL Injection Demo (C / CodeQL)

This project demonstrates how **models-as-data** teaches CodeQL about custom
library functions it doesn't recognise out of the box. Use this README as a
step-by-step guide for the demo.

---

## Table of Contents

1. [Background — What is models-as-data?](#1-background--what-is-models-as-data)
2. [Project layout](#2-project-layout)
3. [The vulnerability](#3-the-vulnerability)
4. [Why CodeQL misses it](#4-why-codeql-misses-it)
5. [Demo walkthrough](#5-demo-walkthrough)
   - Step 1 — Build the application
   - Step 2 — Create the CodeQL database
   - Step 3 — Run analysis WITHOUT models (no results)
   - Step 4 — Inspect the model pack
   - Step 5 — Run analysis WITH models (finds the bug)
   - Step 6 — (Optional) Exploit the vulnerability


---

## 1. Background — What is models-as-data?

CodeQL ships with built-in models for well-known libraries (e.g. it knows that
`fgets` is a source of untrusted input and `sqlite3_exec` is a SQL sink). But
when your code wraps these behind **custom function names**, CodeQL has no idea
they carry the same security semantics.

**Models-as-data** lets you describe the security behaviour of custom functions
in a YAML file — no QL code required — so CodeQL can trace taint through them.

You define three kinds of model:

| Model | Purpose | Example in this project |
|-------|---------|------------------------|
| **Source** | Marks where untrusted data enters | `myapp_read_input()` → wraps `fgets` |
| **Summary** | Describes how taint propagates through a function | `myapp_format()` → wraps `snprintf` |
| **Sink** | Marks where tainted data is dangerous | `mydb_exec()` → wraps `sqlite3_exec` |

---

## 2. Project layout

```
src/
  main.c            # Vulnerable application — the code we're scanning
  mydb.h            # Custom library header (declares source, summary, sink)
  mydb.c            # Custom library implementation (uses dlsym at runtime)
models/
  qlpack.yml        # Model pack metadata — tells CodeQL this is a model pack
  mydb.model.yml    # Models-as-data definitions (source, summary, sink)
```

---

## 3. The vulnerability

`main.c` has a classic **SQL injection**. The taint flow is:

```
  myapp_read_input(…, username, …)       ← SOURCE: reads untrusted user input
          │
          ▼
  myapp_format(query, …, …, username)    ← SUMMARY: taint propagates into query
          │
          ▼
  mydb_exec(conn, query)                 ← SINK: executes unsanitised SQL
```

An attacker entering `' OR 1=1 --` causes the query to become:

```sql
SELECT * FROM users WHERE name = '' OR 1=1 --';
```

…which returns **all rows** in the table.

---

## 4. Why CodeQL misses it

Two things conspire to hide this vulnerability from CodeQL:

### a) Custom function names

CodeQL knows about `fgets`, `snprintf`, and `sqlite3_exec` — but it has
**no built-in knowledge** of `myapp_read_input`, `myapp_format`, or `mydb_exec`.

### b) `dlsym` function-pointer indirection

Even though CodeQL does interprocedural analysis and *could* look inside
`mydb.c`, the implementations resolve the real functions **at runtime** via
`dlsym()`:

```c
driver.exec     = (fn_db_exec)   dlsym(libsqlite, "sqlite3_exec");
driver.readline = (fn_read_line) dlsym(RTLD_DEFAULT, "fgets");
driver.format   = (fn_formatter) dlsym(RTLD_DEFAULT, "snprintf");
```

`dlsym` takes a **string** and returns a `void *` — CodeQL's static analysis
cannot resolve this. It only sees indirect calls through opaque function
pointers, so the taint chain dead-ends at every wrapper.

**Result: zero findings.**

---

## 5. Demo walkthrough

> **Prerequisites:** `codeql` CLI installed and on your `$PATH`


### Step 2 — Create the CodeQL database

```bash
codeql database create mydb-db \
  --language=cpp \
  --build-mode=none \
  --overwrite
```

This builds the project and extracts a CodeQL database into `mydb-db/`.

### Step 3 — Run analysis WITHOUT models (expect zero results)

```bash
codeql database analyze mydb-db \
  codeql/cpp-queries \
  --format=sarif-latest \
  --output=results-without-models.sarif
```

**Talking point:** Open `results-without-models.sarif` — there are **no
SQL injection findings**. CodeQL doesn't recognise the custom wrappers.

### Step 4 — Inspect the model pack

Walk through the two files in `models/`:

1. **`qlpack.yml`** — declares this as a model pack targeting `codeql/cpp-all`:

   ```yaml
   name: s-samadi/mydb-models
   version: 0.1.0
   library: true

   extensionTargets:
     codeql/cpp-all: "*"

   dataExtensions:
     - "**/*.model.yml"
   ```

2. **`mydb.model.yml`** — defines the three models.

**Talking point:** No QL code needed — just YAML. Anyone who understands the
library's API can write these models.

### Step 5 — Run analysis WITH models (finds the SQL injection)

```bash
codeql database analyze mydb-db \
  codeql/cpp-queries \
  --format=sarif-latest \
  --output=results-with-models.sarif \
  --additional-packs=. \
  --extension-packs="s-samadi/mydb-models@*"
```

> **Note:** `--additional-packs=.` tells CodeQL to search the current directory
> for packs (it finds `models/qlpack.yml`). `--extension-packs` explicitly
> activates the model pack by name.

**Talking point:** Open `results-with-models.sarif` — CodeQL now reports the
SQL injection with a full taint path:
`myapp_read_input → myapp_format → mydb_exec`.

