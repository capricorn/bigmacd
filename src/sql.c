#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <stdarg.h>

#include "handles.h"

static const char *sql_insert_row = "INSERT INTO MAC(address,first_seen,"
            "last_seen) VALUES(\"%s\",%d,%d);";
static const char *sql_check_address_exists = "SELECT address FROM mac WHERE "
            "address=\"%s\" limit 1;";
static const char *sql_select_tag_from_address = "SELECT tag FROM mac WHERE "
            "address=\"%s\";";
static const char *sql_set_tag_for_address = "UPDATE mac SET tag=\"%s\" WHERE "
            "address=\"%s\";";
static const char *sql_get_ls_for_address = "SELECT last_seen FROM mac WHERE "
            "address=\"%s\";";
static const char *sql_set_ls_for_address = "UPDATE mac SET last_seen=%ld "
            "WHERE address=\"%s\";";

static size_t sql_insert_row_len = 92;
static size_t sql_check_address_exists_len = 64;
static size_t sql_select_tag_from_address_len = 50;
static size_t sql_set_tag_for_address_len = 116;
static size_t sql_get_ls_for_address_len = 56;
static size_t sql_set_ls_for_address_len = 66;

static int execute_sql(const char *statement);
static int create_table();
static int handle_retrieved_data(void *argument, int col_count, char **column_text,
        char **column_names);
static char *create_statement(const char *skeleton_stmt, size_t len, ...);
/* Have this use sqlite error codes?
 * That way you can tell what the error was from (constraint violation, etc)
*/
static char *column_data;

int execute_sql(const char *statement)
{
    char *error = NULL;

    sqlite3_exec(mac_db, statement, handle_retrieved_data, NULL, &error);
    if (error != NULL) {
        return -1;
    }

    sqlite3_free(error);
    return 0;
}

static int create_table()
{
    const char *table_statement = "create table mac (address char(12),"
        "first_seen timestamp(1), last_seen timestamp(1),"
        "tag char(64), script char(255),"
        "PRIMARY KEY(address, first_seen, last_seen));";

    return execute_sql(table_statement);
}

sqlite3 *check_db_exists()
{
    sqlite3 *db = NULL;

    if (access("mac.db", F_OK) != -1) {
        if (sqlite3_open("mac.db", &db) != SQLITE_OK) {
            fprintf(stderr, "bigmacd: error: Unable to open database.\n");
            exit(EXIT_FAILURE);
        }
        return db;
    }

    printf("bigmacd: Attempting to create database..\n");

    if (sqlite3_open("mac.db", &db) != SQLITE_OK) {
        fprintf(stderr, "bigmacd: error: Unable to create database.");
        exit(EXIT_FAILURE);
    }

    if (create_table(db) == -1) {;
        fprintf(stderr, "bigmacd: error: Unable to create database.");
        exit(EXIT_FAILURE);
    }

    printf("bigmacd: Successfully create database!\n");
    return db;
}

static int handle_retrieved_data(void *argument, int col_count, char **column_text,
        char **column_names)
{
    if (*column_text != NULL) {
        column_data = strdup(*column_text);
        return -1;
    }

    column_data = NULL;
    return 0;
}

int add_mac_to_db(const char *mac, int first_seen_ts, int last_seen_ts)
{
    int ret = 0;
    char *stmt = create_statement(sql_insert_row, sql_insert_row_len, mac,
            first_seen_ts, last_seen_ts);

    ret = execute_sql(stmt);
    free(stmt);

    return ret;
}

int check_for_duplicate_macs(const char *mac)
{
    int ret = 0;
    char *stmt = create_statement(sql_check_address_exists,
            sql_check_address_exists_len, mac);
    ret = execute_sql(stmt);
    free(stmt);

    return ret;
}

void close_mac_db()
{
    sqlite3_close(mac_db);
}

char *retrieve_tag(const char *mac)
{
    char *stmt = create_statement(sql_select_tag_from_address, 
            sql_select_tag_from_address_len, mac);
    execute_sql(stmt);
    free(stmt);

    if (column_data != NULL) {
        return column_data;
    }
    return NULL;
}

// Idea for creating statements in a better way.
//const char *create_stmt(const char *str, va_args ..., size_t len);
// Then you can have an enum of lens, and a bunch of sql statements defined
// above static.

int tag_mac_address(const char *mac, const char *tag)
{
    int ret = 0;

    char *stmt = create_statement(sql_set_tag_for_address,
            sql_set_tag_for_address_len, tag, mac);
    ret = execute_sql(stmt);
    free(stmt);

    return ret;
}

void update_last_seen_ts(const char *mac)
{
    char *stmt = create_statement(sql_set_ls_for_address,
            sql_set_ls_for_address_len, time(NULL), mac);
    execute_sql(stmt);
    free(stmt);
}

time_t retrieve_last_seen_ts(const char *mac)
{
    char *stmt = create_statement(sql_get_ls_for_address,
            sql_get_ls_for_address_len, mac);
    execute_sql(stmt);
    free(stmt);

    if (column_data != NULL) {
        time_t ts = (time_t) strtol(column_data, NULL, 10);
        free(column_data);
        if (ts != 0) {
            return ts;
        }
    }

    return 0;
}

static char *create_statement(const char *skeleton_stmt, size_t len, ...)
{
    va_list ap;
    va_start(ap, len);

    char *complete_stmt = malloc(len);
    vsnprintf(complete_stmt, len, skeleton_stmt, ap);
    complete_stmt[len-1] = '\0';

    va_end(ap);
    return complete_stmt;
}
