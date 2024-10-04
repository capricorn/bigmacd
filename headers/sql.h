#ifndef _SQL_H
#define _SQL_H

#include <sqlite3.h>
#include <time.h>

int add_mac_to_db(const char *mac, int first_seen_ts, int last_seen_ts);
int tag_mac_address(const char *mac, const char *tag);
time_t retrieve_last_seen_ts(const char *mac);
int check_for_duplicate_macs(const char *mac);
char *retrieve_tag(const char *mac);
void close_mac_db();
void update_last_seen_ts(const char *mac);
sqlite3 *check_db_exists();

#endif
