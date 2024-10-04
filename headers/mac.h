#ifndef _MAC_H
#define _MAC_H

char *get_mac_as_ascii(unsigned char *raw_mac);
char *get_company_from_id(const char *mac);
void close_mac_lookup_db();
int open_mac_lookup_db();

#endif
