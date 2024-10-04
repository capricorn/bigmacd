#ifndef _HANDLES_H_
#define _HANDLES_H_

#pragma GCC diagnostic ignored "-Wunused-parameter"

#include <pcap/pcap.h>
#include <sqlite3.h>

char *capture_interface;
pcap_t *pcap_handle;
sqlite3 *mac_db;

#endif
