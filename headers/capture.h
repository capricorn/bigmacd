#ifndef _CAPTURE_H
#define _CAPTURE_H

#define NONE_CAPTURED   -2
#include <pcap/pcap.h>

pcap_t *get_capture_handle();
int capture_packets();
void close_capture_handle();

#endif
