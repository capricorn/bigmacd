#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#include "handles.h"
#include "sql.h"
#include "capture.h"
#include "cmdline.h"
#include "mac.h"

int main(int argc, char **argv)
{
    if (getuid() != 0) {
        fprintf(stderr, "You must be root.\n");
        return 1;
    }

    mac_db = check_db_exists();
    handle_arguments(argc, argv);

    if (capture_interface == NULL) {
        return 1;
    }

    if (open_mac_lookup_db() == -1) {
        fprintf(stderr, "bigmacd: error: Unable to open MAC lookup database.\n");
        return 1;
    }

    pcap_handle = get_capture_handle();
    int packet_count = capture_packets();
    printf("Captured %d packets.\n", packet_count);

    free(capture_interface);
    close_mac_db();
    close_capture_handle();

    return 0;
}
