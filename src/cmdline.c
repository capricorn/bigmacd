#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <stdlib.h>

#include "handles.h"
#include "sql.h"

enum { 
    TAG = 0,
    CAPTURE,
};

int opterr = 0;

void handle_arguments(int arg_count, char **arguments)
{
    struct option opts[] = {
        { "tag", 1, NULL, TAG },
        { "capture", 1, NULL, CAPTURE },
        { 0, 0, NULL, 0 },
    };

    int option;
    int index = 0;
    char *mac = NULL;
    char *tag = NULL;
    char *arg = NULL;

    while ((option = getopt_long(arg_count, arguments, "", opts, 
        &index)) != -1) {
        switch (option) {
            case TAG:
                arg = strdup(optarg);
                mac = strsep(&arg, ":");
                tag = strsep(&arg, ":");

                if (mac == NULL || tag == NULL) {
                    fprintf(stderr, "error: bigmacd: Bad MAC tag.\n");
                    free(arg);
                    break;
                }

                if (tag_mac_address(mac, tag) != 0 ) {
                    fprintf(stderr, "bigmacd: error: Unable to tag MAC.\n");
                }

                free(arg);
                break;
            case CAPTURE:
                capture_interface = strdup(optarg);
                printf("Set capture interface to %s.\n", capture_interface);
                break;
        }
    }
}
