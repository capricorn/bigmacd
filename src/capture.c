#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <signal.h>
#include <time.h>

#include "handles.h"
#include "mac.h"
#include "sql.h"

#define PROBE_REQ   4

#define GET_BITS(value, shift, mask)    \
    ((value >> shift) & mask)

/*
#define print_bin(data, size)   \
{   \
    size_t i = 0;   \
    for (; i < size * 8; i++) { \
        printf("%d", (data >> i) & 1);  \
    }   \
    puts("");   \
}

// format
// 0x0040 = 00000000 0100 00 00
*/

struct ieee80211_radiotap {
    uint8_t it_version;
    uint8_t it_pad;
    uint16_t it_len;
    uint32_t it_present;
} __attribute__((__packed__));

struct ieee80211_frame {
    uint16_t frame_ctrl;
    uint16_t duration;
    uint8_t destination_addr[6];
    uint8_t source_addr[6];
    uint8_t bssid[6];
    uint16_t seq_ctrl;
} __attribute__((__packed__));

struct frame_ctrl_data {
    uint8_t protocol;
    uint8_t type;
    uint8_t subtype;
    uint8_t has_to_ds;
    uint8_t has_from_ds;
    uint8_t has_more_flag;
    uint8_t retry;
    uint8_t has_pwr_mgt;
    uint8_t has_more_data;
    uint8_t has_enc;
    uint8_t order;
};

enum {
    PROTOCOL  = 14,
    TYPE      = 12,
    SUBTYPE   = 8,
    TO_DS     = 7,
    FROM_DS   = 6,
    MF_FLAG   = 5,
    RETRY     = 4,
    POWER     = 3,
    MORE_DATA = 2,
    ENC       = 1,
    ORDER     = 0,
};

static void stop_sniffing(int sig);
static struct frame_ctrl_data *get_frame_ctrl_data(uint16_t frame_ctrl);
void close_capture_handle();

//static volatile sig_atomic_t sniff = 1;

static void handle_packets(unsigned char *args, const struct pcap_pkthdr *header,
        const unsigned char *packet)
{
    /*
    if (!sniff) {
        close_mac_db();
        close_capture_handle();
        close_mac_lookup_db();
        puts("Done!");
        exit(EXIT_SUCCESS);
    }
    */

    int linktype = pcap_datalink(pcap_handle);
    if (linktype != DLT_IEEE802_11_RADIO) {
        return;
    }
    
    struct ieee80211_radiotap *rt = (struct ieee80211_radiotap *) packet;
    struct ieee80211_frame *frame = (struct ieee80211_frame *) (packet + rt->it_len);
    struct frame_ctrl_data *ctrl_data = get_frame_ctrl_data(frame->frame_ctrl);

    if (ctrl_data->subtype != PROBE_REQ) {
        free(ctrl_data);
        return;
    }

    /*
    printf("Linktype: %s\n", pcap_datalink_val_to_name(linktype));
    printf("Radiotap header len: %d\n", rt->it_len);
    printf("Timestamp: %lu\n", header->ts.tv_sec);
    printf("Raw frame ctrl: %04X\n", frame->frame_ctrl);
    print_bin(frame->frame_ctrl, sizeof(frame->frame_ctrl));

    printf("Destination: ");
    print_hex(frame->destination_addr, sizeof(frame->destination_addr));
    printf("Source: ");
    print_hex(frame->source_addr, sizeof(frame->source_addr));
    printf("BSSID: ");
    print_hex(frame->bssid, sizeof(frame->bssid));

    printf("Packet size: %d\n", header->len);
    puts("==Packet==");
    print_hex(packet, header->len);
    puts("==Packet==");
    print_frame_ctrl(frame->frame_ctrl);
    puts("");
    */

    char *mac = get_mac_as_ascii(frame->source_addr);
    char *tag = NULL;
    time_t last_seen_ts = 0;

    int ret = check_for_duplicate_macs(mac);
    if (ret == -1) {
        last_seen_ts = retrieve_last_seen_ts(mac);
        update_last_seen_ts(mac);
        tag = retrieve_tag(mac);
    } else {
        add_mac_to_db(mac, header->ts.tv_sec, header->ts.tv_sec);
    }

    if (time(NULL) - last_seen_ts > 10) {
        char date[64] = {0};
        struct tm *ts_tm = localtime(&last_seen_ts);
        char *comp = get_company_from_id(mac);

        // A better option may be to just set LS to time(NULL)
        if (ts_tm == NULL || last_seen_ts == 0) {
            date[0] = '?';
        } else {
            strftime(date, sizeof(date), "%F %T", ts_tm);
        }
        printf("Detected MAC [%s] (LS: %s, CO: %s).\n", (tag == NULL) ? 
                mac : tag, date, (comp == NULL) ? "N/A": comp);
        //puts(mac);
        //printf(mac);
        free(comp);
    }

    free(tag);
    free(mac);
    free(ctrl_data);
}

pcap_t *get_capture_handle()
{
    pcap_t *handle;
    char error[PCAP_ERRBUF_SIZE];
    struct bpf_program bpf;

    handle = pcap_create(capture_interface, error);
    if (handle == NULL) {
        fprintf(stderr, "bigmacd: error: Unable to get pcap handle.\n");
        goto cleanup;
    }

    if (pcap_can_set_rfmon(handle) != 1) {
        fprintf(stderr, "bigmacd: error: Can't set monitor mode.\n");
        goto cleanup;
    }

    if (pcap_set_rfmon(handle, 1) == PCAP_ERROR_ACTIVATED) {
        fprintf(stderr, "bigmacd: error: Can't activate monitor mode.\n");
        goto cleanup;
    }

    if (pcap_activate(handle) == -1) {
        fprintf(stderr, "Unable to activate pcap handle.\n");
        goto cleanup;
    }

    if (pcap_setdirection(handle, PCAP_D_IN) == -1) {
        fprintf(stderr, "Unable to only capture incoming packets.\n");
    }

    if (pcap_compile(handle, &bpf, "wlan type mgt subtype probe-req", 1, 
                PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Unable to compile packet filter.\n");
        goto cleanup;
    }

    if (pcap_setfilter(handle, &bpf) == -1) {
        fprintf(stderr, "Couldn't set packet filter.\n");
        pcap_freecode(&bpf);
        goto cleanup;
    }
    pcap_freecode(&bpf);
    if (pcap_set_datalink(handle, DLT_IEEE802_11_RADIO) == -1) {
        fprintf(stderr, "bigmacd: error: Can't set datalink type.\n");
        goto cleanup;
    }

    return handle;

cleanup:
    fprintf(stderr, "%s\n", pcap_geterr(handle));
    free(handle);
    return NULL;
}

static void stop_sniffing(int sig)
{
    //sniff = 0;
    pcap_breakloop(pcap_handle);
    close_mac_db();
    close_capture_handle();
    close_mac_lookup_db();
}

int capture_packets()
{
    signal(SIGINT, stop_sniffing);

    int captured = pcap_loop(pcap_handle, -1, handle_packets, NULL);
    if (captured == -2) {
        return 0;
    }

    return captured;
}

void close_capture_handle()
{
    pcap_close(pcap_handle);
}

static struct frame_ctrl_data *get_frame_ctrl_data(uint16_t frame_ctrl)
{
    struct frame_ctrl_data *data = malloc(sizeof(*data));

    data->protocol = GET_BITS(frame_ctrl, PROTOCOL, 3);
    data->type = GET_BITS(frame_ctrl, TYPE, 3);
    //data->subtype = GET_BITS(frame_ctrl, SUBTYPE, 15);  // get 4 bits
    data->subtype = GET_BITS(frame_ctrl, 4, 0xf);
    data->has_to_ds = GET_BITS(frame_ctrl, TO_DS, 1);
    data->has_from_ds = GET_BITS(frame_ctrl, FROM_DS, 1);
    data->has_more_flag = GET_BITS(frame_ctrl, FROM_DS, 1);
    data->retry = GET_BITS(frame_ctrl, RETRY, 1);
    data->has_pwr_mgt = GET_BITS(frame_ctrl, POWER, 1);
    data->has_more_data = GET_BITS(frame_ctrl, MORE_DATA, 1);
    data->has_enc = GET_BITS(frame_ctrl, ENC, 1);
    data->order = GET_BITS(frame_ctrl, ORDER, 1);

    return data;
}
