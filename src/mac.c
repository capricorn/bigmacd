#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bsd/string.h>
#include <sys/stat.h>

#define COMPANIES   20961
#define COMPANY_IDS 20961
#define MAC_LEN     12
#define ID_LEN  7

static char **companies;
static char **company_ids;

static char **read_mac_lookup_db(const char *filename, size_t members);
static void close_db();
static char *grab_id_from_mac(const char *mac);

char *get_mac_as_ascii(unsigned char *raw_mac)
{
    char *buffer = malloc(MAC_LEN + 1);
    size_t i;

    for (i = 0; i < 6; i++) {
        snprintf(buffer + i * 2, 3, "%02X", raw_mac[i]);
    }

    return buffer;
}

char *get_company_from_id(const char *mac)
{
    char *id_name = NULL;
    char *id = grab_id_from_mac(mac);

    size_t i;

    for (i = 0; i < COMPANY_IDS && company_ids[i] != NULL; i++) {
        if (strcmp(id, company_ids[i]) == 0) {
            id_name = strdup(companies[i]);
            break;
        }
    }

    free(id);
    return id_name;
}

int open_mac_lookup_db()
{
    companies = read_mac_lookup_db("./runtime/co.txt", COMPANIES);
    company_ids = read_mac_lookup_db("./runtime/hex.txt", COMPANY_IDS);

    if (companies == NULL || company_ids == NULL) {
        return -1;
    }
    return 0;
}

static char **read_mac_lookup_db(const char *filename, size_t members)
{
    FILE *file = fopen(filename, "r");
    char **data = calloc(members + 1, sizeof(*data));
    char *item;

    size_t i = 0;
    char buff[1024];

    for (; i < members && (item = fgets(buff, 1023, file)) != NULL; i++) {
        data[i] = strdup(item);
        // Remove newline
        *(data[i] + strlen(data[i]) - 1) = '\0';
    }
    fclose(file);

    data[members] = NULL;
    return data;
}

static void close_db(char **data, size_t members)
{
    size_t i;
    for (i = 0; i < members; i++) {
        free(data[i]);
    }
    free(data);
}

void close_mac_lookup_db()
{
    close_db(companies, COMPANIES);
    close_db(company_ids, COMPANY_IDS);
}

static char *grab_id_from_mac(const char *mac)
{
    char *id = malloc(ID_LEN);
    strlcpy(id, mac, ID_LEN);

    return id;
}
