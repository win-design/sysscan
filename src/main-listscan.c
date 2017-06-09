#include "sysscan.h"
#include "logger.h"
#include "rand-blackrock.h"

void
main_listscan(struct sysscan *sysscan)
{
    uint64_t count_ips;
    uint64_t count_ports;
    uint64_t i;
    uint64_t range;
    uint64_t start;
    uint64_t end;
    struct BlackRock blackrock;
    unsigned increment = sysscan->shard.of;
    uint64_t seed = sysscan->seed;

    count_ports = rangelist_count(&sysscan->ports);
    if (count_ports == 0)
        rangelist_add_range(&sysscan->ports, 80, 80);
    count_ports = rangelist_count(&sysscan->ports);

    count_ips = rangelist_count(&sysscan->targets);
    if (count_ips == 0) {
        LOG(0, "FAIL: target IP address list empty\n");
        LOG(0, " [hint] try something like \"--range 10.0.0.0/8\"\n");
        LOG(0, " [hint] try something like \"--range 192.168.0.100-192.168.0.200\"\n");
        return;
    }

    range = count_ips * count_ports;

infinite:
    blackrock_init(&blackrock, range, seed, sysscan->blackrock_rounds);

    start = sysscan->resume.index + (sysscan->shard.one-1);
    end = range;
    if (sysscan->resume.count && end > start + sysscan->resume.count)
        end = start + sysscan->resume.count;
    end += (uint64_t)(sysscan->retries * sysscan->max_rate);

//printf("start=%llu, end=%llu\n", start, end);
    for (i=start; i<end; ) {
        uint64_t xXx;
        unsigned ip;
        unsigned port;

        xXx = blackrock_shuffle(&blackrock,  i);

        ip = rangelist_pick(&sysscan->targets, xXx % count_ips);
        port = rangelist_pick(&sysscan->ports, xXx / count_ips);

        if (count_ports == 1) {
            if (sysscan->is_test_csv) {
                /* [KLUDGE] [TEST]
                 * For testing randomness output, prints last two bytes of
                 * IP address as CSV format for import into spreadsheet
                 */
                printf("%u,%u\n",
                       (ip>>8)&0xFF, (ip>>0)&0xFF
                       );
            } else {
                printf("%u.%u.%u.%u\n",
                       (ip>>24)&0xFF, (ip>>16)&0xFF, (ip>>8)&0xFF, (ip>>0)&0xFF
                       );
            }
        } else
            printf("%u.%u.%u.%u:%u\n",
                   (ip>>24)&0xFF, (ip>>16)&0xFF, (ip>>8)&0xFF, (ip>>0)&0xFF,
                   port
                   );

        i += increment; /* <------ increment by 1 normally, more with shards/nics */
    }

    if (sysscan->is_infinite) {
        seed++;
        goto infinite;
    }
}
