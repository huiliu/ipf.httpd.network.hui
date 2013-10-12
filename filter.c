#define _GNU_SOURCE
#define _XOPEN_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <unistd.h>
#include <event.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <libmemcached/memcached.h>

#define _DEBUG_         1
#define _DEBUG_IPF_     1

#define TIMER_1             10
#define TIMER_1_THRESHOLD   30
#define TIMER_2             30
#define TIMER_2_THRESHOLD   70
#define TIMER_3             60
#define TIMER_3_THRESHOLD   130
#define TIMER_B_THRESHOLD   180

#define MEM_KEY_OUTTIME     131

FILE *f = NULL;
char *buff = NULL;
size_t buff_size = 2000;
const char *file_name = "/tmp/access_log";
char    ip[17] = "\0",
        dim[2],
        username[17] = "\0",
        datetime[22],
        time_zone[7],
        method[4],
        url[100],
        http_version[9];
uint16_t    state_code;
memcached_st *memc = NULL;
memcached_return_t rc;
size_t  value_len = 32,
        key_len,
        bl_value_len = 1600;   /*100 ip*/
const char  *bl_key = "blacklist";
uint8_t bl_key_len = 10;

const uint16_t bl_timer = 3600;

static void
ev_read(int fd, short event, void *argv)
{
    char    bl_value[bl_value_len];
    size_t  ret = 0;
    if ((ret = getline(&buff, &buff_size, stdin)) != -1) {

        fprintf(f, "%s", buff);
        fflush(f);

        sscanf(buff, "%s %s %s [%s %s \"%s %s %s %hu",
                                    ip,
                                    dim,
                                    username,
                                    datetime,
                                    time_zone,
                                    method,
                                    url,
                                    http_version,
                                    &state_code);

        struct in_addr ip_addr;
        inet_aton(ip, &ip_addr);

        char ret_url[50];
        sscanf(url, "%[^?]", ret_url);

        char key_tmp[60] = "\0";
        char *key, *value;
        #if _DEBUG_
        time_t t = 1381003358;
        #else
        time_t t = time(NULL);
        #endif
        time_t timestamp;
        size_t  count;
        struct tm m;
        int8_t active = 0;
        uint32_t flags = 0;

        sprintf(key_tmp, "%u_%s", ip_addr.s_addr, ret_url);
        key = crypt(key_tmp, "$1$--------");
        key_len = strlen(key);

        fprintf(stdout, "Key: %s\n", key);
        if ((value = memcached_get(memc, key, key_len, &value_len, 0, &rc))
                                                                    != NULL) {
            // handle with errors.
            #if _DEBUG_
            fprintf(stdout, "%s\n", value);
            #endif
            sscanf(value, "%ld %zu", &timestamp, &count);
            #if _DEBUG_
            fprintf(stdout, "%ld %zu %ld\n", timestamp, count, t - timestamp);
            #endif

            time_t delta_time = t - timestamp;
            #if _DEBUG_
            fprintf(stdout, "DataTime: %s\tDelta Time: %ld\n",
                                                        datetime, delta_time);
            #endif

            if (delta_time < TIMER_1)
                active = (count >= TIMER_1_THRESHOLD ? 1 : 0);
            else if (delta_time >= TIMER_1 && delta_time < TIMER_2)
                active = (count >= TIMER_2_THRESHOLD ? 1 : 0);
            else if (delta_time >= TIMER_2 && delta_time < TIMER_3)
                active = (count >= TIMER_3_THRESHOLD ? 1 : 0);
            else
                active = (count > TIMER_B_THRESHOLD ? 1 : 2);

            #if _DEBUG_
            fprintf(stderr, "GET STATE: %s\tactive: %d\tKey: %s\n",
                                    memcached_strerror(memc, rc), active, key);
            #endif

            if (active == 1) {
                // insert into black list
                char *ip = inet_ntoa(ip_addr);
                char ipf[100];

                if ((value = memcached_get(memc, bl_key, bl_key_len,
                                            &bl_value_len, 0, &rc)) != NULL) {
                    if (strstr(value, ip) == NULL) {
                        strcpy(bl_value, value);
                        strcat(bl_value, ip);
                        rc = memcached_replace(memc, bl_key, bl_key_len,
                                    bl_value, strlen(bl_value), bl_timer, flags);
                        if (rc != MEMCACHED_SUCCESS)
                            fprintf(stderr, "\e[31mFail\e[0m: %s\n",
                                                    memcached_strerror(memc, rc));
                    }
                }else{
                    rc = memcached_add(memc, bl_key, strlen(bl_key), ip,
                                                strlen(ip), bl_timer, flags);
                    if (rc != MEMCACHED_SUCCESS)
                        fprintf(stderr, "\e[31mFail\e[0m: %s\n",
                                                memcached_strerror(memc, rc));
                }

                #if _DEBUG_IPF_
                sprintf(ipf, "/sbin/iptables -A blacklist -p all -s %s -j DROP", ip);
                system(ipf);
                #endif

                #if _DEBUG_
                fprintf(stdout, "Block IP: %s\n\e[31mIPF\e[0m: %s\n", ip, ipf);
                #endif

                if ((rc = memcached_delete(memc, key, key_len, 0)) !=
                                                            MEMCACHED_SUCCESS) {
                    #if _DEBUG_
                    fprintf(stderr, "%s\nactive: %d\nkey: %s\n",
                                    memcached_strerror(memc, rc), active, key);
                    #endif
                    return;
                }
            }else if (active == 2) {
                if ((rc = memcached_delete(memc, key, key_len, 0)) !=
                                                            MEMCACHED_SUCCESS) {
                    #if _DEBUG_
                    fprintf(stderr, "%s\nactive: %d\nKey: %s\n",
                                    memcached_strerror(memc, rc), active, key);
                    #endif
                    return;
                }
                #if _DEBUG_
                else
                    fprintf(stdout, "successfully delete key %s\n", key);
                #endif
            }else if (active == 0) {
                // update
                count++;
            #if _DEBUG_
                fprintf(stdout, "B: %ld %zu\n", timestamp, count);
            #endif

                sprintf(value, "%ld %zu", timestamp, count);

            #if _DEBUG_
                fprintf(stdout, "A: %ld %zu\n", timestamp, count);
            #endif
                if ((rc = memcached_replace(memc, key, strlen(key),
                    value, strlen(value), 181, flags)) != MEMCACHED_SUCCESS)
            #if _DEBUG_
                {
                    fprintf(stderr,
                                "[\e[31mfailed\e[0m]: %s\nstate: %d\nKey: %s\n",
                                memcached_strerror(memc, rc), active, key);
            #endif
                    return;
            #if _DEBUG_
                }else
                    fprintf(stdout, "update successfully! %zu\n", count);
            #endif
            }else{
                fprintf(stderr, "the state of key \"%s\" occure errors: %u!\n",
                                                                    key, active);
                return;
            }
        }else{
            value = calloc(sizeof(char), 16);

            strptime(datetime, "%d/%b/%Y:%T", &m);
            t = mktime(&m);

            sprintf(value, "%lu %u", t, 1);
            value_len = strlen(value);

            if ((rc = memcached_add(memc, key, key_len,
                        value, value_len, 181, flags)) != MEMCACHED_SUCCESS) {
            #if _DEBUG_
                fprintf(stderr, "\e[31mFailed\e[0m: %s\n",
                                                memcached_strerror(memc, rc));
            #endif
                return;
            }else
                fprintf(stdout, "add successfully!\n");
        }
        free(value);
    }else
        exit(EXIT_SUCCESS);
}

static void
ev_blacklist(int fd, short event, void *argv)
{
    // 动态操作黑名单
    // char *value;
    // if ((value = memcached_get(memc, bl_key, bl_key_len, &bl_value_len, 0, &rc))
    //                                                                 != NULL) {
    // }
}

int
main(int argc, char **argv)
{
    struct event_base *base;
    struct event ev, ev_bl_timer;
    struct timeval tv;
    uint16_t interval = 5;

    const char *config_string = "--SERVER=localhost";
    memc = memcached(config_string, strlen(config_string));

    f = fopen(file_name, "a+");

    base = event_init();

    event_set(&ev, STDIN_FILENO, EV_READ|EV_PERSIST, ev_read, NULL);
    event_add(&ev, NULL);

    evutil_timerclear(&tv);
    tv.tv_sec = interval;
    event_set(&ev_bl_timer, -1, EV_TIMEOUT|EV_PERSIST, ev_blacklist, NULL);
    event_add(&ev_bl_timer, &tv);

    event_base_dispatch(base);

    fclose(f);
    memcached_free(memc);
    return 0;
}
