#include <sys/socket.h>
#include <stdbool.h>

typedef struct {
    int res;
    struct sockaddr_in addr;
} dns_res_t;

typedef void (*dns_done_fn)(void);

bool dns_task_start(void);
void dns_task_shutdown(void);
bool dns_task_submit_query(const char *query, dns_done_fn callback, dns_res_t *res);
