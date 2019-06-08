
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <poll.h>

#include "gdb_server.h"
#include "gdb_stub.h"
#include "poll_event.h"

struct gdb_server
{
    int sock;
    int client;
    gdb_stub_t* stub;
    struct pollfd fds[1];
    size_t nfds;
    poll_event_t poll;
    bool quit;
    char rx_buffer[512];
};

static void gdb_server_disconnect(gdb_server_t* server);
static void gdb_stub_output(gdb_stub_t* stub, char* buffer, size_t length, void* arg);

#include <switch/services/bsd.h>

gdb_server_t* gdb_server_create(int port)
{
    int res;
    gdb_server_t* server;

    printf("gdb_server_create\n");

    server = calloc(1u, sizeof(gdb_server_t));
    if(server == NULL)
    {
        printf("calloc failed\n");
        goto err;
    }

    server->client = -1;
    server->stub = gdb_stub_create(gdb_stub_output, server);
    if(server->stub == NULL)
    {
        printf("gdb_stub_create failed\n");
        goto err_1;
    }

    server->sock = socket(AF_INET, SOCK_STREAM, 0);
    if(server->sock < 0)
    {
        printf("failed to create socket\n");
        goto err_1;
    }

    struct sockaddr_in addr;
    bzero(&addr, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    res = bind(server->sock, (struct sockaddr*)&addr, sizeof(addr));
    if(res < 0)
    {
        printf("bind failed\n");
        goto err_2;
    }

    res = listen(server->sock, 1);
    if(res < 0)
    {
        printf("listen failed\n");
        goto err_2;
    }

    server->fds[0].fd = server->sock;
    server->fds[0].events = POLLIN;
    server->nfds = 1u;

    if(R_FAILED(poll_event_init(&server->poll)))
    {
        goto err_2;
    }

    poll_event_poll(&server->poll, server->fds, server->nfds);

    return server;
err_2:
    close(server->sock);
err_1:
    free(server);
    server = NULL;
err:
    return NULL;
}

ssize_t gdb_server_waiters(gdb_server_t* server, Waiter* waiters, size_t max)
{
    Result res;
    ssize_t count = 0;

    waiters[count++] = poll_event_waiter(&server->poll);

#if 0
    res = gdb_stub_get_waiter(server->stub, &waiters[count]);
    if(R_SUCCEEDED(res))
    {
        count++;
    }
#endif

    return count;
}

bool gdb_server_handle_event(gdb_server_t* server, s32 idx)
{
    printf("gdb_server_handle_event (idx=%d)\n", idx);

    if(idx == 0)
    {
        int res = poll_event_result(&server->poll);

        if(res > 0)
        {
            if(server->fds[0].fd == server->sock)
            {
                if((server->fds[0].events & (POLLERR | POLLHUP | POLLNVAL)) != 0u)
                {
                    printf("server error\n");
                    gdb_server_disconnect(server);
                    return false;
                }
                else if(server->client == -1 && (server->fds[0].revents & POLLIN) != 0u)
                {
                    server->client = accept(server->sock, NULL, NULL);
                    printf("accepted connection\n");

                    memset(server->fds, 0, sizeof(server->fds));
                    server->fds[0].fd = server->client;
                    server->fds[0].events = POLLIN;
                }
            }
            else
            {
                if((server->fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) != 0u)
                {
                    gdb_server_disconnect(server);
                }
                else if((server->fds[0].revents & POLLIN) != 0u)
                {
                    ssize_t count = read(server->client, server->rx_buffer, sizeof(server->rx_buffer));
                    if(count > 0)
                    {
                        gdb_stub_input(server->stub, server->rx_buffer, count);
                    }
                    else
                    {
                        gdb_server_disconnect(server);
                    }
                }
            }

            if(!server->quit)
            {
                poll_event_poll(&server->poll, server->fds, server->nfds);
            }
        }
        else if(res < 0)
        {
            printf("poll error\n");
            server->quit = true;
        }
    }
    else
    {
        gdb_stub_handle_events(server->stub);
    }

    return !server->quit;
}

void gdb_server_destroy(gdb_server_t* server)
{
    if(server->client != -1)
    {
        close(server->client);
    }
    if(server->sock != -1)
    {
        close(server->sock);
    }

    poll_event_destroy(&server->poll);

    memset(server, 0, sizeof(*server));
    free(server);
}

static void gdb_server_disconnect(gdb_server_t* server)
{
    if(server->client != -1)
    {
        close(server->client);
        server->client = -1;
        printf("client disconnected\n");
    }

    memset(server->fds, 0, sizeof(server->fds));
    server->fds[0].fd = server->sock;
    server->fds[0].events = POLLIN;

    server->quit = true;
}

static void gdb_stub_output(gdb_stub_t* stub, char* buffer, size_t length, void* arg)
{
    gdb_server_t* server = (gdb_server_t*)arg;

    buffer[length] = '\0';
    printf("gdb stub output: %s\n", buffer);

    if(server->client >= 0)
    {
        while(length != 0u)
        {
            ssize_t count = write(server->client, buffer, length);
            if(count < 0)
            {
                gdb_server_disconnect(server);
                return;
            }
            else
            {
                length -= count;
                buffer += count;
            }
        }
    }
}
