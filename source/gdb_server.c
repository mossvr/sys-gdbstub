
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
#include "poll_thread.h"

#define MAX_CLIENTS 4

#if 0
#define logf(fmt, ...) printf("gdb_server: " fmt, ##__VA_ARGS__)
#else
#define logf(fmt, ...)
#endif

typedef struct gdb_client
{
    int sock;
    gdb_stub_t* stub;
} gdb_client_t;

struct gdb_server
{
    int sock;

    poll_thread_t poll;
    struct pollfd fds[MAX_CLIENTS+1u];
    gdb_client_t clients[MAX_CLIENTS];

    char rx_buffer[512];
};

static void gdb_server_update_fds(gdb_server_t* server);
static bool gdb_server_accept(gdb_server_t* server);
static void gdb_stub_output(gdb_stub_t* stub, char* buffer, size_t length, void* arg);
static void gdb_client_destroy(gdb_client_t* client);

#include <switch/services/bsd.h>

gdb_server_t* gdb_server_create(int port)
{
    logf("%s\n", __PRETTY_FUNCTION__);

    int res;
    gdb_server_t* server;

    server = calloc(1u, sizeof(gdb_server_t));
    if(server == NULL)
    {
        logf("calloc failed\n");
        goto err;
    }

    for(size_t i = 0u; i < MAX_CLIENTS; ++i)
    {
        server->clients[i].sock = -1;
    }

    server->sock = socket(AF_INET, SOCK_STREAM, 0);
    if(server->sock < 0)
    {
        logf("failed to create socket\n");
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
        logf("bind failed\n");
        goto err_2;
    }

    res = listen(server->sock, 1);
    if(res < 0)
    {
        logf("listen failed\n");
        goto err_2;
    }

    if(R_FAILED(poll_thread_init(&server->poll)))
    {
        goto err_2;
    }

    gdb_server_update_fds(server);
    poll_thread_poll(&server->poll, server->fds, MAX_CLIENTS + 1u, -1);

    return server;
err_2:
    close(server->sock);
err_1:
    free(server);
    server = NULL;
err:
    return NULL;
}

int gdb_server_waiters(gdb_server_t* server, Waiter* waiters, size_t max)
{
    logf("%s\n", __PRETTY_FUNCTION__);

    Result res;
    int count = 0;

    if(max < MAX_CLIENTS + 1u)
    {
        return -1;
    }

    waiters[count++] = poll_thread_waiter(&server->poll);

    for(size_t i = 0u; i < MAX_CLIENTS; ++i)
    {
        gdb_client_t* client = &server->clients[i];
        if(client->stub != NULL)
        {
            res = gdb_stub_get_waiter(client->stub, &waiters[count]);
            if(R_SUCCEEDED(res))
            {
                count++;
            }
        }
    }

    return count;
}

static void gdb_server_update_fds(gdb_server_t* server)
{
    logf("%s\n", __PRETTY_FUNCTION__);

    bool accept_clients = false;

    memset(server->fds, 0, sizeof(server->fds));

    for(size_t i = 0; i < MAX_CLIENTS; ++i)
    {
        if(server->clients[i].sock == -1)
        {
            accept_clients = true;
        }

        server->fds[i+1u].fd = server->clients[i].sock;
        server->fds[i+1u].events = POLLIN;
    }

    logf("%s accepting clients\n", accept_clients ? "are" : "not");

    server->fds[0].fd = accept_clients ? server->sock : -1;
    server->fds[0].events = POLLIN;
}

bool gdb_server_handle_event(gdb_server_t* server, int idx)
{
    logf("%s (idx=%d)\n", __PRETTY_FUNCTION__, idx);

    if(idx == 0)
    {
        bool update_fds = false;
        int res = poll_thread_result(&server->poll);
        if(res < 0)
        {
            logf("poll error\n");
            return false;
        }
        else if(res > 0)
        {
            // check for server socket events
            if(server->fds[0].fd != -1)
            {
                if((server->fds[0].events & (POLLERR | POLLHUP | POLLNVAL)) != 0u)
                {
                    logf("server error\n");
                    return false;
                }
                else if((server->fds[0].revents & POLLIN) != 0u)
                {
                    logf("accepting client\n");
                    if(gdb_server_accept(server))
                    {
                        update_fds = true;
                    }
                    else
                    {
                        logf("accept failed\n");
                        // don't try to accept another client until one disconnects
                        server->fds[0].fd = -1;

                        // give up for now
                        return false;
                    }
                }
            }

            // check for client socket events
            for(size_t i = 0u; i < MAX_CLIENTS; ++i)
            {
                gdb_client_t* client = &server->clients[i];

                if(server->clients[i].sock == -1)
                {
                    continue;
                }

                if((server->fds[i+1u].revents & (POLLERR | POLLHUP | POLLNVAL)) != 0u)
                {
                    gdb_client_destroy(client);
                    update_fds = true;
                }
                else if((server->fds[i+1u].revents & POLLIN) != 0u)
                {
                    ssize_t count = read(client->sock, server->rx_buffer, sizeof(server->rx_buffer));
                    if(count > 0)
                    {
                        gdb_stub_input(client->stub, server->rx_buffer, count);
                    }
                    else
                    {
                        gdb_client_destroy(client);
                        update_fds = true;
                    }
                }
            }

            // update the poll descriptors
            if(update_fds)
            {
                logf("updating poll fds\n");
                gdb_server_update_fds(server);
            }

            logf("starting poll\n");
            // start the next poll
            poll_thread_poll(&server->poll, server->fds, MAX_CLIENTS + 1u, -1);
            logf("poll started\n");
        }
    }
    else
    {
        // handle gdb stub events
        for(size_t i = 0u; i < MAX_CLIENTS; ++i)
        {
            gdb_client_t* client = &server->clients[i];
            if(client->stub != NULL)
            {
                gdb_stub_handle_events(client->stub);
            }
        }
    }

    logf("returning from %s\n", __PRETTY_FUNCTION__);
    return true;
}

void gdb_server_destroy(gdb_server_t* server)
{
    logf("%s\n", __PRETTY_FUNCTION__);
    
    // destroy the clients
    for(size_t i = 0u; i < MAX_CLIENTS; ++i)
    {
        gdb_client_destroy(&server->clients[i]);
    }

    if(server->sock != -1)
    {
        close(server->sock);
    }

    poll_thread_destroy(&server->poll);
    free(server);
}

static bool gdb_server_accept(gdb_server_t* server)
{
    logf("%s\n", __PRETTY_FUNCTION__);

    gdb_client_t* client = NULL;

    for(size_t i = 0u; i < MAX_CLIENTS; ++i)
    {
        if(server->clients[i].sock == -1)
        {
            client = &server->clients[i];
            break;
        }
    }

    if(client == NULL)
    {
        goto err;
    }

    client->stub = gdb_stub_create(gdb_stub_output, client);
    if(client->stub == NULL)
    {
        goto err;
    }

    client->sock = accept(server->sock, NULL, NULL);
    if(client->sock < 0)
    {
        goto err_1;
    }

    logf("accepted connection\n");

    return true;

err_1:
    gdb_stub_destroy(client->stub);
    client->stub = NULL;
    client->sock = -1;
err:
    return false;
}

static void gdb_stub_output(gdb_stub_t* stub, char* buffer, size_t length, void* arg)
{
    logf("%s (length=%lu)\n", __PRETTY_FUNCTION__, length);

    gdb_client_t* client = (gdb_client_t*)arg;
    if(client->sock == -1)
    {
        return;
    }

    while(length != 0u)
    {
        ssize_t count = write(client->sock, buffer, length);
        if(count > 0)
        {
            length -= count;
            buffer += count;
        }
        else
        {
            gdb_client_destroy(client);
            return;
        }
    }
}

static void gdb_client_destroy(gdb_client_t* client)
{
    logf("%s\n", __PRETTY_FUNCTION__);

    if(client->sock != -1)
    {
        logf("client disconnect\n");
        close(client->sock);
        client->sock = -1;
    }

    if(client->stub != NULL)
    {
        gdb_stub_destroy(client->stub);
        client->stub = NULL;
    }
}
