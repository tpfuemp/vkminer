// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The socket half of the REST API. Everything above the socket -- parsing,
// routing, authorisation, the error envelope, the limits -- is in api_http.c,
// which knows nothing about this miner; everything below the routes is here.
//
// One thread, one connection at a time, `Connection: close`. That is a
// deliberate ceiling and not an oversight: this port answers a dashboard
// polling every few seconds, and a persistent connection on a single-threaded
// server is one client holding the API shut for everyone else.

#include "api/api_server.h"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>

// _WIN32 rather than WIN32 in every guard below. The C++ here is built as
// strict ISO, which drops WIN32 -- a predefine reserved to nobody -- and keeps
// _WIN32. The inherited C is built with extensions on and still sees both,
// which is why the two spellings live side by side in this tree and why only
// one of them is safe in a .cpp. Getting it wrong here is not a warning: it
// silently compiles the POSIX branch.
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#endif

extern "C" {
#include "core/miner.h"
}

#include "api_http.h"
#include "api_routes.h"
#include "api/api_control.h"

namespace {

#ifdef _WIN32
typedef SOCKET sock_t;
const sock_t kNoSock = INVALID_SOCKET;
void sock_close(sock_t s) { closesocket(s); }
const char *sock_error() { static char b[32]; snprintf(b, sizeof(b), "error %d", WSAGetLastError()); return b; }
#else
typedef int sock_t;
const sock_t kNoSock = -1;
void sock_close(sock_t s) { close(s); }
const char *sock_error() { return strerror(errno); }
#endif

// How long accept() waits before the loop looks at g_shutdown again. Without
// it the thread sits in a system call until a client happens to connect, which
// on a miner nobody is watching is never -- and it would still be in there
// while the process was tearing its devices down.
constexpr int kAcceptPollS = 1;

// A restarted miner meets its own listener in TIME_WAIT. SO_REUSEADDR covers
// that on Linux and is deliberately not used on Windows, where it lets a
// second program steal a port in use rather than only reclaim a closed one --
// so on Windows the answer is to wait it out.
constexpr int kBindRetries = 6;
constexpr int kBindRetryS = 10;

// Bound on the accepted socket, never on the listener: this is one thread on a
// blocking accept, so a peer that connects and then says nothing would
// otherwise stall every other client. Failing to set them is not fatal -- it
// leaves the old unbounded behaviour, which is worse but still serves.
void set_sock_timeouts(sock_t s)
{
#ifdef _WIN32
    DWORD tv = API_HTTP_SOCK_TIMEOUT_S * 1000;  // winsock counts milliseconds
#else
    struct timeval tv;
    tv.tv_sec = API_HTTP_SOCK_TIMEOUT_S;
    tv.tv_usec = 0;
#endif
    if (setsockopt(s, SOL_SOCKET, SO_RCVTIMEO,
                   reinterpret_cast<const char *>(&tv), sizeof(tv)) < 0)
        applog(LOG_DEBUG, "API SO_RCVTIMEO failed (ignored): %s", sock_error());
    if (setsockopt(s, SOL_SOCKET, SO_SNDTIMEO,
                   reinterpret_cast<const char *>(&tv), sizeof(tv)) < 0)
        applog(LOG_DEBUG, "API SO_SNDTIMEO failed (ignored): %s", sock_error());
}

sock_t open_listener(const char *addr, unsigned short port)
{
    struct sockaddr_in serv;
    memset(&serv, 0, sizeof(serv));
    serv.sin_family = AF_INET;
    serv.sin_port = htons(port);
    serv.sin_addr.s_addr = inet_addr(addr);
    if (serv.sin_addr.s_addr == INADDR_NONE) {
        applog(LOG_ERR, "API not started: '%s' is not an address to bind to",
               addr);
        return kNoSock;
    }

    sock_t s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == kNoSock) {
        applog(LOG_ERR, "API socket failed (%s); the API is off", sock_error());
        return kNoSock;
    }

#ifndef _WIN32
    int one = 1;
    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
                   reinterpret_cast<const char *>(&one), sizeof(one)) < 0)
        applog(LOG_DEBUG, "API SO_REUSEADDR failed (ignored): %s", sock_error());
#endif

    for (int try_no = 0; try_no <= kBindRetries; try_no++) {
        if (bind(s, reinterpret_cast<struct sockaddr *>(&serv), sizeof(serv)) == 0) {
            if (listen(s, 8) == 0)
                return s;
            applog(LOG_ERR, "API listen on port %u failed (%s); the API is off",
                   static_cast<unsigned>(port), sock_error());
            sock_close(s);
            return kNoSock;
        }
        if (try_no == kBindRetries)
            break;
        applog(LOG_WARNING, "API port %u is in use (%s); retrying in %ds",
               static_cast<unsigned>(port), sock_error(), kBindRetryS);
        for (int i = 0; i < kBindRetryS && !g_shutdown; i++)
            sleep(1);
        if (g_shutdown) {
            sock_close(s);
            return kNoSock;
        }
    }

    applog(LOG_ERR, "API bind to port %u failed (%s); the API is off",
           static_cast<unsigned>(port), sock_error());
    sock_close(s);
    return kNoSock;
}

void serve_one(sock_t c)
{
    size_t nroutes = 0;
    const api_route *routes = api_routes_get(&nroutes);
    char *miner_json = api_routes_miner_json_str();

    api_http_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.token = opt_api_token;
    cfg.cors = opt_api_cors != nullptr;
    cfg.miner_json = miner_json;

    // --api-control is what promotes a writing source to a controlling one, so
    // the control verbs need both flags and the transport answers 403 before a
    // handler runs. --api-remote is the write gate on its own: opt_api_allow is
    // the bind address despite the name, so what may reach this port at all is
    // decided by the kernel and not by anything here.
    cfg.control_enabled = vkminer::control_enabled();
    cfg.granted = opt_api_remote
                      ? (cfg.control_enabled ? API_PRIV_CONTROL : API_PRIV_WRITE)
                      : API_PRIV_READ;

    api_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));

    api_http_serve(static_cast<int>(c), routes, nroutes, &ctx, &cfg);
    free(miner_json);

    // Read after the response has been written, which is the whole point of
    // /quit setting a flag rather than shutting the miner down itself: the
    // client sees its 200 instead of a socket that closed mid-answer.
    if (ctx.quit_requested) {
        applog(LOG_NOTICE, "Shutdown requested through the API");
        g_shutdown = VKMINER_SHUTDOWN_API;
    }
}

}  // namespace

extern "C" void *api_thread(void *userdata)
{
    (void)userdata;

#ifdef _WIN32
    // curl_global_init has already done this by the time the thread starts,
    // but WSAStartup is reference-counted and this file should not depend on
    // the order main brings its subsystems up in.
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    const char *addr = opt_api_allow ? opt_api_allow : "127.0.0.1";
    const unsigned short port = static_cast<unsigned short>(opt_api_listen);

    sock_t listener = open_listener(addr, port);
    if (listener == kNoSock)
        return nullptr;

    applog(LOG_INFO, "REST API on http://%s:%d/api/v1/ (%s)", addr,
           opt_api_listen, opt_api_token ? "token" : "no token");
    if (opt_api_remote && !opt_api_token)
        applog(LOG_WARNING, "REST API write access (--api-remote) is enabled "
                            "without --api-token");
    // The bind address is the whole access control, so an address other than
    // loopback is worth saying out loud rather than leaving in a --help line.
    if (strcmp(addr, "127.0.0.1") != 0)
        applog(LOG_WARNING, "REST API is bound to %s, so anything that can "
                            "route to this host can reach it", addr);

    while (!g_shutdown) {
        fd_set rd;
        struct timeval tv;
        FD_ZERO(&rd);
        FD_SET(listener, &rd);
        tv.tv_sec = kAcceptPollS;
        tv.tv_usec = 0;

        const int ready = select(static_cast<int>(listener) + 1, &rd, nullptr,
                                 nullptr, &tv);
        if (ready == 0)
            continue;
        if (ready < 0) {
#ifndef _WIN32
            if (errno == EINTR)
                continue;
#endif
            applog(LOG_ERR, "API select failed (%s); the API is off",
                   sock_error());
            break;
        }

        struct sockaddr_in cli;
        socklen_t clilen = sizeof(cli);
        sock_t c = accept(listener, reinterpret_cast<struct sockaddr *>(&cli),
                          &clilen);
        if (c == kNoSock) {
#ifndef _WIN32
            if (errno == EINTR || errno == ECONNABORTED)
                continue;
#endif
            applog(LOG_DEBUG, "API accept failed (%s)", sock_error());
            continue;
        }

        set_sock_timeouts(c);
        serve_one(c);
        sock_close(c);
    }

    sock_close(listener);
    return nullptr;
}
