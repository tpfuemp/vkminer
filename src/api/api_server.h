// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The API thread: one listener, one blocking accept, one request per
// connection. Started by main like every other thr_info thread.

#ifndef VKMINER_API_API_SERVER_H__
#define VKMINER_API_API_SERVER_H__

#ifdef __cplusplus
extern "C" {
#endif

// thread_create() entry point. Takes the thr_info the way the inherited
// threads do, and returns when the listener could not be opened or when the
// miner is shutting down.
void *api_thread(void *userdata);

#ifdef __cplusplus
}
#endif

#endif  // VKMINER_API_API_SERVER_H__
