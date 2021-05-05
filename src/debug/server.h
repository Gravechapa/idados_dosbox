#ifndef SERVER_H
#define SERVER_H
/*
       IDA Pro remote debugger server
*/

#include <network.hpp>
#include "mem.h"

#include <semaphore>
#include <memory>

#define __SINGLE_THREADED_SERVER__

enum broken_conn_hndl_t
{
    BCH_DEFAULT,
    BCH_KEEP_DEBMOD,
    BCH_KILL_PROCESS,
};

struct dbgsrv_dispatcher_t : public base_dispatcher_t
{
    qstring server_password;
    bool broken_conns_supported;
    broken_conn_hndl_t on_broken_conn;

    dbgsrv_dispatcher_t(bool multi_threaded);

//    virtual void collect_cliopts(cliopts_t* out) override;
    virtual client_handler_t* new_client_handler(idarpc_stream_t* irs) override;

    virtual void shutdown_gracefully(int signum) override;
};

// // sizeof(ea_t)==8 and sizeof(size_t)==4 servers cannot be used to debug 64-bit
// // applications. but to debug 32-bit applications, simple 32-bit servers
// // are enough and can work with both 32-bit and 64-bit versions of ida.
// // so, there is no need to build sizeof(ea_t)==8 and sizeof(size_t)==4 servers
// #if defined(__EA64__) == defined(__X86__)
// #error "Mixed mode servers do not make sense, they should not be compiled"
// #endif

extern std::unique_ptr<std::binary_semaphore> idados_sync;

int idados_init();
void idados_term();
//int idados_handle_command();
void idados_hit_breakpoint(PhysPt addr);
void idados_stopped();
void idados_running();
bool idados_is_running();

#endif