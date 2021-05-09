/*
       IDA remote debugger server
*/
#include "server.h"
#include "dbg_rpc_handler.h"
#include "dosbox_debmod.h"

#include <thread>
#include <barrier>
#include <memory>

std::unique_ptr<std::barrier<>> sync_point;
std::atomic_bool sync_req;
std::thread server_thread;
static bool g_server_running;

//--------------------------------------------------------------------------
// SERVER GLOBAL VARIABLES
#ifdef __SINGLE_THREADED_SERVER__
dbgsrv_dispatcher_t dispatcher(false);

static bool init_lock(void) { return true; }
bool lock_begin(void) { return true; }
bool lock_end(void) { return true; }
#else
dbgsrv_dispatcher_t dispatcher(true);

static qmutex_t g_mutex = NULL;
static bool init_lock(void) { g_mutex = qmutex_create(); return g_mutex != NULL; }
bool lock_begin(void) { return qmutex_lock(g_mutex); }
bool lock_end(void) { return qmutex_unlock(g_mutex); }
#endif

//--------------------------------------------------------------------------
dbg_rpc_handler_t* g_global_server = NULL;

//-------------------------------------------------------------------------
dbgsrv_dispatcher_t::dbgsrv_dispatcher_t(bool multi_threaded)
    : base_dispatcher_t(multi_threaded),
    broken_conns_supported(false),
    on_broken_conn(BCH_DEFAULT)
{
    port_number = DEBUGGER_PORT_NUMBER;
}

//-------------------------------------------------------------------------
client_handler_t* dbgsrv_dispatcher_t::new_client_handler(idarpc_stream_t* _irs)
{
    dbg_rpc_handler_t* h = new dbg_rpc_handler_t(_irs, this);
    h->verbose = verbose;
    void* params = NULL;
    h->set_debugger_instance(create_debug_session(params));
    g_global_server = h;
    return h;
}

//-------------------------------------------------------------------------
void dbgsrv_dispatcher_t::shutdown_gracefully(int signum)
{
    base_dispatcher_t::shutdown_gracefully(signum);
    term_subsystem();
}

int idados_init()
{
#ifdef ENABLE_LOWCNDS
    init_idc();
#endif

    // call the debugger module to initialize its subsystem once
    if (!init_lock() || !init_subsystem())
    {
        lprintf("Could not initialize subsystem!");
        return -1;
    }
    sync_point.reset(new std::barrier(2));
    sync_req = false;
    g_server_running = false;

    dispatcher.server_password = "";

    dispatcher.broken_conns_supported = dosbox_debmod_t::reuse_broken_connections;
    dispatcher.install_signal_handlers();
    server_thread = std::thread(&dbgsrv_dispatcher_t::dispatch, &dispatcher);

    return 1;
}

void idados_term()
{
    sync_point->arrive_and_drop();
    dispatcher.shutdown_gracefully(0);
    if (server_thread.joinable())
    {
        server_thread.join();
    }
}

void idados_stopped()
{
    g_server_running = false;
}

void idados_running()
{
    g_server_running = true;
}

bool idados_is_running()
{
    return g_server_running;
}

void idados_hit_breakpoint(PhysPt addr)
{
    if (!g_global_server)
    {
        return;
    }

    dosbox_debmod_t *dm = (dosbox_debmod_t *)g_global_server->get_debugger_instance();
  
    dm->hit_breakpoint(addr);

    idados_stopped();
}

void idados_sync()
{
    sync_point->arrive_and_wait();
}

void idados_try_sync()
{
    if (sync_req)
    {
        idados_sync();
        sync_req = false;
        idados_sync();
    }
}

void idados_sync_request()
{
    sync_req = true;
    idados_sync();
}

bool idados_is_sync_requested()
{
    return sync_req;
}