/*
       IDA remote debugger server
*/
#include "server.h"
#include "dbg_rpc_handler.h"
#include "dosbox_debmod.h"

#include <thread>

std::unique_ptr<std::binary_semaphore> idados_sync;
std::thread* server_thread = NULL;
static  bool g_server_running = false;

//lint -esym(714, dump_udt) not referenced
void dump_udt(const char*, const struct udt_type_data_t&) {}

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
    idados_sync.reset(new std::binary_semaphore(1));
    dispatcher.server_password = "";

    dispatcher.broken_conns_supported = dosbox_debmod_t::reuse_broken_connections;
    dispatcher.install_signal_handlers();
    server_thread = new std::thread(&dbgsrv_dispatcher_t::dispatch, &dispatcher);

    return 1;
}

bool DEBUG_RemoteDataReady(void) //FIXME need to rework this.
{
    if (g_global_server)
    {
        return irs_ready(g_global_server->irs, 1); //wait 1 millisecond.
    }

    return false;
}

void idados_term()
{
    dispatcher.shutdown_gracefully(0);
    if (server_thread->joinable())
    {
        server_thread->join();
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