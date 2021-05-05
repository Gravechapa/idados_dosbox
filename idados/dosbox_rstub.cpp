#define REMOTE_DEBUGGER
#define RPC_CLIENT

char wanted_name[] = "Remote DOSBox debugger";
#define DEBUGGER_NAME  "dosbox"
#define PROCESSOR_NAME "metapc"
#define TARGET_PROCESSOR PLFM_386
#define DEBUGGER_ID    DEBUGGER_ID_X86_DOSBOX_EMULATOR
#define DEBUGGER_FLAGS DBG_FLAG_REMOTE | DBG_FLAG_USE_SREGS
#define DEBUGGER_RESMOD (DBG_RESMOD_STEP_INTO)

#include <pro.h>
#include <idp.hpp>
#include <idd.hpp>
#include <ua.hpp>
#include <range.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <network.hpp>

#include "dbg_rpc_client.h"
#include "rpc_debmod_dosbox.h"

rpc_debmod_dosbox_t g_dbgmod;
#include "common_stub_impl.cpp"

#define HAVE_MAP_ADDRESS

#include "pc_local_impl.cpp"
#include "dosbox_local_impl.cpp"
#include "common_local_impl.cpp"
