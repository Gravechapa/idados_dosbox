#ifndef __DOSBOX_DEBUGGER_MODULE__
#define __DOSBOX_DEBUGGER_MODULE__

#include <map>
#include <set>

#include "mem.h"

#include "pc_debmod.h"

#ifndef __NT__
typedef int HANDLE;
#endif

struct bpt_info_t
{
    int bid;              // breakpoint id (from TRK)
    int cnt;              // number of times ida kernel added the bpt
    bpt_info_t(int b, int c) : bid(b), cnt(c) {}
};

typedef std::map<ea_t, bpt_info_t> bpts_t;

class dosbox_debmod_t: public pc_debmod_t
{

    typedef pc_debmod_t inherited;

    ea_t entry_point;
    ea_t app_base;
    ea_t stack;

    void cleanup();
    void create_process_start_event(const char *path);

public:
    qstring process_name;            // current process name
    typedef std::map<int, bool> stepping_t; // tid->stepping
    stepping_t stepping;             // tid->stepping

    // debugged process information
    eventlist_t events;              // Pending events
    bool exited;                     // Process has exited

    bpts_t bpts;                     // breakpoint list

    static bool reuse_broken_connections;

    dosbox_debmod_t();
    ~dosbox_debmod_t();

    const exception_info_t *find_exception_by_desc(const char *desc) const;

    virtual void idaapi dbg_set_debugging(bool _debug_debugger) override;
    virtual drc_t idaapi dbg_init(uint32_t* flags2, qstring* errbuf) override;
    virtual void idaapi dbg_term() override;
    virtual drc_t idaapi dbg_get_processes(procinfo_vec_t* info, qstring* errbuf) override;
    virtual drc_t  idaapi dbg_detach_process() override;
    virtual drc_t idaapi dbg_start_process(
        const char* path,
        const char* args,
        const char* startdir,
        int flags,
        const char* input_path,
        uint32 input_file_crc32,
        qstring* errbuf) override;
    virtual gdecode_t  idaapi dbg_get_debug_event(debug_event_t *event, int timeout_ms) override;
    virtual drc_t idaapi dbg_attach_process(pid_t process_id, int event_id, int flags, qstring* errbuf) override;
    virtual drc_t idaapi dbg_prepare_to_pause_process(qstring* errbuf) override;
    virtual drc_t idaapi dbg_exit_process(qstring* errbuf) override;
    virtual drc_t idaapi dbg_continue_after_event(const debug_event_t* event) override;
    virtual void idaapi dbg_stopped_at_debug_event(import_infos_t* infos, bool dlls_added, thread_name_vec_t* thr_names) override;
    virtual drc_t  idaapi dbg_thread_suspend(thid_t thread_id) override;
    virtual drc_t  idaapi dbg_thread_continue(thid_t thread_id) override;
    virtual drc_t  idaapi dbg_set_resume_mode(thid_t thread_id, resume_mode_t resmod) override;
    virtual drc_t idaapi dbg_read_registers(
        thid_t thread_id,
        int clsmask,
        regval_t* values,
        qstring* errbuf) override;
    virtual drc_t idaapi dbg_write_register(
        thid_t thread_id,
        int reg_idx,
        const regval_t* value,
        qstring* errbuf) override;
    virtual drc_t idaapi dbg_thread_get_sreg_base(ea_t* ea, thid_t thread_id, int sreg_value, qstring* errbuf) override;
    virtual drc_t idaapi dbg_get_memory_info(meminfo_vec_t& ranges, qstring* errbuf) override;
    virtual ssize_t idaapi dbg_read_memory(ea_t ea, void* buffer, size_t size, qstring* errbuf) override;
    virtual ssize_t idaapi dbg_write_memory(ea_t ea, const void* buffer, size_t size, qstring* errbuf) override;
    virtual int idaapi dbg_add_bpt(bytevec_t* orig_bytes, bpttype_t type, ea_t ea, int len) override;
    virtual int  idaapi dbg_del_bpt(bpttype_t type, ea_t ea, const uchar *orig_bytes, int len) override;
    virtual int  idaapi dbg_open_file(const char *file, uint64 *fsize, bool readonly) override;
    virtual void idaapi dbg_close_file(int fn) override;
    virtual ssize_t idaapi dbg_read_file(int fn, qoff64_t off, void *buf, size_t size) override;
    virtual ssize_t idaapi dbg_write_file(int fn, qoff64_t off, const void *buf, size_t size) override;
    virtual int idaapi get_system_specific_errno() const override;
    virtual bool refresh_hwbpts() override;
    virtual HANDLE get_thread_handle(thid_t tid) override;
    virtual int idaapi dbg_is_ok_bpt(bpttype_t type, ea_t ea, int len) override;

    bool idaapi close_remote();
    bool idaapi open_remote(const char * /*hostname*/, int port_number, const char * /*password*/);

    bool hit_breakpoint(PhysPt addr);
};

debmod_t *create_debug_session(void*);
bool term_subsystem();
bool init_subsystem();

#define DOSBOX_DEBUGGER_NODE "$ dosbox debugger"  // netnode name to save memory region
                                              // information
#define MEMREG_TAG 'R'                        // blob tag

#endif
