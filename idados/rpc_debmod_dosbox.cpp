#include "typeinf.hpp"

#include "pc_regs.hpp"

#include "rpc_debmod_dosbox.h"

ea_t idaapi rpc_debmod_dosbox_t::map_address(ea_t ea, const regval_t *regs, int regnum)
{
 ea_t mapped_ea = ea;

 if(regs)
 {
   switch(regnum)
   {
     case R_EIP : mapped_ea = (regs[R_CS].ival<<4) + regs[R_EIP].ival; break;
     case R_ESP : mapped_ea = (regs[R_SS].ival<<4) + regs[R_ESP].ival; break;
     case R_EBP : mapped_ea = (regs[R_SS].ival<<4) + regs[R_EBP].ival; break;
	 case R_ESI : mapped_ea = (regs[R_DS].ival<<4) + regs[R_ESI].ival; break;
	 case R_EDI : mapped_ea = (regs[R_DS].ival<<4) + regs[R_EDI].ival; break;

     case R_CS : mapped_ea = (regs[R_CS].ival<<4); break;
     case R_DS : mapped_ea = (regs[R_DS].ival<<4); break;
     case R_SS : mapped_ea = (regs[R_SS].ival<<4); break;
     case R_ES : mapped_ea = (regs[R_ES].ival<<4); break;
   }
 }

  return mapped_ea;
}