/*
 *      ALLEGREX module for the Interactive disassembler (IDA).
 *
 *      based on pspdis, written by xor37h/Hitmen
 *
 *      updates, fixes and bugreports welcomed (you know where i am)
 *
 *      (w)2006 by Groepaz/Hitmen
 */
 
#include "allegrex.hpp"

static bool flow;               // does the current instruction pass
                                // execution to the next instruction?

//------------------------------------------------------------------------
// Handle an operand with an immediate value:
//      - mark it with FF_IMMD flag
//      - for bit logical instructions specify the operand type as a number
//        because such an operand is likely a plain number rather than
//        an offset or of another type.

static void doImmdValue(int n)
{
  doImmd(cmd.ea);
  switch ( cmd.itype )
  {
    case ALLEGREX_and:
    case ALLEGREX_or:
    case ALLEGREX_xor:
      op_num(cmd.ea,1);
//      op_num(cmd.ea,n);
      break;
//    case ALLEGREX_mov:
//      op_dec(cmd.ea, n);
//      break;
  }
  uFlag = getFlags(cmd.ea);             // refresh uFlag with new flags
}

//----------------------------------------------------------------------
static void attach_bit_comment(int addr, int bit)
{
  const ioport_bit_t *predef = find_bit(addr, bit);
  if ( predef != NULL && get_cmt(cmd.ea, false, NULL, 0) == NULL )
    set_cmt(cmd.ea, predef->cmt, false);
}

//----------------------------------------------------------------------
// Calculate the target data address
ea_t map_addr(ulong off, int opnum, bool isdata)
{
#if 0	
  if ( isdata ) 
  {
    if ( isOff(uFlag, opnum) ) return get_offbase(cmd.ea, opnum) >> 4;
    return ((off >= 0x80 && off < 0x100) ? sfrmem : intmem) + off;
  }
#endif
  return toEA(codeSeg(off, opnum), off);
}

//----------------------------------------------------------------------
// Handle an operand. What this function usually does:
//      - creates cross-references from the operand
//        (the kernel deletes all xrefs before calling emu())
//      - creates permanent comments
//      - if possible, specifies the operand type (for example, it may
//        create stack variables)
//      - anything else you might need to emulate or trace

static void handle_operand(op_t &x,int loading /* 1: use 0: change */)
{
  switch ( x.type )
  {
    case o_phrase:              // no special hanlding for these types
    case o_reg:
    case o_vfpucond:
      break;

    case o_imm:                         // an immediate number as an operand
      if ( !loading ) goto BAD_LOGIC;   // this can't happen!
      doImmdValue(x.n);                    // handle immediate number

      // if the value was converted to an offset, then create a data xref:
        if ( isOff(uFlag, x.n) )
	{
 		ua_add_off_drefs(x, dr_O);
	}
	// if the value is in range of the program, create a data xref:
	else //if(isEnabled(x.n))
	{
		ua_add_dref(0,x.value, loading?dr_R:dr_W);
	}

      break;

    case o_displ:
      doImmdValue(x.n);                    // handle immediate number

      // if the value was converted to an offset, then create a data xref:
      if ( isOff(uFlag, x.n) ) ua_add_off_drefs(x, loading?dr_R:dr_W);
      break;

    case o_bit:                         // 8051 specific operand types - bits
//    case o_bitnot:
      x.addr = (x.reg & 0xF8);
      if( (x.addr & 0x80) == 0 ) x.addr = x.addr/8 + 0x20;
      attach_bit_comment(x.addr, x.reg & 7);  // attach a comment if necessary
//      goto MEM_XREF;

//    case o_bit251:
//      attach_bit_comment(x.addr, x.b251_bit);
      /* no break */

    case o_mem:                         // an ordinary memory data reference
MEM_XREF:
      {
        ea_t dea = map_addr(x.addr, x.n, true);
        ua_dodata(dea, x.dtyp);
        if ( !loading ) doVar(dea);     // write access
        ua_add_dref(x.offb, dea, loading ? dr_R : dr_W);
      }
      break;

    case o_near:                        // a code reference
      {
        ea_t ea = map_addr(x.addr, x.n, false);
        int iscall = InstrIsSet(cmd.itype, CF_CALL);
        ua_add_cref(x.offb, ea, iscall ? fl_CN : fl_JN);
        if ( flow && iscall )
        {
          func_t *pfn = get_func(ea);
          if ( pfn != NULL && (pfn->flags & FUNC_NORET) ) flow = false;
        }
      }
      break;

    default:
BAD_LOGIC:
//	warning("%a (%s): bad logic (emu.cpp)", cmd.ea, Instructions[cmd.itype].name);
	msg("%a (%s): bad logic (emu.cpp)", cmd.ea, Instructions[cmd.itype].name);
      break;
  }
}

//----------------------------------------------------------------------
// Emulate an instruction
// This function should:
//      - create all xrefs from the instruction
//      - perform any additional analysis of the instruction/program
//        and convert the instruction operands, create comments, etc.
//      - create stack variables
//      - analyse the delayed branches and similar constructs
// The kernel calls ana() before calling emu(), so you may be sure that
// the 'cmd' structure contains a valid and up-to-date information.
// You are not allowed to modify the 'cmd' structure.
// Upon entering this function, the 'uFlag' variable contains the flags of
// cmd.ea. If you change the characteristics of the current instruction, you
// are required to refresh 'uFlag'.
// Usually the kernel calls emu() with consecutive addresses in cmd.ea but
// you can't rely on this - for example, if the user asks to analyse an
// instruction at arbirary address, his request will be handled immediately,
// thus breaking the normal sequence of emulation.
// If you need to analyse the surroundings of the current instruction, you
// are allowed to save the contents of the 'cmd' structure and call ana().
// For example, this is a very common pattern:
//  {
//    insn_t saved = cmd;
//    if ( decode_prev_insn(cmd.ea) != BADADDR )
//    {
//      ....
//    }
//    cmd = saved;
//  }
//
// This sample emu() function is a very simple emulation engine.

int emu(void)
{
  int Feature = Instructions[cmd.itype].feature;
  flow = ((Feature & CF_STOP) == 0);

  // you may emulate selected instructions with a greater care:
  switch ( cmd.itype )
  {
//    case ALLEGREX_mov:
//      if ( cmd.Op1.type == o_mem && cmd.Op1.addr == 0x81 )  // mov SP, #num
//      {
//        if ( cmd.Op2.type == o_imm && !isDefArg(uFlag,1) )
//          set_offset(cmd.ea,1,intmem);             // convert it to an offset
//      }
//      break;
//    case ALLEGREX_trap:
//      ua_add_cref(0, 0x7B, fl_CN);
//      break;
  }

  if ( Feature & CF_USE1 ) handle_operand(cmd.Op1, 1);
  if ( Feature & CF_USE2 ) handle_operand(cmd.Op2, 1);
  if ( Feature & CF_USE3 ) handle_operand(cmd.Op3, 1);
  if ( Feature & CF_USE4 ) handle_operand(cmd.Op4, 1);
  if ( Feature & CF_JUMP ) QueueMark(Q_jumps,cmd.ea);

  if ( Feature & CF_CHG1 ) handle_operand(cmd.Op1, 0);
  if ( Feature & CF_CHG2 ) handle_operand(cmd.Op2, 0);
  if ( Feature & CF_CHG3 ) handle_operand(cmd.Op3, 0);
  if ( Feature & CF_CHG4 ) handle_operand(cmd.Op4, 0);

#if 1
  {
    // stop if the last instruction was a jump with delay slot	
    insn_t saved = cmd;
    if ( decode_prev_insn(cmd.ea) != BADADDR )
    {
//	  int Feature = Instructions[cmd.itype].feature;
//	  if (( Feature & CF_JUMP )||( Feature & CF_CALL ))
	  if (( cmd.itype == ALLEGREX_j ) || ( cmd.itype == ALLEGREX_jr ))
		{
		 flow=0;	
//		msg("feat: %08x itype: %08x\n",Feature,cmd.itype);
		}
    }
    cmd = saved;
  }
#endif

  // if the execution flow is not stopped here, then create
  // a xref to the next instruction.
  // Thus we plan to analyse the next instruction.

  if ( flow )
  {
	  ua_add_cref(0,cmd.ea+cmd.size,fl_F);
  }

  return 1;    // actually the return value is unimportant, but let's it be so
}
