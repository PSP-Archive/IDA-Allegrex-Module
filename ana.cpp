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


// Structure for decoded instruction
typedef struct
{
    unsigned long  opcode;  // all bits
    unsigned char  op;      // bits 31-26
    unsigned char  rs;      // bits 25-21
    unsigned char  rt;      // bits 20-16
    unsigned char  rd;      // bits 15-11
    unsigned char  shamt;   // bits 10-6
    unsigned char  funct;   // bits 5-0
    unsigned short imm;     // bits 15-0
    unsigned long  target;  // bits 25-0
    unsigned long  code;    // bits 6-26
} Instr;

struct VInstr
{
    unsigned long  imm;
    unsigned short offs;
    unsigned char  vt;
    unsigned char  vs;
    unsigned char  vd;
    unsigned char  vc;
    unsigned char  cond;
    unsigned char  bit1;
    unsigned char  bit7;
    unsigned char  bit15;
    unsigned char  funct2;
    unsigned char  funct3;
    unsigned char  funct7;
    unsigned short funct11;
    unsigned long  funct19;
} VInstr;

typedef struct Opcode Opcode;

struct Opcode
{
//    char *mnemonic;
    int mnemonic;
    void (*f)(Opcode *, Instr *);
    char *fmt1;
    char *fmt2;
    char *fmt3;
    char *fmt4;
    unsigned long flags;
};

static void op_code_0(Opcode *, Instr *);
static void op_code_1(Opcode *, Instr *);
static void op_code_16(Opcode *, Instr *);
static void op_code_17(Opcode *, Instr *);
static void op_code_28(Opcode *, Instr *);
static void op_code_31(Opcode *, Instr *);
static void abs_jump(Opcode *, Instr *);
static void rel_branch(Opcode *, Instr *);
static void rt_rs_imm(Opcode *, Instr *);
static void rt_imm(Opcode *, Instr *);
static void rt_offs_base(Opcode *, Instr *);
static void ft_offs_base(Opcode *, Instr *);
static void cache_func(Opcode *, Instr *);
static void op_VFPU_18(Opcode *, Instr *);
static void op_VFPU_24(Opcode *, Instr *);
static void op_VFPU_25(Opcode *, Instr *);
static void op_VFPU_27(Opcode *, Instr *);
static void op_VFPU_52(Opcode *, Instr *);
static void op_VFPU_53(Opcode *, Instr *);
static void op_VFPU_54(Opcode *, Instr *);
static void op_VFPU_55(Opcode *, Instr *);
static void op_VFPU_60(Opcode *, Instr *);
static void op_VFPU_61(Opcode *, Instr *);
static void op_VFPU_62(Opcode *, Instr *);
static void op_VFPU_63(Opcode *, Instr *);
static void vt_offs_rs(Opcode *, Instr *);

unsigned long SIMFLAG=(
SIM_DROP_RT0|
SIM_DROP_RS0|
SIM_DROP_RSONRTEQRS|
SIM_DROP_OFFS0|
SIM_DROP_RSONRDEQRS|
SIM_DROP_RTONRDEQRT|
SIM_REN_LIONRS0|
SIM_REN_MOVONRT0|
SIM_REN_LI0ONRT0RS0|
SIM_RSIMMONRT0RS0|
SIM_NAMEDREGS|
SIM_NAMEDREGS_FPU|
SIM_NAMEDREGS_COP0|
SIM_NAMEDREGS_COP1|
SIM_NAMEDREGS_COP2|
SIM_NAMEDREGS_VFPU|
SIM_NAMEDREGS_DEBUG
);

static Opcode opcodes[64] = 
{
    {   0,              op_code_0,      0               ,0},  // 00
    {   0,              op_code_1,      0               ,0},  // 01
    {   ALLEGREX_j,            abs_jump,       "%a","","",""            ,0},  // 02
    {   ALLEGREX_jal,          abs_jump,       "%a","","",""            ,0},  // 03
    {   ALLEGREX_beq,          rel_branch,     "%rs","%rt","%b",""  ,SIM_DROP_RT0},  // 04
    {   ALLEGREX_bne,          rel_branch,     "%rs","%rt","%b" ,"" ,SIM_DROP_RT0},  // 05
    {   ALLEGREX_blez,         rel_branch,     "%rs","%b"   ,"",""    ,0},  // 06
    {   ALLEGREX_bgtz,         rel_branch,     "%rs","%b"   ,"",""    ,0},  // 07
    {   ALLEGREX_addi,         rt_rs_imm,      "%rt","%rs","%i" ,"" ,SIM_DROP_RSONRTEQRS|SIM_DROP_RS0|SIM_REN_LIONRS0},  // 08
    {   ALLEGREX_addiu,        rt_rs_imm,      "%rt","%rs","%i" ,"" ,SIM_DROP_RSONRTEQRS|SIM_DROP_RS0|SIM_REN_LIONRS0},  // 09
    {   ALLEGREX_slti,         rt_rs_imm,      "%rt","%rs","%i",""  ,0},  // 10
    {   ALLEGREX_sltiu,        rt_rs_imm,      "%rt","%rs","%i" ,"" ,0},  // 11
    {   ALLEGREX_andi,         rt_rs_imm,      "%rt","%rs","%i" ,"" ,SIM_DROP_RSONRTEQRS},  // 12
    {   ALLEGREX_ori,          rt_rs_imm,      "%rt","%rs","%i" ,"" ,SIM_DROP_RSONRTEQRS|SIM_DROP_RS0},  // 13
    {   ALLEGREX_xori,         rt_rs_imm,      "%rt","%rs","%i" ,"" ,SIM_DROP_RSONRTEQRS|SIM_DROP_RS0},  // 14
    {   ALLEGREX_lui,          rt_imm,         "%rt","%I","",""       ,0},  // 15
//    {   ALLEGREX_li,          rt_imm,         "%rt","%i0000" ,"",""      ,0},  // 15
    {   0,              op_code_16,     0               ,0},  // 16
    {   0,              op_code_17,     0               ,0},  // 17
    {   0,              op_VFPU_18,     0               ,0},  // 18
    {   0,              0,              0               ,0},  // 19
    {   ALLEGREX_beql,         rel_branch,     "%rs","%rt","%b" ,"" ,SIM_DROP_RT0},  // 20
    {   ALLEGREX_bnel,         rel_branch,     "%rs","%rt","%b" ,"" ,SIM_DROP_RT0},  // 21
    {   ALLEGREX_blezl,        rel_branch,     "%rs","%b"   ,"",""    ,0},  // 22
    {   ALLEGREX_bgtzl,        rel_branch,     "%rs","%b"   ,"",""    ,0},  // 23
    {   0,              op_VFPU_24,     0               ,0},  // 24
    {   0,              op_VFPU_25,     0               ,0},  // 25
    {   0,              0,              0               ,0},  // 26
    {   0,              op_VFPU_27,     0               ,0},  // 27
    {   0,              op_code_28,     0               ,0},  // 28
    {   0,              0,              0               ,0},  // 29
    {   0,              0,              0               ,0},  // 30
    {   0,              op_code_31,     0               ,0},  // 31
    {   ALLEGREX_lb,           rt_offs_base,   "%rt","%o(%rs)" ,"","" ,0},  // 32
    {   ALLEGREX_lh,           rt_offs_base,   "%rt","%o(%rs)" ,"","" ,0},  // 33
    {   ALLEGREX_lwl,          rt_offs_base,   "%rt","%o(%rs)" ,"","" ,0},  // 34
    {   ALLEGREX_lw,           rt_offs_base,   "%rt","%o(%rs)" ,"","" ,SIM_DROP_OFFS0},  // 35
    {   ALLEGREX_lbu,          rt_offs_base,   "%rt","%o(%rs)" ,"","" ,0},  // 36
    {   ALLEGREX_lhu,          rt_offs_base,   "%rt","%o(%rs)" ,"","" ,0},  // 37
    {   ALLEGREX_lwr,          rt_offs_base,   "%rt","%o(%rs)" ,"","" ,0},  // 38
    {   0,              0,              0               ,0},  // 39
    {   ALLEGREX_sb,           rt_offs_base,   "%rt","%o(%rs)" ,"","" ,0},  // 40
    {   ALLEGREX_sh,           rt_offs_base,   "%rt","%o(%rs)" ,"","" ,0},  // 41
    {   ALLEGREX_swl,          rt_offs_base,   "%rt","%o(%rs)" ,"","" ,0},  // 42
    {   ALLEGREX_sw,           rt_offs_base,   "%rt","%o(%rs)" ,"","" ,SIM_DROP_OFFS0},  // 43
    {   0,              0,              0               ,0},  // 44
    {   0,              0,              0               ,0},  // 45
    {   ALLEGREX_swr,          rt_offs_base,   "%rt","%o(%rs)" ,"","" ,0},  // 46
    {   ALLEGREX_cache,        cache_func,     "%l","%o(%rs)" ,"",""  ,0},  // 47
    {   ALLEGREX_ll,           rt_offs_base,   "%rt","%o(%rs)","",""  ,0},  // 48
    {   ALLEGREX_lwc1,         ft_offs_base,   "%ft","%o(%rs)" ,"","" ,0},  // 49
    {   ALLEGREX_lv_s,         vt_offs_rs,     "%vt","%vo(%rs)","","" ,0},  // 50
    {   0,              0,              0               ,0},  // 51
    {   0,              op_VFPU_52,     0               ,0},  // 52
    {   0,              op_VFPU_53,     0               ,0},  // 53
    {   0,              op_VFPU_54,     0               ,0},  // 54
    {   0,              op_VFPU_55,     0               ,0},  // 55
    {   ALLEGREX_sc,           rt_offs_base,   "%rt","%o(%rs)" ,"","" ,0},  // 56
    {   ALLEGREX_swc1,         ft_offs_base,   "%ft","%o(%rs)" ,"","" ,0},  // 57
    {   ALLEGREX_sv_s,         vt_offs_rs,     "%vt","%vo(%rs)","","" ,0},  // 58
    {   0,              0,              0               ,0},  // 59
    {   0,              op_VFPU_60,     0               ,0},  // 60
    {   0,              op_VFPU_61,     0               ,0},  // 61
    {   0,              op_VFPU_62,     0               ,0},  // 62
    {   0,              op_VFPU_63,     0               ,0}   // 63
};

void DecodeInst( unsigned long Cmd, Instr * Inst )
{
    Inst->opcode = (unsigned long)    Cmd;
    Inst->op     = (unsigned char)  ( Cmd >> 26 ) & 0x3F;
    Inst->rs     = (unsigned char)  ( Cmd >> 21 ) & 0x1F;
    Inst->rt     = (unsigned char)  ( Cmd >> 16 ) & 0x1F;
    Inst->rd     = (unsigned char)  ( Cmd >> 11 ) & 0x1F;
    Inst->shamt  = (unsigned char)  ( Cmd >>  6 ) & 0x1F;
    Inst->code   = (unsigned long)  ( Cmd >>  6 ) & 0xFFFFF;
    Inst->funct  = (unsigned char)  ( Cmd & 0x0000003F );
    Inst->imm    = (unsigned short) ( Cmd & 0x0000FFFF );
    Inst->target = (unsigned long)  ( Cmd & 0x03FFFFFF );
}

void DecodeVFPUInst( unsigned long Cmd )
{
    VInstr.funct2  = (unsigned char)  ( Cmd >> 24 ) & 0x03;
    VInstr.funct3  = (unsigned char)  ( Cmd >> 23 ) & 0x07;
    VInstr.funct7  = (unsigned char)  ( Cmd >> 19 ) & 0x7F;
    VInstr.funct11 = (unsigned short) ( Cmd >> 15 ) & 0x7FF;
    VInstr.funct19 = (unsigned long)  ( Cmd >>  7 ) & 0x7FFFF;
    VInstr.bit1    = (unsigned char)  ( Cmd >>  1 ) & 0x01;
    VInstr.bit7    = (unsigned char)  ( Cmd >>  7 ) & 0x01;
    VInstr.bit15   = (unsigned char)  ( Cmd >> 15 ) & 0x01;
    VInstr.vt      = (unsigned char)  ( Cmd >> 16 ) & 0x7F;
    VInstr.vs      = (unsigned char)  ( Cmd >>  8 ) & 0x7F;
    VInstr.vd      = (unsigned char)  ( Cmd & 0x7F );
}

unsigned long PC = 0x88000000;

static void format_arg(unsigned long flags,int mnemonic, Instr *i, char *fmt,op_t *Op)
{
    int pad;

    signed long Radd;
    unsigned long Aadd;

	if(fmt==NULL)
	{
		// internal error
		msg("internal problem: %s:%d addr:%08x\n",__FILE__,__LINE__,PC);
		return;
	}

	if(fmt[0]==0)
	{
		return;
	}

	if(fmt[0]=='%')
	{
		switch( fmt[1] )
		{
			case 'a':
				// calculate absolute address
				Aadd = ( PC & 0xF0000000 ) + ( i->target << 2 );
				Op->type = o_near;
				Op->addr = (unsigned int) Aadd;
			break;

                case 'b':
                    // calculate and sign-extend relative offset
                    Radd = i->imm << 2;
                    if( ( i->imm & 0x8000 ) == 0x8000 )
                        Radd |= 0xFFFC0000;
                    Radd = PC + 4 + Radd;

				Op->type = o_near;
				Op->addr = (unsigned int) Radd;
                break;

                case 'd':
/*
                    if( i->code > 9 )
                        sprintf(&al_temp[0],"0x%x", (unsigned int) i->code);
                    else
                        sprintf(&al_temp[0],"%d", (unsigned int) i->code);
                    strcat(AssemblyLine,&al_temp[0]);
*/
				Op->type = o_imm;
				Op->value = i->code;
                break;

                case 'D':	// #.. (for syscall)
				Op->type = o_imm;
				Op->value = i->code;
                break;

                case 'i':
				Op->type = o_imm;
				Op->value = i->imm;
                break;
                case 'I':
				Op->type = o_imm;
				Op->value = (unsigned long)(i->imm<<16);
                break;


		// offset
                case 'o':
#if 0
			if((flags&SIMFLAG&SIM_DROP_OFFS0)&&(i->imm==0))
			{
				// zero offset dropped
//				strcat(AssemblyLine,"<offs==0>");
			}
			else
			{
			    if( i->imm > 9 )
				sprintf(&al_temp[0],"0x%x", i->imm);
			    else
				sprintf(&al_temp[0],"%d", i->imm);
			    strcat(AssemblyLine,&al_temp[0]);
			}
#endif
			if(!strcmp("%o(%rs)",fmt))
			{
				if((flags&SIMFLAG&SIM_DROP_OFFS0)&&(i->imm==0))
				{
					// zero offset dropped
					Op->type = o_displ;
					Op->addr = 0;
					Op->reg = REGS(i->rs);
				}
				else
				{
					Op->type = o_displ;
					Op->addr = i->imm;
					Op->reg = REGS(i->rs);
				}
			}
			else
			{
				// internal error
				msg("internal problem: %s:%d\n",__FILE__,__LINE__);
			}

                break;
                

                
                case 'l':
/*
                    if( i->rt > 9 )
                        sprintf(&al_temp[0],"0x%x", i->rt);
                    else
                        sprintf(&al_temp[0],"%d", i->rt);
                    strcat(AssemblyLine,&al_temp[0]);
*/
				Op->type = o_imm;
				Op->value = i->rt;
                break;



                case 's':
/*
                    if( i->shamt > 9 )
                        sprintf(&al_temp[0],"0x%x", i->shamt);
                    else
                        sprintf(&al_temp[0],"%d", i->shamt);
                    strcat(AssemblyLine,&al_temp[0]);
*/
				Op->type = o_imm;
				Op->value = i->shamt;
                break;



                case 'z':
/*
                    if( ( i->rd+1 ) > 9 )
                        sprintf(&al_temp[0],"0x%x", i->rd+1);
                    else
                        sprintf(&al_temp[0],"%d", i->rd+1);
                    strcat(AssemblyLine,&al_temp[0]);
*/
				Op->type = o_imm;
				Op->value = i->rd+1;
                break;



                case 'x':
/*
                    if( ( ( i->rd+1 ) - i->shamt ) > 9 )
                        sprintf(&al_temp[0],"0x%x", (i->rd+1)-i->shamt);
                    else
                        sprintf(&al_temp[0],"%d", (i->rd+1)-i->shamt);
                    strcat(AssemblyLine,&al_temp[0]);
*/
				Op->type = o_imm;
				Op->value =(i->rd+1)-i->shamt;
                break;


		// cop0 M regs
                case 'c':
                    switch( fmt[2] )
                    {
                        case 's':
//                            sprintf(&al_temp[0],"%s", COP0Regs[ i->rs ]);
//                            strcat(AssemblyLine,&al_temp[0]);
			Op->type = o_reg;
			Op->reg = COP0CREGS(i->rs);
                        break;

                        case 't':
//                            sprintf(&al_temp[0],"%s", COP0Regs[ i->rt ]);
//                            strcat(AssemblyLine,&al_temp[0]);
			Op->type = o_reg;
			Op->reg = COP0CREGS(i->rt);
                        break;

                        case 'd':
//                            sprintf(&al_temp[0],"%s", COP0Regs[ i->rd ]);
//                            strcat(AssemblyLine,&al_temp[0]);
			Op->type = o_reg;
			Op->reg = COP0CREGS(i->rd);
                        break;
                    }
                break;

		// cop0 C regs
                case 'C':
                    switch( fmt[2] )
                    {
                        case 's':
//                            sprintf(&al_temp[0],"%s", COP0CRegs[ i->rs ]);
//                            strcat(AssemblyLine,&al_temp[0]);
			Op->type = o_reg;
			Op->reg = COP0CREGS(i->rs);
                        break;

                        case 't':
//                            sprintf(&al_temp[0],"%s", COP0CRegs[ i->rt ]);
//                            strcat(AssemblyLine,&al_temp[0]);
			Op->type = o_reg;
			Op->reg = COP0CREGS(i->rt);
                        break;

                        case 'd':
//                            sprintf(&al_temp[0],"%s", COP0CRegs[ i->rd ]);
//                            strcat(AssemblyLine,&al_temp[0]);
			Op->type = o_reg;
			Op->reg = COP0CREGS(i->rd);
                        break;
                    }
                break;

		// register
                case 'r':
                    switch( fmt[2] )
                    {
			// rt
                        case 't':
				if((flags&SIMFLAG&SIM_DROP_RT0)&&(i->rt==0))
				{
					// rt==0, drop rt
//					AssemblyLine[strlen(AssemblyLine)-2]=0;
//					strcat(AssemblyLine,"<rt==0>");
			Op->type = o_void;
				}
				else if((flags&SIMFLAG&SIM_DROP_RTONRDEQRT)&&(i->rd==i->rt))
				{
					// rd==rd, drop rt
//					AssemblyLine[strlen(AssemblyLine)-2]=0;
//					strcat(AssemblyLine,"<rd==rd>");
			Op->type = o_void;
				}
				else
				{
//				    sprintf(&al_temp[0],"%s", Regs[ i->rt ]);
//				    strcat(AssemblyLine,&al_temp[0]);
			Op->type = o_reg;
			Op->reg = REGS(i->rt);
  				}
                      break;
			// rs
                        case 's':
				if((flags&SIMFLAG&SIM_RSIMMONRT0RS0)&&(i->rt==0)&&(i->rs==0))
				{
//					sprintf(&al_temp[0],"%s", "0x00");
//				    strcat(AssemblyLine,&al_temp[0]);
			Op->type = o_imm;
			Op->value = 0;
				}
				else if((flags&SIMFLAG&SIM_DROP_RSONRTEQRS)&&(i->rs==i->rt))
				{
					// rs==rt, drop rs
//					AssemblyLine[strlen(AssemblyLine)-2]=0;
//				    strcat(AssemblyLine,"<rs==rt>");
			Op->type = o_void;
				}
				else if((flags&SIMFLAG&SIM_DROP_RSONRDEQRS)&&(i->rs==i->rd))
				{
					// rs==rd, drop rs
//					AssemblyLine[strlen(AssemblyLine)-2]=0;
//				    strcat(AssemblyLine,"<rs==rd>");
			Op->type = o_void;
				}
				else if((flags&SIMFLAG&SIM_DROP_RS0)&&(i->rs==0))
				{
					// rs==0, drop rs (make li command?)
//					AssemblyLine[strlen(AssemblyLine)-2]=0;
//				    strcat(AssemblyLine,"<rs==0>");
			Op->type = o_void;
				}
				else
				{
//				    sprintf(&al_temp[0],"%s", Regs[ i->rs ]);
//				    strcat(AssemblyLine,&al_temp[0]);
			Op->type = o_reg;
			Op->reg = REGS(i->rs);
				}
                        break;

                        case 'd':
/*
                            sprintf(&al_temp[0],"%s", Regs[ i->rd ]);
                            strcat(AssemblyLine,&al_temp[0]);
*/
			Op->type = o_reg;
			Op->reg = REGS(i->rd);
                        break;
                        
                        case 'b':
/*
                            sprintf(&al_temp[0],"%s", DebugRegs[i->rd  ]);
                            strcat(AssemblyLine,&al_temp[0]);
*/
			Op->type = o_reg;
			Op->reg = DEBUGREGS(i->rd);

                        break;
                    }
                break;



                case 'f':
                    switch( fmt[2] )
                    {
                        case 't':
//                            sprintf(&al_temp[0],"%s", FPURegs[ i->rt ]);
//                            strcat(AssemblyLine,&al_temp[0]);
			Op->type = o_reg;
			Op->reg = FPUREGS(i->rt);
                        break;

                        case 's':
//                            sprintf(&al_temp[0],"%s", FPURegs[ i->rd ]);
//                            strcat(AssemblyLine,&al_temp[0]);
			Op->type = o_reg;
			Op->reg = FPUREGS(i->rd);
                        break;

                        case 'd':
//                            sprintf(&al_temp[0],"%s", FPURegs[ i->shamt ]);
//                            strcat(AssemblyLine,&al_temp[0]);
			Op->type = o_reg;
			Op->reg = FPUREGS(i->shamt);
                        break;
                    }
                break;

                case 'v':
                    switch( fmt[2] )
                    {
                        case 'i':
//                            if( VInstr.imm > 9 )
//                                sprintf(&al_temp[0],"0x%x", (unsigned int) VInstr.imm);
//                            else
//                                sprintf(&al_temp[0],"%d", (unsigned int) VInstr.imm);
//                            strcat(AssemblyLine,&al_temp[0]);
			Op->type = o_imm;
			Op->value = VInstr.imm;
                        break;

                        case 'o':
//                            if( VInstr.offs > 9 )
//                                sprintf(&al_temp[0],"0x%x", VInstr.offs);
//                            else
//                                sprintf(&al_temp[0],"%d", VInstr.offs);
//                            strcat(AssemblyLine,&al_temp[0]);

			if(!strcmp("%vo(%rs)",fmt))
			{
				if((flags&SIMFLAG&SIM_DROP_OFFS0)&&(VInstr.offs==0))
				{
					// zero offset dropped
					Op->type = o_displ;
					Op->addr = 0;
					Op->reg = REGS(i->rs);
				}
				else
				{
					Op->type = o_displ;
					Op->addr = VInstr.offs;
					Op->reg = REGS(i->rs);
				}
			}
			else
			{
				// internal error
				msg("internal problem: %s:%d\n",__FILE__,__LINE__);
			}

                        break;

                        case 't':
//                            sprintf(&al_temp[0],"%s", VFPURegs[ VInstr.vt ]);
//                            strcat(AssemblyLine,&al_temp[0]);
			Op->type = o_reg;
			Op->reg = VFPUREGS(VInstr.vt);
                        break;

                        case 's':
//                            sprintf(&al_temp[0],"%s", VFPURegs[ VInstr.vs ]);
//                            strcat(AssemblyLine,&al_temp[0]);
			Op->type = o_reg;
			Op->reg = VFPUREGS(VInstr.vs);
                        break;

                        case 'd':
//                            sprintf(&al_temp[0],"%s", VFPURegs[ VInstr.vd ]);
//                            strcat(AssemblyLine,&al_temp[0]);
			Op->type = o_reg;
			Op->reg = VFPUREGS(VInstr.vd);
                        break;

                        case 'h':
//                            sprintf(&al_temp[0],"%s", VFPURegs[ VInstr.vc ]);
//                            strcat(AssemblyLine,&al_temp[0]);
			Op->type = o_reg;
			Op->reg = VFPUREGS(VInstr.vc);
                        break;

                        case 'c':
//                            sprintf(&al_temp[0],"%s", VFPUCond[ VInstr.cond ]);
//                            strcat(AssemblyLine,&al_temp[0]);

				Op->type = o_vfpucond;
				Op->value =VInstr.cond;

                        break;

                    }
                break;
		}
	}
	else
	{
		// internal error
		msg("internal problem: %s:%d addr:%08x fmt:%s\n",__FILE__,__LINE__,PC,fmt);
	}
	
}

static void format(unsigned long flags,int mnemonic, Instr *i, char *fmt1, char *fmt2, char *fmt3, char *fmt4)
{
	if((flags&SIMFLAG&SIM_REN_LI0ONRT0RS0)&&(i->rt==0)&&(i->rs==0))
	{
		cmd.itype = ALLEGREX_li;
	}
	else if((flags&SIMFLAG&SIM_REN_MOVONRT0)&&(i->rt==0))
	{
		cmd.itype = ALLEGREX_mov;
	}
	else if((flags&SIMFLAG&SIM_REN_LIONRS0)&&(i->rs==0))
	{
		cmd.itype = ALLEGREX_li;
	}
	else
	{
		cmd.itype = mnemonic;
	}

	format_arg(flags,mnemonic,i,fmt1,&cmd.Op1);
	format_arg(flags,mnemonic,i,fmt2,&cmd.Op2);
	format_arg(flags,mnemonic,i,fmt3,&cmd.Op3);
	format_arg(flags,mnemonic,i,fmt4,&cmd.Op4);
}

static void op_code_0(Opcode *o, Instr *i)
{
    o=o; // get rid of warning  

    if( i->opcode == 0x00000000 )
    {
        format(o->flags,ALLEGREX_nop, i, "","","","");
        return;
    }
    else if( i->opcode == 0x0000000F )
    {
        format(o->flags,ALLEGREX_sync, i, "","","","");
          return;
    }

    switch( i->funct )
    {
        case 0x0C:
            format(o->flags,ALLEGREX_syscall, i, "%D","","","");
        break;

        case 0x0D:
            format(o->flags,ALLEGREX_break, i, "%D","","","");
        break;

        case 0x02:
            if( i->rs == 0x00 )
            {
                format(o->flags,ALLEGREX_srl, i, "%rd","%rt","%s","");
            }
            else if( i->rs == 0x01 )
            {
                format(o->flags,ALLEGREX_rotr, i, "%rd","%rt","%s","");
            }
        break;

        case 0x06:
            if( i->shamt == 0x00 )
            {
                format(o->flags,ALLEGREX_srlv, i, "%rd","%rt","%rs","");
            }
            else if( i->shamt == 0x01 )
            {
                format(o->flags,ALLEGREX_rotrv, i, "%rd","%rt","%rs","");
            }
        break;

        if( i->rs == 0x00 )
        {
            case 0x00:
                format(o->flags,ALLEGREX_sll, i, "%rd","%rt","%s","");
            break;

            case 0x03:
                format(o->flags,ALLEGREX_sra, i, "%rd","%rt","%s","");
            break;
        }

        if( i->shamt == 0x00 )
        {
            if( i->rt == 0x00 )
            {
                case 0x08:
                    format(o->flags,ALLEGREX_jr, i, "%rs","","","");
                break;

                case 0x09:
                    format(o->flags,ALLEGREX_jalr, i, "%rd","%rs","","");
                break;

                case 0x16:
                    format(o->flags,ALLEGREX_clz, i, "%rd","%rs","","");
                break;

                case 0x17:
                    format(o->flags,ALLEGREX_clo, i, "%rd","%rs","","");
                break;

                if( i->rs == 0x00 )
                {
                    case 0x10:
                        format(o->flags,ALLEGREX_mfhi, i, "%rd","","","");
                    break;

                    case 0x12:
                        format(o->flags,ALLEGREX_mflo, i, "%rd","","","");
                    break;
                }

                if( i->rd == 0x00 )
                {
                    case 0x11:
                        format(o->flags,ALLEGREX_mthi, i, "%rs","","","");
                    break;

                    case 0x13:
                        format(o->flags,ALLEGREX_mtlo, i, "%rs","","","");
                    break;
                }
            }

            if( i->rd == 0x00 )
            {
                case 0x18:
                    format(o->flags,ALLEGREX_mult, i, "%rs","%rt","","");
                break;

                case 0x19:
                    format(o->flags,ALLEGREX_multu, i, "%rs","%rt","","");
                break;

                case 0x1A:
                    format(o->flags,ALLEGREX_div, i, "%rs","%rt","","");
                break;

                case 0x1B:
                    format(o->flags,ALLEGREX_divu, i, "%rs","%rt","","");
                break;

                case 0x1C:
                    format(o->flags,ALLEGREX_madd, i, "%rs","%rt","","");
                break;

                case 0x1D:
                    format(o->flags,ALLEGREX_maddu, i, "%rs","%rt","","");
                break;

                case 0x2E:
                    format(o->flags,ALLEGREX_msub, i, "%rs","%rt","","");
                break;

                case 0x2F:
                    format(o->flags,ALLEGREX_msubu, i, "%rs","%rt","","");
                break;
            }

            case 0x04:
                format(o->flags,ALLEGREX_sllv, i, "%rd","%rt","%rs","");
            break;

            case 0x07:
                format(o->flags,ALLEGREX_srav, i, "%rd","%rt","%rs","");
            break;

            case 0x0A:
                format(o->flags,ALLEGREX_movz, i, "%rd","%rs","%rt","");
            break;

            case 0x0B:
                format(o->flags,ALLEGREX_movn, i, "%rd","%rs","%rt","");
            break;

            case 0x20:
                format(o->flags|SIM_DROP_RSONRDEQRS|SIM_DROP_RTONRDEQRT|SIM_DROP_RT0|SIM_REN_MOVONRT0|SIM_REN_LI0ONRT0RS0|SIM_RSIMMONRT0RS0,ALLEGREX_add, i, "%rd","%rs","%rt","");
            break;

            case 0x21:
                format(o->flags|SIM_DROP_RSONRDEQRS|SIM_DROP_RTONRDEQRT|SIM_DROP_RT0|SIM_REN_MOVONRT0|SIM_REN_LI0ONRT0RS0|SIM_RSIMMONRT0RS0,ALLEGREX_addu, i, "%rd","%rs","%rt","");
            break;

            case 0x22:
                format(o->flags,ALLEGREX_sub, i, "%rd","%rs","%rt","");
            break;

            case 0x23:
                format(o->flags,ALLEGREX_subu, i, "%rd","%rs","%rt","");
            break;

            case 0x24:
                format(o->flags,ALLEGREX_and, i, "%rd","%rs","%rt","");
            break;

            case 0x25:
                format(o->flags,ALLEGREX_or, i, "%rd","%rs","%rt","");
            break;

            case 0x26:
                format(o->flags,ALLEGREX_xor, i, "%rd","%rs","%rt","");
            break;

            case 0x27:
                format(o->flags,ALLEGREX_nor, i, "%rd","%rs","%rt","");
            break;

            case 0x2A:
                format(o->flags,ALLEGREX_slt, i, "%rd","%rs","%rt","");
            break;

            case 0x2B:
                format(o->flags,ALLEGREX_sltu, i, "%rd","%rs","%rt","");
            break;
            
            case 0x2C:
                format(o->flags,ALLEGREX_max, i, "%rd","%rs","%rt","");
            break;

            case 0x2D:
                format(o->flags,ALLEGREX_min, i, "%rd","%rs","%rt","");
            break;
        }
    }
}

static void op_code_1(Opcode *o, Instr *i)
{
    o=o; // get rid of warning  

    switch( i->rt )
    {
        case 0x00:
            format(o->flags,ALLEGREX_bltz, i, "%rs","%b","","");
        break;

        case 0x01:
            format(o->flags,ALLEGREX_bgez, i, "%rs","%b","","");
        break;

        case 0x02:
            format(o->flags,ALLEGREX_bltzl, i, "%rs","%b","","");
        break;

        case 0x03:
            format(o->flags,ALLEGREX_bgezl, i, "%rs","%b","","");
        break;

        case 0x10:
            format(o->flags,ALLEGREX_bltzal, i, "%rs","%b","","");
        break;

        case 0x11:
            format(o->flags,ALLEGREX_bgezal, i, "%rs","%b","","");
        break;

        case 0x12:
            format(o->flags,ALLEGREX_bltzall, i, "%rs","%b","","");
        break;

        case 0x13:
            format(o->flags,ALLEGREX_bgezall, i, "%rs","%b","","");
        break;
    }
}

static void op_code_16(Opcode *o, Instr *i)
{
    o=o; // get rid of warning  

    if( i->opcode == 0x42000018 )
    {
        format(o->flags,ALLEGREX_eret, i, "", "", "", "");
        return;
    }

    if( ( i->shamt == 0x00 ) && ( i->funct == 0x00 ) )
    {
        switch( i->rs )
        {
            case 0x00:
                format(o->flags,ALLEGREX_mfc0, i, "%rt","%cd","","");
            break;

            case 0x02:
                format(o->flags,ALLEGREX_cfc0, i, "%rt","%Cd","","");
            break;

            case 0x04:
                format(o->flags,ALLEGREX_mtc0, i, "%rt","%cd","","");
            break;
            
            case 0x06:
                format(o->flags,ALLEGREX_ctc0, i, "%rt","%Cd","","");
            break;
        }
    }

    switch( i->rs )
    {
        case 0x08:
            switch( i->rt )
            {
                case 0x00:
                    format(o->flags,ALLEGREX_bc0f, i, "%b","","","");
                break;

                case 0x01:
                    format(o->flags,ALLEGREX_bc0t, i, "%b","","","");
                break;

                case 0x02:
                    format(o->flags,ALLEGREX_bc0fl, i, "%b","","","");
                break;

                case 0x03:
                    format(o->flags,ALLEGREX_bc0tl, i, "%b","","","");
                break;
            }
        break;
    }
}

static void op_code_17(Opcode *o, Instr *i)
{
    o=o; // get rid of warning  

    if( ( i->shamt == 0x00 ) && ( i->funct == 0x00 ) )
    {
        switch( i->rs )
        {
            case 0x00:
                format(o->flags,ALLEGREX_mfc1, i, "%rt","%fs","","");
            break;
    
            case 0x02:
                format(o->flags,ALLEGREX_cfc1, i, "%rt","%fs","","");
            break;
    
            case 0x04:
                format(o->flags,ALLEGREX_mtc1, i, "%rt","%fs","","");
            break;
    
            case 0x06:
                format(o->flags,ALLEGREX_ctc1, i, "%rt","%fs","","");
            break;
        }
    }

    switch( i->rs )
    {
        case 0x08:
            switch( i->rt )
            {
                case 0x00:
                    format(o->flags,ALLEGREX_bc1f, i, "%b","","","");
                break;

                case 0x01:
                    format(o->flags,ALLEGREX_bc1t, i, "%b","","","");
                break;

                case 0x02:
                    format(o->flags,ALLEGREX_bc1fl, i, "%b","","","");
                break;

                case 0x03:
                    format(o->flags,ALLEGREX_bc1tl, i, "%b","","","");
                break;
            }
        break;

        case 0x10:
            switch( i->funct )
            {
                case 0x00:
                    format(o->flags,ALLEGREX_add_s, i, "%fd","%fs","%ft","");
                break;

                case 0x01:
                    format(o->flags,ALLEGREX_sub_s, i, "%fd","%fs","%ft","");
                break;

                case 0x02:
                    format(o->flags,ALLEGREX_mul_s, i, "%fd","%fs","%ft","");
                break;

                case 0x03:
                    format(o->flags,ALLEGREX_div_s, i, "%fd","%fs","%ft","");
                break;

                if( i->rt == 0x00 )
                {
                    case 0x04:
                        format(o->flags,ALLEGREX_sqrt_s, i, "%fd","%fs","","");
                    break;

                    case 0x05:
                        format(o->flags,ALLEGREX_abs_s, i, "%fd","%fs","","");
                    break;

                    case 0x06:
                        format(o->flags,ALLEGREX_mov_s, i, "%fd","%fs","","");
                    break;

                    case 0x07:
                        format(o->flags,ALLEGREX_neg_s, i, "%fd","%fs","","");
                    break;

                    case 0x0C:
                        format(o->flags,ALLEGREX_ceil_w_s, i, "%fd","%fs","","");
                    break;

                    case 0x0D:
                        format(o->flags,ALLEGREX_trunc_w_s, i, "%fd","%fs","","");
                    break;

                    case 0x0E:
                        format(o->flags,ALLEGREX_round_w_s, i, "%fd","%fs","","");
                    break;

                    case 0x0F:
                        format(o->flags,ALLEGREX_floor_w_s, i, "%fd","%fs","","");
                    break;

                    case 0x24:
                        format(o->flags,ALLEGREX_cvt_w_s, i, "%fd","%fs","","");
                    break;

                    case 0x30:
                        format(o->flags,ALLEGREX_c_f_s, i, "%fs","%ft","","");
                    break;

                    case 0x31:
                        format(o->flags,ALLEGREX_c_un_s, i, "%fs","%ft","","");
                    break;

                    case 0x32:
                        format(o->flags,ALLEGREX_c_eq_s, i, "%fs","%ft","","");
                    break;

                    case 0x33:
                        format(o->flags,ALLEGREX_c_ueq_s, i, "%fs","%ft","","");
                    break;

                    case 0x34:
                        format(o->flags,ALLEGREX_c_olt_s, i, "%fs","%ft","","");
                    break;

                    case 0x35:
                        format(o->flags,ALLEGREX_c_ult_s, i, "%fs","%ft","","");
                    break;

                    case 0x36:
                        format(o->flags,ALLEGREX_c_ole_s, i, "%fs","%ft","","");
                    break;

                    case 0x37:
                        format(o->flags,ALLEGREX_c_ule_s, i, "%fs","%ft","","");
                    break;

                    case 0x38:
                        format(o->flags,ALLEGREX_c_sf_s, i, "%fs","%ft","","");
                    break;

                    case 0x39:
                        format(o->flags,ALLEGREX_c_ngle_s, i, "%fs","%ft","","");
                    break;

                    case 0x3A:
                        format(o->flags,ALLEGREX_c_seq_s, i, "%fs","%ft","","");
                    break;

                    case 0x3B:
                        format(o->flags,ALLEGREX_c_ngl_s, i, "%fs","%ft","","");
                    break;

                    case 0x3C:
                        format(o->flags,ALLEGREX_c_lt_s, i, "%fs","%ft","","");
                    break;

                    case 0x3D:
                        format(o->flags,ALLEGREX_c_nge_s, i, "%fs","%ft","","");
                    break;

                    case 0x3E:
                        format(o->flags,ALLEGREX_c_le_s, i, "%fs","%ft","","");
                    break;

                    case 0x3F:
                        format(o->flags,ALLEGREX_c_ngt_s, i, "%fs","%ft","","");
                    break;
                }
            }
        break;

        case 0x14:
            if( i->rt == 0x00 )
            {
                format(o->flags,ALLEGREX_cvt_s_w, i, "%fd","%fs","","");
            }
        break;
    }
}

static void op_VFPU_18(Opcode *o, Instr *i)
{
    unsigned short sub;

    o=o; // get rid of warning  

    DecodeVFPUInst( i->opcode );

    switch( i->rs )
    {
        case 0x03:
            sub = (unsigned short) ( i->opcode >> 7 ) & 0x1FF;
            if ( sub == 0x00 )
            {
                format(o->flags,ALLEGREX_mfv, i, "%rt","%vd","","");
                return;
            }
            sub >>= 1;
            if ( sub == 0x00 )
            {
                VInstr.vc = (unsigned char) ( i->opcode & 0xFF );
                format(o->flags,ALLEGREX_mfvc, i, "%rt","%vh","","");
                return;
            }
        break;

        case 0x07:
            sub = (unsigned short) ( i->opcode >> 7 ) & 0x1FF;
            if ( sub == 0x00 )
            {
                format(o->flags,ALLEGREX_mtv, i, "%rt","%vd","","");
                return;
            }
            sub >>= 1;
            if ( sub == 0x00 )
            {
                VInstr.vc = (unsigned char) ( i->opcode & 0xFF );
                format(o->flags,ALLEGREX_mtvc, i, "%rt","%vh","","");
                return;
            }
        break;

        case 0x08:
            sub = (unsigned short) ( i->opcode >> 16 ) & 0x03;
            VInstr.imm = ( i->opcode >> 18 ) & 0x07;

            switch( sub )
            {
                case 0x00:
                    format(o->flags,ALLEGREX_bvf, i, "%vi","%b","","");
                break;

                case 0x01:
                    format(o->flags,ALLEGREX_bvt, i, "%vi","%b","","");
                break;

                case 0x02:
                    format(o->flags,ALLEGREX_bvfl, i, "%vi","%b","","");
                break;

                case 0x03:
                    format(o->flags,ALLEGREX_bvtl, i, "%vi","%b","","");
                break;
            }
        break;
    }
}

static void op_VFPU_24(Opcode *o, Instr *i)
{
    o=o; // get rid of warning  

    DecodeVFPUInst( i->opcode );

    switch( VInstr.funct3 )
    {
        case 0x00:
            if( ( VInstr.bit7 == 0 ) && ( VInstr.bit15 == 0 ) )
                format(o->flags,ALLEGREX_vadd_s, i, "%vd","%vs","%vt","");

            if( ( VInstr.bit7 == 1 ) && ( VInstr.bit15 == 0 ) )
                format(o->flags,ALLEGREX_vadd_p, i, "%vd","%vs","%vt","");

            if( ( VInstr.bit7 == 0 ) && ( VInstr.bit15 == 1 ) )
                format(o->flags,ALLEGREX_vadd_t, i, "%vd","%vs","%vt","");

            if( ( VInstr.bit7 == 1 ) && ( VInstr.bit15 == 1 ) )
                format(o->flags,ALLEGREX_vadd_q, i, "%vd","%vs","%vt","");
        break;

        case 0x01:
            if( ( VInstr.bit7 == 0 ) && ( VInstr.bit15 == 0 ) )
                format(o->flags,ALLEGREX_vsub_s, i, "%vd","%vs","%vt","");

            if( ( VInstr.bit7 == 1 ) && ( VInstr.bit15 == 0 ) )
                format(o->flags,ALLEGREX_vsub_p, i, "%vd","%vs","%vt","");

            if( ( VInstr.bit7 == 0 ) && ( VInstr.bit15 == 1 ) )
                format(o->flags,ALLEGREX_vsub_t, i, "%vd","%vs","%vt","");

            if( ( VInstr.bit7 == 1 ) && ( VInstr.bit15 == 1 ) )
                format(o->flags,ALLEGREX_vsub_q, i, "%vd","%vs","%vt","");
        break;

        case 0x02:
            if( ( VInstr.bit7 == 0 ) && ( VInstr.bit15 == 0 ) )
                format(o->flags,ALLEGREX_vsbn_s, i, "%vd","%vs","%vt","");
        break;

        case 0x07:
            if( ( VInstr.bit7 == 0 ) && ( VInstr.bit15 == 0 ) )
                format(o->flags,ALLEGREX_vdiv_s, i, "%vd","%vs","%vt","");

            if( ( VInstr.bit7 == 1 ) && ( VInstr.bit15 == 0 ) )
                format(o->flags,ALLEGREX_vdiv_p, i, "%vd","%vs","%vt","");

            if( ( VInstr.bit7 == 0 ) && ( VInstr.bit15 == 1 ) )
                format(o->flags,ALLEGREX_vdiv_t, i, "%vd","%vs","%vt","");

            if( ( VInstr.bit7 == 1 ) && ( VInstr.bit15 == 1 ) )
                format(o->flags,ALLEGREX_vdiv_q, i, "%vd","%vs","%vt","");
        break;
    }
}

static void op_VFPU_25(Opcode *o, Instr *i)
{
    o=o; // get rid of warning  

    DecodeVFPUInst( i->opcode );

    switch( VInstr.funct3 )
    {
        case 0x00:
            if( ( VInstr.bit7 == 0 ) && ( VInstr.bit15 == 0 ) )
                format(o->flags,ALLEGREX_vmul_s, i, "%vd","%vs","%vt","");

            if( ( VInstr.bit7 == 1 ) && ( VInstr.bit15 == 0 ) )
                format(o->flags,ALLEGREX_vmul_p, i, "%vd","%vs","%vt","");

            if( ( VInstr.bit7 == 0 ) && ( VInstr.bit15 == 1 ) )
                format(o->flags,ALLEGREX_vmul_t, i, "%vd","%vs","%vt","");

            if( ( VInstr.bit7 == 1 ) && ( VInstr.bit15 == 1 ) )
                format(o->flags,ALLEGREX_vmul_q, i, "%vd","%vs","%vt","");
        break;

        case 0x01:
            if( ( VInstr.bit7 == 1 ) && ( VInstr.bit15 == 0 ) )
                format(o->flags,ALLEGREX_vdot_p, i, "%vd","%vs","%vt","");

            if( ( VInstr.bit7 == 0 ) && ( VInstr.bit15 == 1 ) )
                format(o->flags,ALLEGREX_vdot_t, i, "%vd","%vs","%vt","");

            if( ( VInstr.bit7 == 1 ) && ( VInstr.bit15 == 1 ) )
                format(o->flags,ALLEGREX_vdot_q, i, "%vd","%vs","%vt","");
        break;

        case 0x02:
            if( ( VInstr.bit7 == 1 ) && ( VInstr.bit15 == 0 ) )
                format(o->flags,ALLEGREX_vscl_p, i, "%vd","%vs","%vt","");

            if( ( VInstr.bit7 == 0 ) && ( VInstr.bit15 == 1 ) )
                format(o->flags,ALLEGREX_vscl_t, i, "%vd","%vs","%vt","");

            if( ( VInstr.bit7 == 1 ) && ( VInstr.bit15 == 1 ) )
                format(o->flags,ALLEGREX_vscl_q, i, "%vd","%vs","%vt","");
        break;

        case 0x04:
            if( ( VInstr.bit7 == 1 ) && ( VInstr.bit15 == 0 ) )
                format(o->flags,ALLEGREX_vhdp_p, i, "%vd","%vs","%vt","");

            if( ( VInstr.bit7 == 0 ) && ( VInstr.bit15 == 1 ) )
                format(o->flags,ALLEGREX_vhdp_t, i, "%vd","%vs","%vt","");

            if( ( VInstr.bit7 == 1 ) && ( VInstr.bit15 == 1 ) )
                format(o->flags,ALLEGREX_vhdp_q, i, "%vd","%vs","%vt","");
        break;

        case 0x05:
            if( ( VInstr.bit7 == 0 ) && ( VInstr.bit15 == 1 ) )
                format(o->flags,ALLEGREX_vcrs_t, i, "%vd","%vs","%vt","");
        break;

        case 0x06:
            if( ( VInstr.bit7 == 1 ) && ( VInstr.bit15 == 0 ) )
                format(o->flags,ALLEGREX_vdet_p, i, "%vd","%vs","%vt","");
        break;
    }
}

static void op_VFPU_27(Opcode *o, Instr *i)
{
    unsigned char sub;

    o=o; // get rid of warning  

    DecodeVFPUInst( i->opcode );

    switch( VInstr.funct3 )
    {
        case 0x00:
            sub = (unsigned char) ( i->opcode >> 4 ) & 0x0F;
            VInstr.cond = (unsigned char) ( i->opcode & 0x0F );

            switch( sub )
            {
                case 0x00:
                    if( VInstr.bit15 == 0 )
                        format(o->flags,ALLEGREX_vcmp_s, i, "%vc","%vs","%vt","");

                    if( VInstr.bit15 == 1 )
                        format(o->flags,ALLEGREX_vcmp_t, i, "%vc","%vs","%vt","");
                break;

                case 0x08:
                    if( VInstr.bit15 == 0 )
                        format(o->flags,ALLEGREX_vcmp_p, i, "%vc","%vs","%vt","");

                    if( VInstr.bit15 == 1 )
                        format(o->flags,ALLEGREX_vcmp_q, i, "%vc","%vs","%vt","");
                break;
            }
        break;

        case 0x02:
            if( ( VInstr.bit7 == 0 ) && ( VInstr.bit15 == 0 ) )
                format(o->flags,ALLEGREX_vmin_s, i, "%vd","%vs","%vt","");

            if( ( VInstr.bit7 == 1 ) && ( VInstr.bit15 == 0 ) )
                format(o->flags,ALLEGREX_vmin_p, i, "%vd","%vs","%vt","");

            if( ( VInstr.bit7 == 0 ) && ( VInstr.bit15 == 1 ) )
                format(o->flags,ALLEGREX_vmin_t, i, "%vd","%vs","%vt","");

            if( ( VInstr.bit7 == 1 ) && ( VInstr.bit15 == 1 ) )
                format(o->flags,ALLEGREX_vmin_q, i, "%vd","%vs","%vt","");
        break;

        case 0x03:
            if( ( VInstr.bit7 == 0 ) && ( VInstr.bit15 == 0 ) )
                format(o->flags,ALLEGREX_vmax_s, i, "%vd","%vs","%vt","");

            if( ( VInstr.bit7 == 1 ) && ( VInstr.bit15 == 0 ) )
                format(o->flags,ALLEGREX_vmax_p, i, "%vd","%vs","%vt","");

            if( ( VInstr.bit7 == 0 ) && ( VInstr.bit15 == 1 ) )
                format(o->flags,ALLEGREX_vmax_t, i, "%vd","%vs","%vt","");

            if( ( VInstr.bit7 == 1 ) && ( VInstr.bit15 == 1 ) )
                format(o->flags,ALLEGREX_vmax_q, i, "%vd","%vs","%vt","");
        break;

        case 0x05:
            if( ( VInstr.bit7 == 0 ) && ( VInstr.bit15 == 0 ) )
                format(o->flags,ALLEGREX_vscmp_s, i, "%vd","%vs","%vt","");

            if( ( VInstr.bit7 == 1 ) && ( VInstr.bit15 == 0 ) )
                format(o->flags,ALLEGREX_vscmp_p, i, "%vd","%vs","%vt","");

            if( ( VInstr.bit7 == 0 ) && ( VInstr.bit15 == 1 ) )
                format(o->flags,ALLEGREX_vscmp_t, i, "%vd","%vs","%vt","");

            if( ( VInstr.bit7 == 1 ) && ( VInstr.bit15 == 1 ) )
                format(o->flags,ALLEGREX_vscmp_q, i, "%vd","%vs","%vt","");
        break;

        case 0x06:
            if( ( VInstr.bit7 == 0 ) && ( VInstr.bit15 == 0 ) )
                format(o->flags,ALLEGREX_vsge_s, i, "%vd","%vs","%vt","");

            if( ( VInstr.bit7 == 1 ) && ( VInstr.bit15 == 0 ) )
                format(o->flags,ALLEGREX_vsge_p, i, "%vd","%vs","%vt","");

            if( ( VInstr.bit7 == 0 ) && ( VInstr.bit15 == 1 ) )
                format(o->flags,ALLEGREX_vsge_t, i, "%vd","%vs","%vt","");

            if( ( VInstr.bit7 == 1 ) && ( VInstr.bit15 == 1 ) )
                format(o->flags,ALLEGREX_vsge_q, i, "%vd","%vs","%vt","");
        break;

        case 0x07:
            if( ( VInstr.bit7 == 0 ) && ( VInstr.bit15 == 0 ) )
                format(o->flags,ALLEGREX_vslt_s, i, "%vd","%vs","%vt","");

            if( ( VInstr.bit7 == 1 ) && ( VInstr.bit15 == 0 ) )
                format(o->flags,ALLEGREX_vslt_p, i, "%vd","%vs","%vt","");

            if( ( VInstr.bit7 == 0 ) && ( VInstr.bit15 == 1 ) )
                format(o->flags,ALLEGREX_vslt_t, i, "%vd","%vs","%vt","");

            if( ( VInstr.bit7 == 1 ) && ( VInstr.bit15 == 1 ) )
                format(o->flags,ALLEGREX_vslt_q, i, "%vd","%vs","%vt","");
        break;
    }
}

static void op_code_28(Opcode *o, Instr *i)
{
    o=o; // get rid of warning  

    // 011100 00000000000000000000 111110       dret
    // 011100 00000000000000000000 111111       dbreak
    if( i->opcode == 0x7000003E )
    {
	cmd.itype = ALLEGREX_dret;
          return;
    }
    else if( i->opcode == 0x7000003F )
    {
	cmd.itype = ALLEGREX_dbreak;
        return;
    }

    // 011100 00000 ttttt rrrrr 00000 111101    mfdr rt, dr
    // 011100 00100 ttttt rrrrr 00000 111101    mtdr rt, dr
    if( ( i->shamt == 0x00 ) && ( i->funct == 0x3D ) )
    {
        switch( i->rs )
        {
            case 0x00:
                format(o->flags,ALLEGREX_mfdr, i, "%rt","%rb","","");
            break;
            
            case 0x04:
                format(o->flags,ALLEGREX_mtdr, i, "%rt","%rb","","");
            break;
        }
    }

    // unknown opcodes!
    // 880402E8:   00 00 00 70
    if( i->opcode == 0x70000000 )
    {
        format(o->flags,ALLEGREX_D_UNK_00, i, "", "", "", "");
        return;
    }

    // Thanks to TyRaNiD for reversing these two PSP Specifics!
    switch( i->funct )
    {
        case 0x24:
            format(o->flags,ALLEGREX_mfic, i, "%rt","%rd","","");
        break;
        
        case 0x26:
            format(o->flags,ALLEGREX_mtic, i, "%rt","%rd","","");
        break;
    }
}

static void op_code_31(Opcode *o, Instr *i)
{
    o=o; // get rid of warning  

    switch( i->funct )
    {
        case 0x00:
            format(o->flags,ALLEGREX_ext, i, "%rt","%rs","%s","%z");
        break;

        case 0x04:
            format(o->flags,ALLEGREX_ins, i, "%rt","%rs","%s","%x");
        break;

        case 0x20:
            if( i->rs == 0x00 )
            {
                switch( i->shamt )
                {
                    case 0x02:
                        format(o->flags,ALLEGREX_wsbh, i, "%rd","%rt","","");
                    break;

                    case 0x03:
                        format(o->flags,ALLEGREX_wsbw, i, "%rd","%rt","","");
                    break;

                    case 0x10:
                        format(o->flags,ALLEGREX_seb, i, "%rd","%rt","","");
                    break;

                    case 0x14:
                        format(o->flags,ALLEGREX_bitrev, i, "%rd","%rt","","");
                    break;

                    case 0x18:
                        format(o->flags,ALLEGREX_seh, i, "%rd","%rt","","");
                    break;
                }
            }
        break;
    }
}

static void op_VFPU_52(Opcode *o, Instr *i)
{
    unsigned short sub;

    o=o; // get rid of warning  

    DecodeVFPUInst( i->opcode );

    if( VInstr.funct2 == 0x03)
    {
        if( ( VInstr.bit7 == 0 ) && ( VInstr.bit15 == 0 ) )
        {
            VInstr.imm = ( i->opcode >> 16 ) & 0xFF;
            format(o->flags,ALLEGREX_vwbn_s, i, "%vd","%vs","%vi","");
            return;
        }
    }

    VInstr.imm = i->rt;
    switch( i->rs )
    {
        case 0x03:
            sub = (unsigned short) ( i->opcode >> 7 ) & 0x1FF;
            switch( sub )
            {
                case 0x000:
                    format(o->flags,ALLEGREX_vcst_s, i, "%vd","%vi","","");
                break;

                case 0x001:
                    format(o->flags,ALLEGREX_vcst_p, i, "%vd","%vi","","");
                break;

                case 0x100:
                    format(o->flags,ALLEGREX_vcst_t, i, "%vd","%vi","","");
                break;

                case 0x101:
                    format(o->flags,ALLEGREX_vcst_q, i, "%vd","%vi","","");
                break;
            }                         
        break;

        case 0x10:
            if( ( VInstr.bit7 == 0 ) && ( VInstr.bit15 == 0 ) )
                format(o->flags,ALLEGREX_vf2in_s, i, "%vd","%vs","%vi","");

            if( ( VInstr.bit7 == 1 ) && ( VInstr.bit15 == 0 ) )
                format(o->flags,ALLEGREX_vf2in_p, i, "%vd","%vs","%vi","");

            if( ( VInstr.bit7 == 0 ) && ( VInstr.bit15 == 1 ) )
                format(o->flags,ALLEGREX_vf2in_t, i, "%vd","%vs","%vi","");

            if( ( VInstr.bit7 == 1 ) && ( VInstr.bit15 == 1 ) )
                format(o->flags,ALLEGREX_vf2in_q, i, "%vd","%vs","%vi","");
        break;

        case 0x11:
            if( ( VInstr.bit7 == 0 ) && ( VInstr.bit15 == 0 ) )
                format(o->flags,ALLEGREX_vf2iz_s, i, "%vd","%vs","%vi","");

            if( ( VInstr.bit7 == 1 ) && ( VInstr.bit15 == 0 ) )
                format(o->flags,ALLEGREX_vf2iz_p, i, "%vd","%vs","%vi","");

            if( ( VInstr.bit7 == 0 ) && ( VInstr.bit15 == 1 ) )
                format(o->flags,ALLEGREX_vf2iz_t, i, "%vd","%vs","%vi","");

            if( ( VInstr.bit7 == 1 ) && ( VInstr.bit15 == 1 ) )
                format(o->flags,ALLEGREX_vf2iz_q, i, "%vd","%vs","%vi","");
        break;

        case 0x12:
            if( ( VInstr.bit7 == 0 ) && ( VInstr.bit15 == 0 ) )
                format(o->flags,ALLEGREX_vf2iu_s, i, "%vd","%vs","%vi","");

            if( ( VInstr.bit7 == 1 ) && ( VInstr.bit15 == 0 ) )
                format(o->flags,ALLEGREX_vf2iu_p, i, "%vd","%vs","%vi","");

            if( ( VInstr.bit7 == 0 ) && ( VInstr.bit15 == 1 ) )
                format(o->flags,ALLEGREX_vf2iu_t, i, "%vd","%vs","%vi","");

            if( ( VInstr.bit7 == 1 ) && ( VInstr.bit15 == 1 ) )
                format(o->flags,ALLEGREX_vf2iu_q, i, "%vd","%vs","%vi","");
        break;

        case 0x13:
            if( ( VInstr.bit7 == 0 ) && ( VInstr.bit15 == 0 ) )
                format(o->flags,ALLEGREX_vf2id_s, i, "%vd","%vs","%vi","");

            if( ( VInstr.bit7 == 1 ) && ( VInstr.bit15 == 0 ) )
                format(o->flags,ALLEGREX_vf2id_p, i, "%vd","%vs","%vi","");

            if( ( VInstr.bit7 == 0 ) && ( VInstr.bit15 == 1 ) )
                format(o->flags,ALLEGREX_vf2id_t, i, "%vd","%vs","%vi","");

            if( ( VInstr.bit7 == 1 ) && ( VInstr.bit15 == 1 ) )
                format(o->flags,ALLEGREX_vf2id_q, i, "%vd","%vs","%vi","");
        break;

        case 0x14:
            if( ( VInstr.bit7 == 0 ) && ( VInstr.bit15 == 0 ) )
                format(o->flags,ALLEGREX_vi2f_s, i, "%vd","%vs","%vi","");

            if( ( VInstr.bit7 == 1 ) && ( VInstr.bit15 == 0 ) )
                format(o->flags,ALLEGREX_vi2f_p, i, "%vd","%vs","%vi","");

            if( ( VInstr.bit7 == 0 ) && ( VInstr.bit15 == 1 ) )
                format(o->flags,ALLEGREX_vi2f_t, i, "%vd","%vs","%vi","");

            if( ( VInstr.bit7 == 1 ) && ( VInstr.bit15 == 1 ) )
                format(o->flags,ALLEGREX_vi2f_q, i, "%vd","%vs","%vi","");
        break;
    }

    switch( VInstr.funct19 )
    {
        case 0x0601:
            format(o->flags,ALLEGREX_vidt_p, i, "%vd","","","");
        break;

        case 0x0701:
            format(o->flags,ALLEGREX_vidt_q, i, "%vd","","","");
        break;

        case 0x0C00:
            format(o->flags,ALLEGREX_vzero_s, i, "%vd","","","");
        break;
        
        case 0x0C01:
            format(o->flags,ALLEGREX_vzero_p, i, "%vd","","","");
        break;

        case 0x0D00:
            format(o->flags,ALLEGREX_vzero_t, i, "%vd","","","");
        break;

        case 0x0D01:
            format(o->flags,ALLEGREX_vzero_q, i, "%vd","","","");
        break;

        case 0x0E00:
            format(o->flags,ALLEGREX_vone_s, i, "%vd","","","");
        break;

        case 0x0E01:
            format(o->flags,ALLEGREX_vone_p, i, "%vd","","","");
        break;

        case 0x0F00:
            format(o->flags,ALLEGREX_vone_t, i, "%vd","","","");
        break;

        case 0x0F01:
            format(o->flags,ALLEGREX_vone_q, i, "%vd","","","");
        break;

        case 0x4200:
            format(o->flags,ALLEGREX_vrndi_s, i, "%vd","","","");
        break;

        case 0x4201:
            format(o->flags,ALLEGREX_vrndi_p, i, "%vd","","","");
        break;

        case 0x4300:
            format(o->flags,ALLEGREX_vrndi_t, i, "%vd","","","");
        break;

        case 0x4301:
            format(o->flags,ALLEGREX_vrndi_q, i, "%vd","","","");
        break;

        case 0x4400:
            format(o->flags,ALLEGREX_vrndf1_s, i, "%vd","","","");
        break;

        case 0x4401:
            format(o->flags,ALLEGREX_vrndf1_p, i, "%vd","","","");
        break;

        case 0x4500:
            format(o->flags,ALLEGREX_vrndf1_t, i, "%vd","","","");
        break;

        case 0x4501:
            format(o->flags,ALLEGREX_vrndf1_q, i, "%vd","","","");
        break;

        case 0x4600:
            format(o->flags,ALLEGREX_vrndf2_s, i, "%vd","","","");
        break;

        case 0x4601:
            format(o->flags,ALLEGREX_vrndf2_p, i, "%vd","","","");
        break;

        case 0x4700:
            format(o->flags,ALLEGREX_vrndf2_t, i, "%vd","","","");
        break;

        case 0x4701:
            format(o->flags,ALLEGREX_vrndf2_q, i, "%vd","","","");
        break;
    }

    VInstr.imm = ( i->opcode >> 6) & 0x07;
    switch( VInstr.funct7 )
    {
        case 0x54:
            if( ( VInstr.bit7 == 0 ) && ( VInstr.bit15 == 0 ) )
                format(o->flags,ALLEGREX_vcmovt_s, i, "%vd","%vs","%vi","");

            if( ( VInstr.bit7 == 1 ) && ( VInstr.bit15 == 0 ) )
                format(o->flags,ALLEGREX_vcmovt_p, i, "%vd","%vs","%vi","");

            if( ( VInstr.bit7 == 0 ) && ( VInstr.bit15 == 1 ) )
                format(o->flags,ALLEGREX_vcmovt_t, i, "%vd","%vs","%vi","");

            if( ( VInstr.bit7 == 1 ) && ( VInstr.bit15 == 1 ) )
                format(o->flags,ALLEGREX_vcmovt_q, i, "%vd","%vs","%vi","");
        break;

        case 0x55:
            if( ( VInstr.bit7 == 0 ) && ( VInstr.bit15 == 0 ) )
                format(o->flags,ALLEGREX_vcmovf_s, i, "%vd","%vs","%vi","");

            if( ( VInstr.bit7 == 1 ) && ( VInstr.bit15 == 0 ) )
                format(o->flags,ALLEGREX_vcmovf_p, i, "%vd","%vs","%vi","");

            if( ( VInstr.bit7 == 0 ) && ( VInstr.bit15 == 1 ) )
                format(o->flags,ALLEGREX_vcmovf_t, i, "%vd","%vs","%vi","");

            if( ( VInstr.bit7 == 1 ) && ( VInstr.bit15 == 1 ) )
                format(o->flags,ALLEGREX_vcmovf_q, i, "%vd","%vs","%vi","");
        break;
    }

    switch( VInstr.funct11 )
    {
        case 0x40:
            sub = (unsigned short) i->opcode & 0xFF;
            if ( sub == 0x00 )
            {
                format(o->flags,ALLEGREX_vrnds_s, i, "%vs","","","");
            }
        break;

        case 0xA2:
            VInstr.imm = i->opcode & 0xFF;
            format(o->flags,ALLEGREX_vmtvc, i, "%vi","%vs","","");
        break;

        case 0x00:
            if( VInstr.bit7 == 0 )
                format(o->flags,ALLEGREX_vmov_s, i, "%vd","%vs","","");
            else
                format(o->flags,ALLEGREX_vmov_p, i, "%vd","%vs","","");
        break;

        case 0x01:
            if( VInstr.bit7 == 0 )
                format(o->flags,ALLEGREX_vmov_t, i, "%vd","%vs","","");
            else
                format(o->flags,ALLEGREX_vmov_q, i, "%vd","%vs","","");
        break;

        case 0x02:
            if( VInstr.bit7 == 0 )
                format(o->flags,ALLEGREX_vabs_s, i, "%vd","%vs","","");
            else
                format(o->flags,ALLEGREX_vabs_p, i, "%vd","%vs","","");
        break;

        case 0x03:
            if( VInstr.bit7 == 0 )
                format(o->flags,ALLEGREX_vabs_t, i, "%vd","%vs","","");
            else
                format(o->flags,ALLEGREX_vabs_q, i, "%vd","%vs","","");
        break;

        case 0x04:
            if( VInstr.bit7 == 0 )
                format(o->flags,ALLEGREX_vneg_s, i, "%vd","%vs","","");
            else
                format(o->flags,ALLEGREX_vneg_p, i, "%vd","%vs","","");
        break;

        case 0x05:
            if( VInstr.bit7 == 0 )
                format(o->flags,ALLEGREX_vneg_t, i, "%vd","%vs","","");
            else
                format(o->flags,ALLEGREX_vneg_q, i, "%vd","%vs","","");
        break;

        case 0x08:
            if( VInstr.bit7 == 0 )
                format(o->flags,ALLEGREX_vsat0_s, i, "%vd","%vs","","");
            else
                format(o->flags,ALLEGREX_vsat0_p, i, "%vd","%vs","","");
        break;

        case 0x09:
            if( VInstr.bit7 == 0 )
                format(o->flags,ALLEGREX_vsat0_t, i, "%vd","%vs","","");
            else
                format(o->flags,ALLEGREX_vsat0_q, i, "%vd","%vs","","");
        break;

        case 0x0A:
            if( VInstr.bit7 == 0 )
                format(o->flags,ALLEGREX_vsat1_s, i, "%vd","%vs","","");
            else
                format(o->flags,ALLEGREX_vsat1_p, i, "%vd","%vs","","");
        break;

        case 0x0B:
            if( VInstr.bit7 == 0 )
                format(o->flags,ALLEGREX_vsat1_t, i, "%vd","%vs","","");
            else
                format(o->flags,ALLEGREX_vsat1_q, i, "%vd","%vs","","");
        break;

        case 0x20:
            if( VInstr.bit7 == 0 )
                format(o->flags,ALLEGREX_vrcp_s, i, "%vd","%vs","","");
            else
                format(o->flags,ALLEGREX_vrcp_p, i, "%vd","%vs","","");
        break;

        case 0x21:
            if( VInstr.bit7 == 0 )
                format(o->flags,ALLEGREX_vrcp_t, i, "%vd","%vs","","");
            else
                format(o->flags,ALLEGREX_vrcp_q, i, "%vd","%vs","","");
        break;

        case 0x22:
            if( VInstr.bit7 == 0 )
                format(o->flags,ALLEGREX_vrsq_s, i, "%vd","%vs","","");
            else
                format(o->flags,ALLEGREX_vrsq_p, i, "%vd","%vs","","");
        break;

        case 0x23:
            if( VInstr.bit7 == 0 )
                format(o->flags,ALLEGREX_vrsq_t, i, "%vd","%vs","","");
            else
                format(o->flags,ALLEGREX_vrsq_q, i, "%vd","%vs","","");
        break;

        case 0x24:
            if( VInstr.bit7 == 0 )
                format(o->flags,ALLEGREX_vsin_s, i, "%vd","%vs","","");
            else
                format(o->flags,ALLEGREX_vsin_p, i, "%vd","%vs","","");
        break;

        case 0x25:
            if( VInstr.bit7 == 0 )
                format(o->flags,ALLEGREX_vsin_t, i, "%vd","%vs","","");
            else
                format(o->flags,ALLEGREX_vsin_q, i, "%vd","%vs","","");
        break;

        case 0x26:
            if( VInstr.bit7 == 0 )
                format(o->flags,ALLEGREX_vcos_s, i, "%vd","%vs","","");
            else
                format(o->flags,ALLEGREX_vcos_p, i, "%vd","%vs","","");
        break;

        case 0x27:
            if( VInstr.bit7 == 0 )
                format(o->flags,ALLEGREX_vcos_t, i, "%vd","%vs","","");
            else
                format(o->flags,ALLEGREX_vcos_q, i, "%vd","%vs","","");
        break;

        case 0x28:
            if( VInstr.bit7 == 0 )
                format(o->flags,ALLEGREX_vexp2_s, i, "%vd","%vs","","");
            else
                format(o->flags,ALLEGREX_vexp2_p, i, "%vd","%vs","","");
        break;

        case 0x29:
            if( VInstr.bit7 == 0 )
                format(o->flags,ALLEGREX_vexp2_t, i, "%vd","%vs","","");
            else
                format(o->flags,ALLEGREX_vexp2_q, i, "%vd","%vs","","");
        break;

        case 0x2A:
            if( VInstr.bit7 == 0 )
                format(o->flags,ALLEGREX_vlog2_s, i, "%vd","%vs","","");
            else
                format(o->flags,ALLEGREX_vlog2_p, i, "%vd","%vs","","");
        break;

        case 0x2B:
            if( VInstr.bit7 == 0 )
                format(o->flags,ALLEGREX_vlog2_t, i, "%vd","%vs","","");
            else
                format(o->flags,ALLEGREX_vlog2_q, i, "%vd","%vs","","");
        break;

        case 0x2C:
            if( VInstr.bit7 == 0 )
                format(o->flags,ALLEGREX_vsqrt_s, i, "%vd","%vs","","");
            else
                format(o->flags,ALLEGREX_vsqrt_p, i, "%vd","%vs","","");
        break;

        case 0x2D:
            if( VInstr.bit7 == 0 )
                format(o->flags,ALLEGREX_vsqrt_t, i, "%vd","%vs","","");
            else
                format(o->flags,ALLEGREX_vsqrt_q, i, "%vd","%vs","","");
        break;

        case 0x2E:
            if( VInstr.bit7 == 0 )
                format(o->flags,ALLEGREX_vasin_s, i, "%vd","%vs","","");
            else
                format(o->flags,ALLEGREX_vasin_p, i, "%vd","%vs","","");
        break;

        case 0x2F:
            if( VInstr.bit7 == 0 )
                format(o->flags,ALLEGREX_vasin_t, i, "%vd","%vs","","");
            else
                format(o->flags,ALLEGREX_vasin_q, i, "%vd","%vs","","");
        break;

        case 0x30:
            if( VInstr.bit7 == 0 )
                format(o->flags,ALLEGREX_vnrcp_s, i, "%vd","%vs","","");
            else
                format(o->flags,ALLEGREX_vnrcp_p, i, "%vd","%vs","","");
        break;

        case 0x31:
            if( VInstr.bit7 == 0 )
                format(o->flags,ALLEGREX_vnrcp_t, i, "%vd","%vs","","");
            else
                format(o->flags,ALLEGREX_vnrcp_q, i, "%vd","%vs","","");
        break;

        case 0x34:
            if( VInstr.bit7 == 0 )
                format(o->flags,ALLEGREX_vnsin_s, i, "%vd","%vs","","");
            else
                format(o->flags,ALLEGREX_vnsin_p, i, "%vd","%vs","","");
        break;

        case 0x35:
            if( VInstr.bit7 == 0 )
                format(o->flags,ALLEGREX_vnsin_t, i, "%vd","%vs","","");
            else
                format(o->flags,ALLEGREX_vnsin_q, i, "%vd","%vs","","");
        break;

        case 0x38:
            if( VInstr.bit7 == 0 )
                format(o->flags,ALLEGREX_vrexp2_s, i, "%vd","%vs","","");
            else
                format(o->flags,ALLEGREX_vrexp2_p, i, "%vd","%vs","","");
        break;

        case 0x39:
            if( VInstr.bit7 == 0 )
                format(o->flags,ALLEGREX_vrexp2_t, i, "%vd","%vs","","");
            else
                format(o->flags,ALLEGREX_vrexp2_q, i, "%vd","%vs","","");
        break;

        case 0x64:
            if( VInstr.bit7 == 1 )
                format(o->flags,ALLEGREX_vf2h_p, i, "%vd","%vs","","");
        break;

        case 0x65:
            if( VInstr.bit7 == 1 )
                format(o->flags,ALLEGREX_vf2h_q, i, "%vd","%vs","","");
        break;

        case 0x66:
            if( VInstr.bit7 == 0 )
                format(o->flags,ALLEGREX_vh2f_s, i, "%vd","%vs","","");
            else
                format(o->flags,ALLEGREX_vh2f_p, i, "%vd","%vs","","");
        break;

        case 0x6C:
            if( VInstr.bit7 == 0 )
                format(o->flags,ALLEGREX_vsbz_s, i, "%vd","%vs","","");
        break;

        case 0x6E:
            if( VInstr.bit7 == 0 )
                format(o->flags,ALLEGREX_vlgb_s, i, "%vd","%vs","","");
        break;

        case 0x74:
            if( VInstr.bit7 == 0 )
                format(o->flags,ALLEGREX_vus2i_s, i, "%vd","%vs","","");
            else
                format(o->flags,ALLEGREX_vus2i_p, i, "%vd","%vs","","");
        break;

        case 0x76:
            if( VInstr.bit7 == 0 )
                format(o->flags,ALLEGREX_vs2i_s, i, "%vd","%vs","","");
            else
                format(o->flags,ALLEGREX_vs2i_p, i, "%vd","%vs","","");
        break;

        case 0x79:
            if( VInstr.bit7 == 1 )
                format(o->flags,ALLEGREX_vi2uc_q, i, "%vd","%vs","","");
        break;

        case 0x7B:
            if( VInstr.bit7 == 1 )
                format(o->flags,ALLEGREX_vi2c_q, i, "%vd","%vs","","");
        break;

        case 0x7C:
            if( VInstr.bit7 == 1 )
                format(o->flags,ALLEGREX_vi2us_p, i, "%vd","%vs","","");
        break;

        case 0x7D:
            if( VInstr.bit7 == 1 )
                format(o->flags,ALLEGREX_vi2us_q, i, "%vd","%vs","","");
        break;

        case 0x7E:
            if( VInstr.bit7 == 1 )
                format(o->flags,ALLEGREX_vi2s_p, i, "%vd","%vs","","");
        break;

        case 0x7F:
            if( VInstr.bit7 == 1 )
                format(o->flags,ALLEGREX_vi2s_q, i, "%vd","%vs","","");
        break;

        case 0x81:
            if( VInstr.bit7 == 1 )
                format(o->flags,ALLEGREX_vsrt1_q, i, "%vd","%vs","","");
        break;

        case 0x83:
            if( VInstr.bit7 == 1 )
                format(o->flags,ALLEGREX_vsrt2_q, i, "%vd","%vs","","");
        break;

        case 0x84:
            if( VInstr.bit7 == 1 )
                format(o->flags,ALLEGREX_vbfy1_p, i, "%vd","%vs","","");
        break;

        case 0x85:
            if( VInstr.bit7 == 1 )
                format(o->flags,ALLEGREX_vbfy1_q, i, "%vd","%vs","","");
        break;

        case 0x87:
            if( VInstr.bit7 == 1 )
                format(o->flags,ALLEGREX_vbfy2_q, i, "%vd","%vs","","");
        break;

        case 0x88:
            if( VInstr.bit7 == 0 )
                format(o->flags,ALLEGREX_vocp_s, i, "%vd","%vs","","");
            else
                format(o->flags,ALLEGREX_vocp_p, i, "%vd","%vs","","");
        break;

        case 0x89:
            if( VInstr.bit7 == 0 )
                format(o->flags,ALLEGREX_vocp_t, i, "%vd","%vs","","");
            else
                format(o->flags,ALLEGREX_vocp_q, i, "%vd","%vs","","");
        break;

        case 0x8A:
            if( VInstr.bit7 == 0 )
                format(o->flags,ALLEGREX_vsocp_s, i, "%vd","%vs","","");
            else
                format(o->flags,ALLEGREX_vsocp_p, i, "%vd","%vs","","");
        break;

        case 0x8C:
            if( VInstr.bit7 == 1 )
                format(o->flags,ALLEGREX_vfad_p, i, "%vd","%vs","","");
        break;

        case 0x8D:
            if( VInstr.bit7 == 0 )
                format(o->flags,ALLEGREX_vfad_t, i, "%vd","%vs","","");
            else
                format(o->flags,ALLEGREX_vfad_q, i, "%vd","%vs","","");
        break;

        case 0x8E:
            if( VInstr.bit7 == 1 )
                format(o->flags,ALLEGREX_vavg_p, i, "%vd","%vs","","");
        break;

        case 0x8F:
            if( VInstr.bit7 == 0 )
                format(o->flags,ALLEGREX_vavg_t, i, "%vd","%vs","","");
            else
                format(o->flags,ALLEGREX_vavg_q, i, "%vd","%vs","","");
        break;

        case 0x91:
            if( VInstr.bit7 == 1 )
                format(o->flags,ALLEGREX_vsrt3_q, i, "%vd","%vs","","");
        break;

        case 0x93:
            if( VInstr.bit7 == 1 )
                format(o->flags,ALLEGREX_vsrt4_q, i, "%vd","%vs","","");
        break;

        case 0x94:
            if( VInstr.bit7 == 0 )
                format(o->flags,ALLEGREX_vsgn_s, i, "%vd","%vs","","");
            else
                format(o->flags,ALLEGREX_vsgn_p, i, "%vd","%vs","","");
        break;

        case 0x95:
            if( VInstr.bit7 == 0 )
                format(o->flags,ALLEGREX_vsgn_t, i, "%vd","%vs","","");
            else
                format(o->flags,ALLEGREX_vsgn_q, i, "%vd","%vs","","");
        break;

        case 0xB3:
            if( VInstr.bit7 == 1 )
                format(o->flags,ALLEGREX_vt4444_q, i, "%vd","%vs","","");
        break;

        case 0xB5:
            if( VInstr.bit7 == 1 )
                format(o->flags,ALLEGREX_vt5551_q, i, "%vd","%vs","","");
        break;

        case 0xB7:
            if( VInstr.bit7 == 1 )
                format(o->flags,ALLEGREX_vt5650_q, i, "%vd","%vs","","");
        break;
    }

    VInstr.funct11 >>= 1;
    if( VInstr.funct11 == 0x50 )
    {
        if( VInstr.bit7 == 0 )
        {
            VInstr.imm = ( i->opcode >> 8 ) & 0xFF;
            format(o->flags,ALLEGREX_vmfvc, i, "%vd","%vi","","");
        }
    }
}

static void op_VFPU_53(Opcode *o, Instr *i)
{
    o=o; // get rid of warning  

    DecodeVFPUInst( i->opcode );

    VInstr.vt = (unsigned char) ( ( (i->opcode & 0x01 ) << 5 ) + ( i->rt ) );
    VInstr.offs = (unsigned short) ( i->opcode >> 2 ) & 0x3FFF;
    if( VInstr.bit1 == 0 )
        format(o->flags,ALLEGREX_lvl_q , i, "%vt","%vo(%rs)","","");
    else
        format(o->flags,ALLEGREX_lvr_q , i, "%vt","%vo(%rs)","","");
}

static void op_VFPU_54(Opcode *o, Instr *i)
{
    o=o; // get rid of warning  

    DecodeVFPUInst( i->opcode );

    VInstr.vt = (unsigned char) ( ( (i->opcode & 0x01 ) << 5 ) + ( i->rt ) );
    VInstr.offs = (unsigned short) ( i->opcode >> 2 ) & 0x3FFF;
    if( VInstr.bit1 == 0 )
        format(o->flags,ALLEGREX_lv_q , i, "%vt","%vo(%rs)","","");
}


static void op_VFPU_55(Opcode *o, Instr *i)
{
    o=o; // get rid of warning  

    DecodeVFPUInst( i->opcode );

    VInstr.imm = i->opcode & 0xFFFFFF;
    switch( VInstr.funct2 )
    {

        case 0x00:
            format(o->flags,ALLEGREX_vpfxs, i, "%vi","","","");
        break;

        case 0x01:
            format(o->flags,ALLEGREX_vpfxt, i, "%vi","","","");
        break;

        case 0x02:
            format(o->flags,ALLEGREX_vpfxd, i, "%vi","","","");
        break;
    }

    VInstr.imm = i->opcode & 0xFFFF;
    switch( VInstr.funct3 )
    {

        case 0x06:
            format(o->flags,ALLEGREX_viim_s, i, "%vt","%vi","","");
        break;

        case 0x07:
            format(o->flags,ALLEGREX_vfim_s, i, "%vt","%vi","","");
        break;
    }
}

static void op_VFPU_60(Opcode *o, Instr *i)
{
    o=o; // get rid of warning  

    DecodeVFPUInst( i->opcode );

    if( i->rs == 0x1D )
    {
        VInstr.imm = i->rt;

        if( ( VInstr.bit7 == 1 ) && ( VInstr.bit15 == 0 ) )
            format(o->flags,ALLEGREX_vrot_p, i, "%vd","%vs","%vi","");

        if( ( VInstr.bit7 == 0 ) && ( VInstr.bit15 == 1 ) )
            format(o->flags,ALLEGREX_vrot_t, i, "%vd","%vs","%vi","");

        if( ( VInstr.bit7 == 1 ) && ( VInstr.bit15 == 1 ) )
            format(o->flags,ALLEGREX_vrot_q, i, "%vd","%vs","%vi","");
    }

    switch( VInstr.funct11 )
    {
        case 0x700:
            if( VInstr.bit7 == 1 )
                format(o->flags,ALLEGREX_vmmov_p, i, "%vd","%vs","","");
        break;

        case 0x701:
            if( VInstr.bit7 == 0 )
                format(o->flags,ALLEGREX_vmmov_t, i, "%vd","%vs","","");
            else
                format(o->flags,ALLEGREX_vmmov_q, i, "%vd","%vs","","");
        break;
    }

    switch( VInstr.funct3 )
    {
        case 0x00:
            if( ( VInstr.bit7 == 1 ) && ( VInstr.bit15 == 0 ) )
                format(o->flags,ALLEGREX_vmmul_p, i, "%vd","%vs","%vt","");

            if( ( VInstr.bit7 == 0 ) && ( VInstr.bit15 == 1 ) )
                format(o->flags,ALLEGREX_vmmul_t, i, "%vd","%vs","%vt","");

            if( ( VInstr.bit7 == 1 ) && ( VInstr.bit15 == 1 ) )
                format(o->flags,ALLEGREX_vmmul_q, i, "%vd","%vs","%vt","");
        break;

        case 0x01:
            if( ( VInstr.bit7 == 0 ) && ( VInstr.bit15 == 0 ) )
                format(o->flags,ALLEGREX_vhtfm2_p, i, "%vd","%vs","%vt","");

            if( ( VInstr.bit7 == 1 ) && ( VInstr.bit15 == 0 ) )
                format(o->flags,ALLEGREX_vtfm2_p, i, "%vd","%vs","%vt","");
        break;

        case 0x02:
            if( ( VInstr.bit7 == 1 ) && ( VInstr.bit15 == 0 ) )
                format(o->flags,ALLEGREX_vhtfm3_t, i, "%vd","%vs","%vt","");

            if( ( VInstr.bit7 == 0 ) && ( VInstr.bit15 == 1 ) )
                format(o->flags,ALLEGREX_vtfm3_t, i, "%vd","%vs","%vt","");
        break;

        case 0x03:
            if( ( VInstr.bit7 == 0 ) && ( VInstr.bit15 == 1 ) )
                format(o->flags,ALLEGREX_vhtfm4_q, i, "%vd","%vs","%vt","");

            if( ( VInstr.bit7 == 1 ) && ( VInstr.bit15 == 1 ) )
                format(o->flags,ALLEGREX_vtfm4_q, i, "%vd","%vs","%vt","");
        break;

        case 0x04:
            if( ( VInstr.bit7 == 1 ) && ( VInstr.bit15 == 0 ) )
                format(o->flags,ALLEGREX_vmscl_p, i, "%vd","%vs","%vt","");

            if( ( VInstr.bit7 == 0 ) && ( VInstr.bit15 == 1 ) )
                format(o->flags,ALLEGREX_vmscl_q, i, "%vd","%vs","%vt","");

            if( ( VInstr.bit7 == 1 ) && ( VInstr.bit15 == 1 ) )
                format(o->flags,ALLEGREX_vmscl_q, i, "%vd","%vs","%vt","");
        break;

        case 0x05:
            if( ( VInstr.bit7 == 0 ) && ( VInstr.bit15 == 1 ) )
                format(o->flags,ALLEGREX_vcrsp_t, i, "%vd","%vs","%vt","");

            if( ( VInstr.bit7 == 1 ) && ( VInstr.bit15 == 1 ) )
                format(o->flags,ALLEGREX_vqmul_q, i, "%vd","%vs","%vt","");
        break;
    }

    
    switch( VInstr.funct19 )
    {

        case 0x70601:
            format(o->flags,ALLEGREX_vmidt_p, i, "%vd","","","");
        break;

        case 0x70700:
            format(o->flags,ALLEGREX_vmidt_t, i, "%vd","","","");
        break;

        case 0x70701:
            format(o->flags,ALLEGREX_vmidt_q, i, "%vd","","","");
        break;

        case 0x70E01:
            format(o->flags,ALLEGREX_vmone_p, i, "%vd","","","");
        break;

        case 0x70F00:
            format(o->flags,ALLEGREX_vmone_t, i, "%vd","","","");
        break;

        case 0x70F01:
            format(o->flags,ALLEGREX_vmone_q, i, "%vd","","","");
        break;

        case 0x70C01:
            format(o->flags,ALLEGREX_vmzero_p, i, "%vd","","","");
        break;

        case 0x70D00:
            format(o->flags,ALLEGREX_vmzero_t, i, "%vd","","","");
        break;

        case 0x70D01:
            format(o->flags,ALLEGREX_vmzero_q, i, "%vd","","","");
        break;
    }
}

static void op_VFPU_61(Opcode *o, Instr *i)
{
    o=o; // get rid of warning  

    DecodeVFPUInst( i->opcode );

    VInstr.vt = (unsigned char) ( ( (i->opcode & 0x01 ) << 5 ) + ( i->rt ) );
    VInstr.offs = (unsigned short) ( i->opcode >> 2 ) & 0x3FFF;
    if( VInstr.bit1 == 0 )
        format(o->flags,ALLEGREX_svl_q , i, "%vt","%vo(%rs)","","");
    else
        format(o->flags,ALLEGREX_svr_q , i, "%vt","%vo(%rs)","","");
}

static void op_VFPU_62(Opcode *o, Instr *i)
{
    o=o; // get rid of warning  

    DecodeVFPUInst( i->opcode );

    VInstr.vt = (unsigned char) ( ( (i->opcode & 0x01 ) << 5 ) + ( i->rt ) );
    VInstr.offs = (unsigned short) ( i->opcode >> 2 ) & 0x3FFF;
    if( VInstr.bit1 == 0 )
        format(o->flags,ALLEGREX_sv_q , i, "%vt","%vo(%rs)","","");
    else
        format(o->flags,ALLEGREX_sv_q , i, "%vt","%vo(%rs)","wb","");
}

static void op_VFPU_63(Opcode *o, Instr *i)
{
    o=o; // get rid of warning  

    if( i->opcode == 0xFFFF0000 )
    {
        format(o->flags,ALLEGREX_vnop, i, "", "", "", "");
        return;
    }
    else if( i->opcode == 0xFFFF0320 )
    {
        format(o->flags,ALLEGREX_vsync, i, "", "", "", "");
        return;
    }
    else if( i->opcode == 0xFFFF040D )
    {
        format(o->flags,ALLEGREX_vflush, i, "", "", "", "");
        return;
    }
}

static void abs_jump(Opcode *o, Instr *i)
{
    format(o->flags,o->mnemonic, i, o->fmt1, o->fmt2, o->fmt3, o->fmt4);
}

static void rel_branch(Opcode *o, Instr *i)
{
//	if((o->flags&SIM_DROP_RT0)&&(0==i->rt))
//	{
//		char m[10];
//		strcpy(m,o->mnemonic);
//		strcat(m,"z");
//		format(o->flags,m, i, "%rs, %b");
//	}
//	else
//	{
		format(o->flags,o->mnemonic, i, o->fmt1, o->fmt2, o->fmt3, o->fmt4);
//	}
}

static void rt_rs_imm(Opcode *o, Instr *i)
{
//	if((o->flags&SIM_DROP_RSONRTEQRS)&&(i->rs==i->rt))
//	{
//		format(o->flags,o->mnemonic, i, "%rt, %i");
//	}
//	else if((o->flags&SIM_REN_LIONRS0)&&(i->rs==0))
//	{
//		format(o->flags,ALLEGREX_li , i, "%rt, %i");
//	}
//	else
//	{
		format(o->flags,o->mnemonic, i, o->fmt1, o->fmt2, o->fmt3, o->fmt4);
//	}
}

static void rt_imm(Opcode *o, Instr *i)
{
    format(o->flags,o->mnemonic, i, o->fmt1, o->fmt2, o->fmt3, o->fmt4);
}

static void rt_offs_base(Opcode *o, Instr *i)
{

//	if((o->flags&SIM_DROP_OFFS0)&&(i->imm==0))
//	{
//		format(o->flags,o->mnemonic, i, "%rt, (%rs)");
//	}
//	else
//	{
		format(o->flags,o->mnemonic, i,o->fmt1, o->fmt2, o->fmt3, o->fmt4);
//	}
}

static void ft_offs_base(Opcode *o, Instr *i)
{
    format(o->flags,o->mnemonic, i, o->fmt1, o->fmt2, o->fmt3, o->fmt4);
}

static void cache_func(Opcode *o, Instr *i)
{
    format(o->flags,o->mnemonic, i, o->fmt1, o->fmt2, o->fmt3, o->fmt4);
}

static void vt_offs_rs(Opcode *o, Instr *i)
{
    DecodeVFPUInst( i->opcode );
    
    VInstr.vt = (unsigned char) ( ( (i->opcode & 0x03 ) << 5 ) + ( i->rt ) );
    VInstr.offs = (unsigned short) ( i->opcode >> 2 ) & 0x3FFF;
    format(o->flags,o->mnemonic, i, o->fmt1, o->fmt2, o->fmt3, o->fmt4);
}

void PSPdisInit(unsigned long flags)
{
#if 0
	if(flags&SIM_NAMEDREGS)
	{
		Regs=reginfo[REGSALLEGREX].named;
	}
	else
	{
		Regs=reginfo[REGSALLEGREX].numeric;
	}
	if(flags&SIM_NAMEDREGS_FPU)
	{
		FPURegs=reginfo[REGSFPU].named;
	}
	else
	{
		FPURegs=reginfo[REGSFPU].numeric;
	}
	if(flags&SIM_NAMEDREGS_COP0)
	{
		COP0Regs=reginfo[REGSCOP0M].named;
		COP0CRegs=reginfo[REGSCOP0C].named;
	}
	else
	{
		COP0Regs=reginfo[REGSCOP0M].numeric;
		COP0CRegs=reginfo[REGSCOP0C].numeric;
	}
	if(flags&SIM_NAMEDREGS_COP1)
	{
	}
	else
	{
	}
	if(flags&SIM_NAMEDREGS_COP2)
	{
	}
	else
	{
	}
	if(flags&SIM_NAMEDREGS_VFPU)
	{
		VFPURegs=reginfo[REGSVFPU].named;
	}
	else
	{
		VFPURegs=reginfo[REGSVFPU].numeric;
	}
	if(flags&SIM_NAMEDREGS_DEBUG)
	{
		DebugRegs=reginfo[REGSDEBUG].named;
	}
	else
	{
		DebugRegs=reginfo[REGSDEBUG].numeric;
	}
#endif
	SIMFLAG=flags;
};

//----------------------------------------------------------------------


//----------------------------------------------------------------------
// analyse an instruction
// returns size of command, or 0 

int ana(void)
{
    Instr Inst;
unsigned long Cmd;

	cmd.itype = 0; // opcode
	// cmd.auxpref |= aux_1ext; ?
	// addr mode (o_imm, o_near, o_reg, o_mem, o_phrase, o_bit, o_bitnot
	// o_displ - register indirect with displacement
	cmd.Op1.type = o_void; 
	cmd.Op2.type = o_void; 
	cmd.Op3.type = o_void; 
	cmd.Op4.type = o_void; 
	
	cmd.Op1.offb = 0; 
//	cmd.Op1.b251_bitneg = 0;
//	cmd.Op1.indreg = 0; // for o_phrase
	cmd.Op1.addr = 0; // o_displ
	cmd.Op1.reg = 0; // for o_reg
	cmd.Op1.value = 0; // for o_imm
	cmd.Op1.phrase = 0; // for o_phrase, o_displ
	// dt_dword, dt_word, dt_byte
   
	cmd.Op1.dtyp = dt_word;
	cmd.Op2.dtyp = dt_word;
	cmd.Op3.dtyp = dt_word;
	cmd.Op4.dtyp = dt_word;

	cmd.size=0;

    PC  = cmd.ea;
    Cmd = (unsigned long)(get_byte(cmd.ea+3)<<24)+(get_byte(cmd.ea+2)<<16)+(get_byte(cmd.ea+1)<<8)+get_byte(cmd.ea+0);

    DecodeInst( Cmd, &Inst );

    if( opcodes[ Inst.op ].f != 0 )
    {
        opcodes[ Inst.op ].f(&opcodes[ Inst.op ], &Inst);
	cmd.size=4;
    }

	else
	{
	cmd.size=0;
	}

  return cmd.size;
}
