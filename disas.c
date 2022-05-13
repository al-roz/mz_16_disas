/*
Модуль дизассемблирования.
*/


#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "disas.h"
#include "mz.h"
#include "system.h"


// массив опкодов (от 00 до FF)
d_func opcodes[] = {
    d_add,    d_add,    d_add,    d_add,    d_add,    d_add,    d_push,   d_pop,
    d_or,     d_or,     d_or,     d_or,     d_or,     d_or,     d_push,   d_unk,
    d_adc,    d_adc,    d_adc,    d_adc,    d_adc,    d_adc,    d_push,   d_pop,
    d_sbb,    d_sbb,    d_sbb,    d_sbb,    d_sbb,    d_sbb,    d_push,   d_pop,
    d_and,    d_and,    d_and,    d_and,    d_and,    d_and,    d_es,     d_daa,
    d_sub,    d_sub,    d_sub,    d_sub,    d_sub,    d_sub,    d_cs,     d_das,
    d_xor,    d_xor,    d_xor,    d_xor,    d_xor,    d_xor,    d_ss,     d_aaa,
    d_cmp,    d_cmp,    d_cmp,    d_cmp,    d_cmp,    d_cmp,    d_ds,     d_aas,
    d_inc,    d_inc,    d_inc,    d_inc,    d_inc,    d_inc,    d_inc,    d_inc,
    d_dec,    d_dec,    d_dec,    d_dec,    d_dec,    d_dec,    d_dec,    d_dec,
    d_push,   d_push,   d_push,   d_push,   d_push,   d_push,   d_push,   d_push,
    d_pop,    d_pop,    d_pop,    d_pop,    d_pop,    d_pop,    d_pop,    d_pop,
    d_unk,    d_unk,    d_unk,    d_unk,    d_unk,    d_unk,    d_unk,    d_unk,
    d_unk,    d_unk,    d_unk,    d_unk,    d_unk,    d_unk,    d_unk,    d_unk,
    d_jo,     d_jno,    d_jb,     d_jae,    d_jz,     d_jnz,    d_jbe,    d_ja,
    d_js,     d_jns,    d_jpe,    d_jpo,    d_jl,     d_jge,    d_jle,    d_jg,  
    d_gr80,   d_gr80,   d_gr80,   d_gr80,   d_test,   d_test,   d_xchg,   d_xchg,
    d_mov,    d_mov,    d_mov,    d_mov,    d_mov,    d_lea,    d_mov,    d_pop,
    d_nop,    d_xchg,   d_xchg,   d_xchg,   d_xchg,   d_xchg,   d_xchg,   d_xchg,
    d_cbw,    d_cwd,    d_call,   d_wait,   d_pushf,  d_popf,   d_sahf,   d_lahf, 
    d_mov,    d_mov,    d_mov,    d_mov,    d_movsb,  d_movsw,  d_cmpsb,  d_cmpsw,
    d_test,   d_test,   d_stosb,  d_stosw,  d_lodsb,  d_lodsw,  d_scasb,  d_scasw,
    d_mov,    d_mov,    d_mov,    d_mov,    d_mov,    d_mov,    d_mov,    d_mov,
    d_mov,    d_mov,    d_mov,    d_mov,    d_mov,    d_mov,    d_mov,    d_mov,
    d_unk,    d_unk,    d_retn,   d_retn,   d_les,    d_lds,    d_mov,    d_mov,
    d_unk,    d_unk,    d_retf,   d_retf,   d_int3,   d_int,    d_into,   d_iret,
    d_grd0,   d_grd0,   d_grd0,   d_grd0,   d_aam,    d_aad,    d_unk,    d_xlat,
    d_unk,    d_unk,    d_unk,    d_unk,    d_unk,    d_unk,    d_unk,    d_unk,
    d_loopnz, d_loopz,  d_loop,   d_jcxz,   d_in,     d_in,     d_out,    d_out,
    d_call,   d_jmp,    d_jmp,    d_jmp,    d_in,     d_in,     d_out,    d_out,
    d_lock,   d_unk,    d_rep,    d_rep,    d_hlt,    d_cmc,    d_grf6,   d_grf6,
    d_clc,    d_stc,    d_cli,    d_sti,    d_cld,    d_std,    d_grfe,   d_grff 
};

char* addressing_Modesand_Segment_Registers[8][5] = {
    "[bx + si",  "[bx + si" , "[bx + si" , "al" , "ax",
    "[bx + di",  "[bx + di" , "[bx + di" , "cl" , "cx",
    "[bp + si",  "[bp + si" , "[bp + si" , "dl" , "dx",
    "[bp + di",  "[bp + di" , "[bp + di" , "bl" , "bx",
       "[si",       "[si" ,     "[si" ,    "ah" , "sp",
       "[di",       "[di" ,     "[di" ,    "ch" , "bp",
       "[",         "[bp" ,     "[bp" ,    "dh" , "si",
       "[bx",       "[bx" ,     "[bx" ,    "bh" , "di"
};

char* reg_Field_Value_Word[8] = { "ax", "cx", "dx", "bx", "sp", "bp", "si", "di" };

char* reg_Field_Value_Byte[8] = { "al", "cl", "dl", "bl", "ah", "ch", "dh", "bh" };

char* seg_Reg_Field_Value[4] = { "es", "cs", "ss", "ds" };

//d_func GR1[] = {d_add, d_or, d_adc, d_sbb, d_and, d_sub, d_xor, d_cmp};
char* GR1[] = { "add    ", "or     ", "adc    ", "sbb    ", "and    ", "sub    ", "xor    ", "cmp    " };
//d_func GR2[] = {d_rol, d_ror, d_rcl, d_rcr, d_shl, d_shr, d_unk , d_sar};
char* GR2[] = { "rol    ", "ror    ", "rcl    ", "rcr    ", "shl    ", "shr    ", "unk    ", "sar    " };
//d_func GR3[] = {d_test, d_unk, d_not, d_neg, d_mul, d_imul, d_div , d_idiv};
char* GR3[] = { "test   ", "unk    ", "not    ", "neg    ", "mul    ", "imul   ", "div    ", "idiv   " };
//d_func GR4[] = {d_inc, d_dec, d_unk, d_unk, d_unk, d_unk, d_unk , d_unk };
char* GR4[] = { "inc    ","dec     " };
//d_func GR5[] = {d_inc, d_dec, d_call, d_call, d_jmp, d_jmp, d_push , d_unk };
char* GR5[] = { "inc    ","dec     ", "call   ", "call   ", "jmp    ", "jmp    ", "push   ", "unk    " };


int change_seg = -1;

//
// функция вывода одной дизассемблированной инстркуции на экран
//
void PrintInstruction(MZHeaders *mz, DWORD pos, DWORD inst_len, char *inst) {
    unsigned int i;
    if (change_seg == -1)
    {
        printf("%04X:%04X ", mz->doshead->e_cs + IMAGE_BASE_SEG + (SIZE_OF_SEG_P * (pos / SIZE_OF_SEG_B)), pos % SIZE_OF_SEG_B);
        if (*(mz->code + pos - 1) == 0x2E || *(mz->code + pos - 1) == 0x26 || *(mz->code + pos - 1) == 0x36 || *(mz->code + pos - 1) == 0x3E)
        {
            for (int i = 0; i < inst_len + 1; i++) {
                printf("%02X", (mz->code + pos)[i-1]);
            }
            for (i = inst_len + 1; i < INSTRUCTION_LEN; i++) {
                printf("  ");
            }
        }
        else
        {
            for (i = 0; i < inst_len; i++) {
                printf("%02X", (mz->code + pos)[i]);
            }
            for (i = inst_len; i < INSTRUCTION_LEN; i++) {
                printf("  ");
            }
        }
        
        printf(" %s\n", inst);
    }
    return;
}


//
// функция дизассемблирования сегмента кода
//
void DisasCodeSeg(MZHeaders *mz) {
    DWORD pos = 0, inst_len;
    char inst[256];
    
    printf("Disassembled code segment\n");

    ApplyRelocs(mz, IMAGE_BASE_SEG);
    while (pos < mz->code_size) {
        inst_len = opcodes[*(mz->code + pos)](mz, pos, inst);
        PrintInstruction(mz, pos, inst_len, inst);
        pos += inst_len;
    }
    RemoveRelocs(mz, IMAGE_BASE_SEG);

    return;
}

DWORD defining_the_addressing_mode(MZHeaders* mz, DWORD pos, char* buffer)
{
    BYTE W = *(mz->code + pos) & 1;
    BYTE DS = *(mz->code + pos) & 2;
    DS = DS >> 1;
    BYTE SEG = *(mz->code + pos + 1);
    BYTE RM = SEG & 7;
    BYTE REG = SEG & 56;
    REG = REG >> 3;
    BYTE MOD = SEG & 192;
    MOD = MOD >> 6;

    DWORD RETURN = 0;
    if (MOD == 3)
    {
        strcpy(buffer, addressing_Modesand_Segment_Registers[RM][MOD + W]);
        return 1;
    }        
    else
        strcpy(buffer, addressing_Modesand_Segment_Registers[RM][MOD]);

    if (MOD == 0)
        RETURN = 1;

    
    if (change_seg != -1)
    {
        
        char tmp[50] = "";
        strcpy(tmp, seg_Reg_Field_Value[change_seg]);        
        strcat(tmp, ":");
        strcat(tmp, buffer);
        strcpy(buffer, tmp);
        change_seg = -1;
    }
    //printf("MOD == %d\n", MOD);
    //printf("REG == %d\n", REG);
    if (MOD == 1)
    {
        BYTE OFFSET = *(mz->code + pos + 2);
        CHAR BUFFER_OFFSET[20] = "";
        itoa(OFFSET, BUFFER_OFFSET, 16);
        strcat(buffer, " + ");
        strcat(buffer, BUFFER_OFFSET);
        strcat(buffer, "h");
        RETURN = 2;
    }
    if (MOD == 2 || (MOD == 0 && RM == 6))
    {
        DWORD OFFSET = *(mz->code + pos + 3);
        OFFSET = OFFSET << 8;
        OFFSET += *(mz->code + pos + 2);
        CHAR BUFFER_OFFSET[20] = "";
        itoa(OFFSET, BUFFER_OFFSET, 16);
        strcat(buffer, " + ");
        strcat(buffer, BUFFER_OFFSET);
        strcat(buffer, "h");
        RETURN = 3;
    }
    strcat(buffer, "]");

    if (W == 0)
    {
        char tmp[50] = "byte ptr ";
        strcat(tmp, buffer);
        strcpy(buffer, tmp);
    }
    else
    {
        char tmp[50] = "word ptr ";
        strcat(tmp, buffer);
        strcpy(buffer, tmp);
    }

    return RETURN;


}

void defining_the_register_mod(MZHeaders* mz, DWORD pos, char* buffer)
{
    BYTE W = *(mz->code + pos) & 1;
    BYTE REG = *(mz->code + pos + 1) & 56;
    REG = REG >> 3;
    if (W == 1)
        strcpy(buffer, reg_Field_Value_Word[REG]);
    else
        strcpy(buffer, reg_Field_Value_Byte[REG]);
}

void defining_the_segment_register_mod(MZHeaders* mz, DWORD pos, char* buffer)
{
    BYTE SR = *(mz->code + pos + 1);
    SR = SR >> 3;
    SR = SR & 3;
    strcat(buffer, seg_Reg_Field_Value[SR]);
}

void swap_source_and_recipent(char* source, char* recipient)
{
    char tmp[50] = "";
    strcpy(tmp, source);
    strcpy(source, recipient);
    strcpy(recipient, tmp);
}

DWORD find_offset(MZHeaders* mz, DWORD pos, BYTE mod)
{
    if (mod == 2)
    {
        WORD OFFSET = *(mz->code + pos);
        OFFSET = OFFSET << 8;
        OFFSET += *(mz->code + pos - 1);
        return OFFSET;
    }
    if (mod == 1)
    {
        WORD OFFSET = *(mz->code + pos);
        return OFFSET;
    }
    if (mod == 3)
    {
        DWORD OFFSET = *(mz->code + pos);
        OFFSET = OFFSET << 8;
        OFFSET += *(mz->code + pos - 1);
        OFFSET = OFFSET << 8;
        OFFSET += *(mz->code + pos - 2);
        OFFSET = OFFSET << 8;
        OFFSET += *(mz->code + pos - 3);
        return OFFSET;
    }
};

void find_offset_str(MZHeaders* mz, DWORD pos, char* buffer, BYTE mod)
{
    if (mod == 2)
    {
        WORD OFFSET = *(mz->code + pos);
        OFFSET = OFFSET << 8;
        OFFSET += *(mz->code + pos - 1);
        itoa(OFFSET, buffer, 16);
        strcat(buffer, "h");
    }
    else
    {
        WORD OFFSET = *(mz->code + pos);
        itoa(OFFSET, buffer, 16);
        strcat(buffer, "h");
    }
}

void find_memoffset_str(MZHeaders* mz, DWORD pos, char* buffer, BYTE mod)
{
    char tmp[50] = "[";
    find_offset_str(mz, pos, buffer, mod);
    strcat(tmp, buffer);
    strcat(tmp, "]");
    strcpy(buffer, tmp);

    if (change_seg != -1)
    {

        char tmp[50] = "";
        strcpy(tmp, seg_Reg_Field_Value[change_seg]);
        strcat(tmp, ":");
        strcat(tmp, buffer);
        strcpy(buffer, tmp);
        change_seg = -1;
    }
}

void add_source_and_recipient_to_inst(char* inst, char* source, char* recipient)
{
    strcat(inst, source);
    strcat(inst, ",");
    strcat(inst, recipient);
}

DWORD ax_al_with_imm16_imm8(MZHeaders* mz, DWORD pos, char* inst)
{
    BYTE OPERATION = *(mz->code + pos);

    BYTE DS = OPERATION & 2;
    DS = DS >> 1;
    BYTE W = OPERATION & 1;

    char source[50] = "";
    char recipient[50] = "";

    if (W == 0)
        strcpy(source, "al");
    else
        strcpy(source, "ax");

    if (W == 1)
        // find_memoffset_str(mz, pos + 2, recipient, 2);
        find_offset_str(mz, pos + 2, recipient, 2);
    else
        //find_memoffset_str(mz, pos + 1, recipient, 1);
        find_offset_str(mz, pos + 1, recipient, 1);

    if (DS == 1)
        swap_source_and_recipent(source, recipient);

    add_source_and_recipient_to_inst(inst, source, recipient);

    if (W == 1)
        return 3;
    else
        return 2;
}

DWORD r16_r8_with_rm16_rm8(MZHeaders* mz, DWORD pos, char* inst)
{
    BYTE RETURN = 0;
    char source[50] = "";
    char recipient[50] = "";
    BYTE OPERATION = *(mz->code + pos);

    BYTE DS = OPERATION & 2;
    DS = DS >> 1;
    BYTE W = OPERATION & 1;

    RETURN = defining_the_addressing_mode(mz, pos, recipient);

    defining_the_register_mod(mz, pos, source);

    if (DS == 0)
        swap_source_and_recipent(source, recipient);

    add_source_and_recipient_to_inst(inst, source, recipient);

    return (RETURN + 1);
}

DWORD rm16_rm8_with_imm16_imm8(MZHeaders* mz, DWORD pos, char* inst)
{
    BYTE OPERATION = *(mz->code + pos);
};

void find_offset_for_jamp_str(MZHeaders* mz, DWORD pos, char* buffer, BYTE mod)
{
    if (mod == 1)
    {
        char tmp[50] = "";
        char OFFSET = find_offset(mz, pos + 1, 1);
        itoa(mz->doshead->e_cs + IMAGE_BASE_SEG, tmp, 16);
        strcat(buffer, tmp);
        strcpy(tmp, "");
        strcat(buffer, ":");
        itoa(pos + OFFSET + 2, tmp, 16);
        strcat(buffer, tmp);
    }
    if (mod == 2)
    {
        char tmp[50] = "";
        char OFFSET = find_offset(mz, pos + 2, 2);
        itoa(mz->doshead->e_cs + IMAGE_BASE_SEG, tmp, 16);
        strcat(buffer, tmp);
        strcpy(tmp, "");
        strcat(buffer, ":");
        itoa(pos + OFFSET + 3, tmp, 16);
        strcat(buffer, tmp);
    }
    if (mod == 3)
    {

    }

}

//
// функции обработки команд
//
DWORD d_aaa(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "aaa");
    return 1;
}

DWORD d_aad(MZHeaders *mz, DWORD pos, char *inst){
    if (*(mz->code + pos + 1) == 10) {
        strcpy(inst, "aad");
    }
    else {
        sprintf(inst, "aad    %u", *(mz->code + pos + 1));
    }
    return 2;
}

DWORD d_aam(MZHeaders *mz, DWORD pos, char *inst){
    if (*(mz->code + pos + 1) == 10) {
        strcpy(inst, "aam");
    }
    else {
        sprintf(inst, "aam    %u", *(mz->code + pos + 1));
    }
    return 2;
}

DWORD d_aas(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "aas");
    return 1;
}

DWORD d_adc(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "adc    ");
    BYTE OPERATION = *(mz->code + pos);
    if (OPERATION >= 0x10 && OPERATION <= 0x13)
    {
        return r16_r8_with_rm16_rm8(mz, pos, inst);
    }
    if (OPERATION == 0x14 || OPERATION == 0x15)
    {
        return ax_al_with_imm16_imm8(mz, pos, inst);
    }
}

DWORD d_add(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "add    ");
    BYTE OPERATION = *(mz->code + pos);

    if (OPERATION >= 0x00 && OPERATION <= 0x03)
    {
        return r16_r8_with_rm16_rm8(mz, pos, inst);
    }
    if (OPERATION == 0x04 || OPERATION == 0x05)
    {
        return ax_al_with_imm16_imm8(mz, pos, inst);
    }    
}

DWORD d_and(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "and    ");
    BYTE OPERATION = *(mz->code + pos);

    if (OPERATION >= 0x20 && OPERATION <= 0x23)
    {
        return r16_r8_with_rm16_rm8(mz, pos, inst);
    }
    if (OPERATION == 0x24 || OPERATION == 0x25)
    {
        return ax_al_with_imm16_imm8(mz, pos, inst);
    }
}

DWORD d_call(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "call   ");
    BYTE OPERATION = *(mz->code + pos);
    char tmp[50] = "";
    if (OPERATION == 0xE8)
    {
        find_offset_str(mz, pos + 2, tmp, 2);
        strcat(inst, tmp);
        return 3;
    }
    if (OPERATION == 0x9A)
    {
        strcat(inst, "far ptr ");
        char tmp[50] = "";
        short OFFSET = find_offset(mz, pos + 4, 2);
        itoa(OFFSET, tmp, 16);
        strcat(inst, tmp);
        strcpy(tmp, "");
        strcat(inst, ":");
        OFFSET = find_offset(mz, pos + 2, 2);
        itoa(OFFSET, tmp, 16);
        strcat(inst, tmp);
        return 5;
    }

    
}

DWORD d_cbw(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "cbw");
    return 1;
}

DWORD d_clc(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "clc");
    return 1;
}

DWORD d_cld(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "cld");
    return 1;
}

DWORD d_cli(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "cli");
    return 1;
}

DWORD d_cmc(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "cmc");
    return 1;
}

DWORD d_cmp(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "cmp    ");
    BYTE OPERATION = *(mz->code + pos);

    if (OPERATION >= 0x38 && OPERATION <= 0x3B)
    {
        return r16_r8_with_rm16_rm8(mz, pos, inst);
    }
    if (OPERATION == 0x3C || OPERATION == 0x3D)
    {
        return ax_al_with_imm16_imm8(mz, pos, inst);
    }
}

DWORD d_cmpsb(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "cmpsb");
    return 1;
}

DWORD d_cmpsw(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "cmpsw");
    return 1;
}

DWORD d_cwd(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "cwd");
    return 1;
}

DWORD d_daa(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "das");
    return 1;
}

DWORD d_das(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "das");
    return 1;
}

DWORD d_dec(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "dec    ");
    char source[50] = "";
    char recipient[50] = "";
    BYTE OPERATION = *(mz->code + pos);
    strcat(source, reg_Field_Value_Word[OPERATION - 0x48]);
    find_offset_str(mz, pos + 2, recipient, 2);
    add_source_and_recipient_to_inst(inst, source, recipient);
    return 3;
}

DWORD d_div(MZHeaders *mz, DWORD pos, char *inst){
    return d_unk(mz, pos, inst);
}

DWORD d_hlt(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "hlt");
    return 1;
}

DWORD d_idiv(MZHeaders *mz, DWORD pos, char *inst){
    return d_unk(mz, pos, inst);
}

DWORD d_imul(MZHeaders *mz, DWORD pos, char *inst){
    return d_unk(mz, pos, inst);
}

DWORD d_in(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "in     ");
    BYTE OPERATION = *(mz->code + pos);
    char recipient[50] = "";
    if (OPERATION == 0xE4 || OPERATION == 0xEC)
        strcat(inst, "al");
    if (OPERATION == 0xE5 || OPERATION == 0xED)
        strcat(inst, "ax");

    if (OPERATION == 0xE4 || OPERATION == 0xE5)
    {
        find_memoffset_str(mz, pos, recipient, 1);
        strcat(inst, recipient);
        return 2;
    }
    if (OPERATION == 0xEC || OPERATION == 0xED)
    {
        strcat(inst, "dx");
        return 1;
    }
}

DWORD d_inc(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "inc    ");
    char source[50] = "";
    char recipient[50] = "";
    BYTE OPERATION = *(mz->code + pos);
    strcat(source, reg_Field_Value_Word[OPERATION - 0x40]);
    strcat(inst, source);
    return 1;
    
}

DWORD d_int(MZHeaders *mz, DWORD pos, char *inst){
    sprintf(inst, "int    %2Xh", *(mz->code + pos + 1));
    return 2;
}

DWORD d_int3(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "int    3");
    return 1;
}

DWORD d_into(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "into");
    return 1;
}

DWORD d_iret(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "iret");
    return 1;
}

DWORD d_ja(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "ja     ");
    find_offset_for_jamp_str(mz, pos, inst, 1);
    return 2;
}

DWORD d_jae(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "jae    ");
    find_offset_for_jamp_str(mz, pos, inst, 1);
    return 2;
}

DWORD d_jb(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "jb     ");
    find_offset_for_jamp_str(mz, pos, inst, 1);
    return 2;
}

DWORD d_jbe(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "jbe    ");
    find_offset_for_jamp_str(mz, pos, inst, 1);
    return 2;
}

DWORD d_jg(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "jg     ");
    find_offset_for_jamp_str(mz, pos, inst, 1);
    return 2;
}

DWORD d_jge(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "jge    ");
    find_offset_for_jamp_str(mz, pos, inst, 1);
    return 2;
}

DWORD d_jl(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "jl     ");
    find_offset_for_jamp_str(mz, pos, inst, 1);
    return 2;
}

DWORD d_jle(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "jle    ");
    find_offset_for_jamp_str(mz, pos, inst, 1);
    return 2;
}

DWORD d_jno(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "jno    ");
    find_offset_for_jamp_str(mz, pos, inst, 1);
    return 2;
}

DWORD d_jns(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "jns    ");
    find_offset_for_jamp_str(mz, pos, inst, 1);
    return 2;;
}

DWORD d_jnz(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "jnz    ");
    find_offset_for_jamp_str(mz, pos, inst, 1);
    return 2;
}

DWORD d_jo(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "jo     ");
    find_offset_for_jamp_str(mz, pos, inst, 1);
    return 2;

}

DWORD d_jpe(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "jpe    ");
    find_offset_for_jamp_str(mz, pos, inst, 1);
    return 2;
}

DWORD d_jpo(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "jpo    ");
    find_offset_for_jamp_str(mz, pos, inst, 1);;
    return 2;
}

DWORD d_js(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "js     ");
    find_offset_for_jamp_str(mz, pos, inst, 1);
    return 2;
}

DWORD d_jz(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "jz     ");
    find_offset_for_jamp_str(mz, pos, inst, 1);
    return 2;
}

DWORD d_jcxz(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "jcxz   ");
    find_offset_for_jamp_str(mz, pos, inst, 1);
    return 2;
}

DWORD d_jmp(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "jmp    ");
    char tmp[50] = "";
    BYTE OPERATION = *(mz->code + pos);
    if (OPERATION == 0xEB)
    {
        find_offset_for_jamp_str(mz, pos, inst, 1);
        return 2;
    }
    if (OPERATION == 0xE9)
    {
        find_offset_for_jamp_str(mz, pos, inst, 2);
        return 3;
    }
    if (OPERATION == 0xEA)
    {
        strcat(inst, "far ptr ");
        char tmp[50] = "";
        short OFFSET = find_offset(mz, pos + 4, 2);
        itoa(OFFSET, tmp, 16);
        strcat(inst, tmp);
        strcpy(tmp, "");
        strcat(inst, ":");
        OFFSET = find_offset(mz, pos + 2, 2);
        itoa(OFFSET, tmp, 16);
        strcat(inst, tmp);
        return 5;
    }
        
}

DWORD d_lahf(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "lahf");
    return 1;
}

DWORD d_lds(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "lds    ");
    char source[50] = "";
    char recipient[50] = "";
    BYTE RETURN = 0;
    defining_the_register_mod(mz, pos, source);
    RETURN = defining_the_addressing_mode(mz, pos, recipient);
    strcat(inst, source);
    strcat(inst, ",d");
    strcat(inst, recipient);
    return RETURN + 1;
}

DWORD d_lea(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "lea    ");
    return r16_r8_with_rm16_rm8(mz,pos,inst);
}

DWORD d_les(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "les    ");
    PBYTE tmp = mz->code + pos;
    *(PWORD)tmp += 1;
    char source[50] = "";
    char recipient[50] = "";
    BYTE RETURN = 0;
    defining_the_register_mod(mz, pos, source);
    RETURN = defining_the_addressing_mode(mz, pos, recipient);
    strcat(inst, source);
    strcat(inst, ",d");
    strcat(inst, recipient);
    *(PWORD)tmp -= 1;
    return RETURN + 1;
}

DWORD d_lock(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "lock");
    return 1;
}

DWORD d_lodsb(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "lodsb");
    return 1;
}

DWORD d_lodsw(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "lodsw");
    return 1;
}

DWORD d_loop(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "loop   ");
    char tmp[50] = "";
    find_offset_str(mz, pos + 1, tmp, 1);
    strcat(inst, tmp);
    return 2;
    
}

DWORD d_loopnz(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "loopnz ");
    char tmp[50] = "";
    find_offset_str(mz, pos + 1, tmp, 1);
    strcat(inst, tmp);
    return 2;
}

DWORD d_loopz(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "loopz  ");
    char tmp[50] = "";
    find_offset_str(mz, pos + 1, tmp, 1);
    strcat(inst, tmp);
    return 2;
}

DWORD d_mov(MZHeaders *mz, DWORD pos, char *inst){

    strcpy(inst, "mov    ");
    BYTE RETURN = 0;
    char source[50] = "";
    char recipient[50] = "";

    /*PBYTE tmp = mz->data + mz->relocs[0].segment * 16 * sizeof(BYTE) + mz->relocs[0].offset + 7;
    *(PWORD)tmp = 0xA2;*/
    //mov bx,
    BYTE OPERATION = *(mz->code + pos);
    if (OPERATION >= 0xB8 && OPERATION <= 0xBF)
    {        
        strcat(source, reg_Field_Value_Word[OPERATION - 0xB8]);
        find_offset_str(mz, pos + 2, recipient, 2);
        add_source_and_recipient_to_inst(inst, source, recipient);
        return 3;
    }
    //mov bh, 123h
    if (OPERATION >= 0xB0 && OPERATION <= 0xB7)
    {
        strcat(source, reg_Field_Value_Byte[OPERATION - 0xB0]);
        find_offset_str(mz, pos + 1, recipient, 1);
        add_source_and_recipient_to_inst(inst, source, recipient);
        return 2;
    }

    if (OPERATION == 0xC6 || OPERATION == 0xC7)
    {
        RETURN = defining_the_addressing_mode(mz, pos, source);
        if (OPERATION == 0xC6)
        {
            find_offset_str(mz, pos + 1 + RETURN, recipient, 1);
            add_source_and_recipient_to_inst(inst, source, recipient);
            return 2 + RETURN;
        }
        if (OPERATION == 0xC7)
        {
            find_offset_str(mz, pos + 2 + RETURN, recipient, 2);
            add_source_and_recipient_to_inst(inst, source, recipient);
            return 3 + RETURN;
        }
    }
    //mov ax, [234h]
    if (OPERATION >= 0xA0 && OPERATION <= 0xA3)
    {
        BYTE DS = OPERATION & 2;
        DS = DS >> 1;
        BYTE W = OPERATION & 1;        

        if (W == 0)        
            strcpy(source, "al");        
        else
            strcpy(source, "ax");

        if (W == 1)
            find_memoffset_str(mz, pos + 2, recipient, 2);
        else
            find_memoffset_str(mz, pos + 1, recipient, 1);

        if (DS == 1)
            swap_source_and_recipent(source, recipient);
        
        add_source_and_recipient_to_inst(inst, source, recipient);        

        if (W == 1)
            return 3;
        else
            return 2;

        
    }
   // mov bx, cx
    if (OPERATION >= 0x88 && OPERATION <= 0x8B)
    {
        BYTE DS = OPERATION & 2;
        DS = DS >> 1;
        BYTE W = OPERATION & 1;

        RETURN = defining_the_addressing_mode(mz, pos, recipient);

        defining_the_register_mod(mz, pos, source);

        if (DS == 0)
            swap_source_and_recipent(source, recipient);

        add_source_and_recipient_to_inst(inst, source, recipient);

        return (RETURN + 1);
    }

    if (OPERATION == 0x8C || OPERATION == 0x8E)
    {
        BYTE DS = OPERATION & 2;
        DS = DS >> 1;
        PBYTE tmp = mz->code + pos;
        *(PWORD)tmp += 1;
        

       RETURN = defining_the_addressing_mode(mz, pos, recipient);


        defining_the_segment_register_mod(mz, pos, source);
        
        if (DS == 0)
            swap_source_and_recipent(source, recipient);

        add_source_and_recipient_to_inst(inst, source, recipient);
        *(PWORD)tmp -= 1;
        
        return (RETURN + 1);
    }

}

DWORD d_movsb(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "movsb");
    return 1;
}

DWORD d_movsw(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "movsw");
    return 1;
}

DWORD d_mul(MZHeaders *mz, DWORD pos, char *inst){
    return d_unk(mz, pos, inst);
}

DWORD d_neg(MZHeaders *mz, DWORD pos, char *inst){
    return d_unk(mz, pos, inst);
}

DWORD d_nop(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "nop");
    return 1;
}

DWORD d_not(MZHeaders *mz, DWORD pos, char *inst){
    return d_unk(mz, pos, inst);
}

DWORD d_or(MZHeaders *mz, DWORD pos, char *inst){
    BYTE OPERATION = *(mz->code + pos);

    strcpy(inst, "or     ");

    if (OPERATION >= 0x08 && OPERATION <= 0x0B)
    {
        return r16_r8_with_rm16_rm8(mz, pos, inst);
    }
    if (OPERATION == 0x0C || OPERATION == 0x0D)
    {
        return ax_al_with_imm16_imm8(mz, pos, inst);
    }
}

DWORD d_out(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "out    ");
    BYTE OPERATION = *(mz->code + pos);
    char recipient[50] = "";
    char source[50] = "";
    if (OPERATION == 0xE4 || OPERATION == 0xEC)
        strcat(source, "al");
    if (OPERATION == 0xE5 || OPERATION == 0xED)
        strcat(source, "ax");

    if (OPERATION == 0xE6 || OPERATION == 0xE7)
    {
        find_memoffset_str(mz, pos, recipient, 1);
        strcat(inst, recipient);
        strcat(inst, source);
        return 2;
    }
    if (OPERATION == 0xEC || OPERATION == 0xED)
    {
        strcat(inst, "dx");
        strcat(inst, source);
        return 1;
    }
}

DWORD d_pop(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "pop    ");
    char source[50] = "";
    char recipient[50] = "";
    BYTE OPERATION = *(mz->code + pos);
    if (OPERATION >= 0x58 && OPERATION <= 0x5F)
    {
        strcat(source, reg_Field_Value_Word[OPERATION - 0x58]);
        strcat(inst, source);
        return 1;
    }
    if (OPERATION == 0x8F)
    {
        defining_the_addressing_mode(mz, pos, source);
        strcat(inst, source);
        return 2;
    }
    if (OPERATION == 0x17)
        strcat(inst, "ss");
    if (OPERATION == 0x1F)
        strcat(inst, "ds");
    if (OPERATION == 0x07)
        strcat(inst, "es");
    return 1;
}

DWORD d_popf(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "popf");
    return 1;
}

DWORD d_push(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "push   ");
    char source[50] = "";
    char recipient[50] = "";
    BYTE OPERATION = *(mz->code + pos);
    if (OPERATION >= 0x50 && OPERATION <= 0x57)    
    {
        strcat(source, reg_Field_Value_Word[OPERATION - 0x50]);
        strcat(inst, source);
        return 1;
    }
    if (OPERATION == 0x0E)
        strcat(inst,"cs");
    if (OPERATION == 0x16)
        strcat(inst, "ss");
    if (OPERATION == 0x1E)
        strcat(inst, "ds");
    if (OPERATION == 0x06)
        strcat(inst, "es");
    return 1;
    

}

DWORD d_pushf(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "pushf");
    return 1;
}

DWORD d_rcl(MZHeaders *mz, DWORD pos, char *inst){
    return d_unk(mz, pos, inst);
}

DWORD d_rcr(MZHeaders *mz, DWORD pos, char *inst){
    return d_unk(mz, pos, inst);
}

DWORD d_rep(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "rep    ");
    BYTE OPERATION = *(mz->code + pos);
    if (OPERATION == 0xF3)
        strcpy(inst, "rep    ");
    if (OPERATION == 0xF2)
        strcpy(inst, "repne  ");

    OPERATION = *(mz->code + pos + 1);

    if (OPERATION == 0xA4)
        strcat(inst, "movsb");
    if (OPERATION == 0xA5)
        strcat(inst, "movsw");
    if (OPERATION == 0xAC)
        strcat(inst, "lodsb");
    if (OPERATION == 0xAD)
        strcat(inst, "lodsw");
    if (OPERATION == 0xAA)
        strcat(inst, "stosb");
    if (OPERATION == 0xAB)
        strcat(inst, "stosw");
    if (OPERATION == 0xA6)
        strcat(inst, "cmpsb");
    if (OPERATION == 0xA7)
        strcat(inst, "cmpsw");
    if (OPERATION == 0xAE)
        strcat(inst, "scasb");
    if (OPERATION == 0xAF)
        strcat(inst, "scasw");
    if (OPERATION == 0xAE)
        strcat(inst, "scasb");
    if (OPERATION == 0xAF)
        strcat(inst, "scasw");

    return 2;
}

DWORD d_retn(MZHeaders *mz, DWORD pos, char *inst){
    BYTE opc = *(mz->code + pos);
    if (opc == 0xC2) {
        sprintf(inst, "retn   %u", *((PWORD)(mz->code + pos + 1)));
        return 3;
    }
    else {
        strcpy(inst, "retn");
        return 1;
    }
}

DWORD d_retf(MZHeaders *mz, DWORD pos, char *inst){
    BYTE opc = *(mz->code + pos);
    if (opc == 0xCA) {
        sprintf(inst, "retf   %u", *((PWORD)(mz->code + pos + 1)));
        return 3;
    }
    else {
        strcpy(inst, "retf");
        return 1;
    }
}

DWORD d_rol(MZHeaders *mz, DWORD pos, char *inst){
    return d_unk(mz, pos, inst);
}

DWORD d_ror(MZHeaders *mz, DWORD pos, char *inst){
    return d_unk(mz, pos, inst);
}

DWORD d_sahf(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "sahf");
    return 1;
}

DWORD d_sal(MZHeaders *mz, DWORD pos, char *inst){
    return d_unk(mz, pos, inst);
}

DWORD d_sar(MZHeaders *mz, DWORD pos, char *inst){
    return d_unk(mz, pos, inst);
}

DWORD d_sbb(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "sbb    ");
    BYTE OPERATION = *(mz->code + pos);
    if (OPERATION >= 0x18 && OPERATION <= 0x1B)
    {
        return r16_r8_with_rm16_rm8(mz, pos, inst);
    }
    if (OPERATION == 0x1C || OPERATION == 0x1D)
    {
        return ax_al_with_imm16_imm8(mz, pos, inst);
    }
}

DWORD d_scasb(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "scasb");
    return 1;
}

DWORD d_scasw(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "scasw");
    return 1;
}

DWORD d_shl(MZHeaders *mz, DWORD pos, char *inst){
    return d_unk(mz, pos, inst);
}

DWORD d_shr(MZHeaders *mz, DWORD pos, char *inst){
    return d_unk(mz, pos, inst);
}

DWORD d_stc(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "stc");
    return 1;
}

DWORD d_std(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "std");
    return 1;
}

DWORD d_sti(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "sti");
    return 1;
}

DWORD d_stosb(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "stosb");
    return 1;
}

DWORD d_stosw(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "stosw");
    return 1;
}

DWORD d_sub(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "sub    ");
    BYTE OPERATION = *(mz->code + pos);

    if (OPERATION >= 0x28 && OPERATION <= 0x2b)
    {
        return r16_r8_with_rm16_rm8(mz, pos, inst);
    }
    if (OPERATION == 0x2C || OPERATION == 0x2D)
    {
        return ax_al_with_imm16_imm8(mz, pos, inst);
    }
}

DWORD d_test(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "test   ");
    char source[50] = "";
    char recipient[50] = "";
    BYTE OPERATION = *(mz->code + pos);
    if (OPERATION == 0x84 || OPERATION == 0x85)
    {
       return r16_r8_with_rm16_rm8(mz, pos,inst);
    }
    if (OPERATION == 0xA8 || OPERATION == 0xA9)
    {
        return ax_al_with_imm16_imm8(mz, pos, inst);
    }
}

DWORD d_wait(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "wait");
    return 1;
}

DWORD d_xchg(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "xchg   ");
    char source[50] = "";
    char recipient[50] = "";
    BYTE OPERATION = *(mz->code + pos);
    if (OPERATION == 0x86 || OPERATION == 0x87)
    {
        return r16_r8_with_rm16_rm8(mz, pos, inst);
    }
    if (OPERATION >= 0x91)
    {
        strcat(inst, "ax");
        strcat(inst, reg_Field_Value_Word[OPERATION - 0x90]);
    }
}

DWORD d_xlat(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "xlat");
    return 1;
}

DWORD d_xor(MZHeaders *mz, DWORD pos, char *inst){
    strcpy(inst, "xor    ");
    BYTE OPERATION = *(mz->code + pos);

    if (OPERATION >= 0x30 && OPERATION <= 0x33)
    {
        return r16_r8_with_rm16_rm8(mz, pos, inst);
    }
    if (OPERATION == 0x34 || OPERATION == 0x35)
    {
        return ax_al_with_imm16_imm8(mz, pos, inst);
    }
}

DWORD d_cs(MZHeaders *mz, DWORD pos, char *inst){
    change_seg = 1;
    return 1;
}

DWORD d_ds(MZHeaders *mz, DWORD pos, char *inst){
    change_seg = 3;
    return 1;
}

DWORD d_es(MZHeaders *mz, DWORD pos, char *inst){
    change_seg = 0;
    return 1;
}

DWORD d_ss(MZHeaders *mz, DWORD pos, char *inst){
    change_seg = 2;
    return 1;
}

DWORD d_gr80(MZHeaders *mz, DWORD pos, char *inst){
    BYTE OPERATION = *(mz->code + pos);
    BYTE COP = *(mz->code + pos + 1) & 56;
    COP = COP >> 3;
    strcpy(inst, GR1[COP]);
    
    if (OPERATION == 0x80 || OPERATION == 0x81 || OPERATION == 0x83)
    {
        BYTE RETURN = 0;
        char source[50] = "";
        char recipient[50] = "";
        RETURN = defining_the_addressing_mode(mz, pos, source);
        if (OPERATION == 0x80 || OPERATION == 0x83)
        {
            find_offset_str(mz, pos + 1 + RETURN, recipient, 1);
            RETURN += 1;
        }
        else
        {
            find_offset_str(mz, pos + 2 + RETURN, recipient, 2);
            RETURN += 2;
        }
        strcat(inst, source);
        strcat(inst, ",");
        strcat(inst, recipient);
        return RETURN + 1;
    }
    if (OPERATION == 0x82)
    {
        return d_unk(mz, pos, inst);
    }
    
}

DWORD d_grd0(MZHeaders *mz, DWORD pos, char *inst){
    
    BYTE OPERATION = *(mz->code + pos);
    BYTE COP = *(mz->code + pos + 1) & 56;
    COP = COP >> 3;
    strcpy(inst, GR2[COP]);
    BYTE RETURN = 0;
    char source[50] = "";
    char recipient[50] = "";
    RETURN = defining_the_addressing_mode(mz, pos, source);
    if (OPERATION == 0xD0 || OPERATION == 0xD1)
        strcpy(recipient, "1");
    if (OPERATION == 0xD2 || OPERATION == 0xD3)
        strcpy(recipient, "cl");
    strcat(inst, source);
    strcat(inst, ",");
    strcat(inst, recipient);
    return RETURN + 1;
}

DWORD d_grf6(MZHeaders *mz, DWORD pos, char *inst){
    BYTE OPERATION = *(mz->code + pos);
    BYTE COP = *(mz->code + pos + 1) & 56;
    COP = COP >> 3;
    strcpy(inst, GR3[COP]);
    BYTE RETURN = 0;
    char source[50] = "";
    char recipient[50] = "";
    RETURN = defining_the_addressing_mode(mz, pos, source);
    strcat(inst, source);
    if (COP == 0)
    {
        if (OPERATION == 0xF6)
        {
            find_offset_str(mz, pos + 1 + RETURN, recipient, 1);
            strcat(inst, ",");
            strcat(inst, recipient);
            return RETURN + 2;
        }
            
        if (OPERATION == 0xF7)
        {
            find_offset_str(mz, pos + 2 + RETURN, recipient, 2);
            strcat(inst, ",");
            strcat(inst, recipient);
            return RETURN + 3;
        }
    }
    return RETURN + 1;
    
}

DWORD d_grfe(MZHeaders *mz, DWORD pos, char *inst){
    BYTE OPERATION = *(mz->code + pos);
    BYTE COP = *(mz->code + pos + 1) & 56;
    COP = COP >> 3;
    strcpy(inst, GR4[COP]);
    BYTE RETURN = 0;
    char source[50] = "";
    char recipient[50] = "";
    RETURN = defining_the_addressing_mode(mz, pos, source);
    strcat(inst, source);
    return RETURN + 1;
    
}

DWORD d_grff(MZHeaders *mz, DWORD pos, char *inst){
    BYTE OPERATION = *(mz->code + pos);
    BYTE COP = *(mz->code + pos + 1) & 56;
    COP = COP >> 3;
    strcpy(inst, GR5[COP]);
    BYTE RETURN = 0;
    char source[50] = "";
    char recipient[50] = "";
    if (COP == 3 || COP == 5)
    {
        strcat(inst, "d");
    }
    RETURN = defining_the_addressing_mode(mz, pos, source);
    strcat(inst, source);
    return RETURN + 1;
}

DWORD d_unk(MZHeaders *mz, DWORD pos, char *inst){ 
    strcpy(inst, "???");
    return 1;
}