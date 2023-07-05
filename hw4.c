#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <signal.h>
#include <syscall.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>

#include "elf64 (1).h"

#define  ET_NONE  0  //No file type
#define  ET_REL  1  //Relocatable file
#define  ET_EXEC  2  //Executable file
#define  ET_DYN  3  //Shared object file
#define  ET_CORE  4  //Core file


/* symbol_name    - The symbol (maybe function) we need to search for.
 * exe_file_name  - The file where we search the symbol in.
 * error_val    - If  1: A global symbol was found, and defined in the given executable.
 *       - If -1: Symbol not found.
 *      - If -2: Only a local symbol was found.
 *       - If -3: File is not an executable.
 *       - If -4: The symbol was found, it is global, but it is not defined in the executable.
 * return value    - The address which the symbol_name will be loaded to, if the symbol was found and is global.
 */
int table_len(char* strtab, Elf64_Word st_name) {
    //including null-terminator
    int length = 0;
    char c = strtab[st_name];
    while (c != 0) {
        length++;
        c = strtab[st_name +length];
    }
    return length+1;
}


unsigned long get_absolute_addr( char* symbol_name, FILE* file, Elf64_Ehdr header1, Elf64_Shdr* sectable){
    Elf64_Shdr my_relaplt_table;
    Elf64_Shdr my_dynsym;
    Elf64_Shdr my_dynstr;

    Elf64_Shdr my_strtab = sectable[header1.e_shstrndx];
    char strtab_arr [my_strtab.sh_size];
    fseek(file, my_strtab.sh_offset, SEEK_SET);
    fread(strtab_arr, my_strtab.sh_size, 1, file);

    int length;

    for (int i = 0; i < header1.e_shnum; i++) {
        if (sectable[i].sh_type == 4) {//check if RELA.plt_TABLE
            my_relaplt_table = sectable[i];
        }
        if (sectable[i].sh_type == 11) {//check if DYNSYM_TABLE
            my_dynsym = sectable[i];
        }

        length = table_len(strtab_arr, sectable[i].sh_name);
        char name[length];
        char* source = strtab_arr + sectable[i].sh_name;
        strncpy(name, source, length);

        if (strcmp(".dynstr", name) == 0)//check if DYNSTR_TABLE
        {
            my_dynstr = sectable[i];
        }
    }

    int rela_plt_total_size = my_relaplt_table.sh_size;
    int rela_numentries = (int) (rela_plt_total_size / sizeof(Elf64_Rela));
    Elf64_Rela rela_symbols[rela_numentries];
    fseek(file, my_relaplt_table.sh_offset, SEEK_SET);
    fread(rela_symbols, sizeof(Elf64_Rela), rela_numentries, file);

    int dynsym_total_size = my_dynsym.sh_size;
    int numentries = (int) (dynsym_total_size / sizeof(Elf64_Sym));
    Elf64_Sym dyn_symbols[numentries];
    fseek(file, my_dynsym.sh_offset, SEEK_SET);
    fread(dyn_symbols, sizeof(Elf64_Sym), numentries, file);

    char dynstr[my_dynstr.sh_size];
    fseek(file, my_dynstr.sh_offset, SEEK_SET);
    fread(dynstr, my_dynstr.sh_size, 1, file);

    Elf64_Word dynsymbol_index;

    for (int i = 0; i < rela_numentries; i++)
    {
         dynsymbol_index = ELF64_R_SYM(rela_symbols[i].r_info);
         length = table_len(dynstr,dyn_symbols[dynsymbol_index].st_name);
         char name[length];
         char* source = dynstr + dyn_symbols[dynsymbol_index].st_name;
         strncpy(name, source, length);
         if(strcmp(symbol_name, name)==0)
         {
             //return rela_symbols[i].r_offset;
             return dyn_symbols[dynsymbol_index].st_value;
         }
     }
    return 0;
}

unsigned long get_plt(FILE* file, Elf64_Ehdr header1, Elf64_Shdr* sectable, int index) {

    int index_of_strtab = header1.e_shstrndx;
    Elf64_Shdr strtab_header = sectable[index_of_strtab];
    char strtab[strtab_header.sh_size];
    fseek(file, strtab_header.sh_offset, SEEK_SET);
    fread(strtab, strtab_header.sh_size, 1, file);

    int length;

    //get .plt
    Elf64_Shdr plt;
    for (int i = 0; i < header1.e_shnum; i++) {
        length = table_len(strtab, sectable[i].sh_name);
        char name[length];
        char* source = strtab + sectable[i].sh_name;
        strncpy(name, source, length);


        if (strcmp(".plt", name) == 0) {
            plt = sectable[i];
        }
    }

    return plt.sh_addr + plt.sh_entsize * (index+1);
}


unsigned long find_symbol(char* symbol_name, char* exe_file_name, int* error_val) {
    int symbol_name_length = strlen(symbol_name);
    FILE *file = fopen(exe_file_name, "rb");
    Elf64_Ehdr header1;
    fseek(file, 0, SEEK_SET);
    fread(&header1, sizeof(Elf64_Ehdr), 1, file);

    if (header1.e_type != ET_EXEC) {
        *error_val = -3;
        fclose(file);
        return 0;
    }
    int num_of_sec_headers = header1.e_shnum;
    Elf64_Shdr sectable[num_of_sec_headers];
    fseek(file, header1.e_shoff, SEEK_SET);
    fread(&sectable, sizeof(Elf64_Shdr), num_of_sec_headers, file);
    Elf64_Shdr my_strtab;
    Elf64_Shdr my_symtab;
    for (int i = 0; i < num_of_sec_headers; i++) {
        if (sectable[i].sh_type == 2) {//check if SYMTAB
            my_symtab = sectable[i];
        }
        if (sectable[i].sh_type == 3 && i != header1.e_shstrndx) {//check if wright STRTAB
            my_strtab = sectable[i];
        }

    }
    int symtab_total_size = my_symtab.sh_size;
    int numentries = (int) (symtab_total_size / sizeof(Elf64_Sym));
    Elf64_Sym symbols[numentries];
    fseek(file, my_symtab.sh_offset, SEEK_SET);
    fread(symbols, sizeof(Elf64_Sym), numentries, file);
    char strtab[my_strtab.sh_size];
    fseek(file, my_strtab.sh_offset, SEEK_SET);
    fread(strtab, my_strtab.sh_size, 1, file);

    int index_of_symbol = -1;
    int length;
    bool is_local = false;
    bool is_global = false;
    bool exists=false;
    bool defined=true;
    for(int i = 0; i<numentries; i++){
        length = table_len(strtab,symbols[i].st_name);
        char name[length];
        char* source = strtab + symbols[i].st_name;
        strncpy(name, source, length);
        if(strcmp(symbol_name, name)==0){
            index_of_symbol=i;
            exists=true;
            if (ELF64_ST_BIND(symbols[i].st_info) == 0) {
                is_local = 1;
            }
            if (ELF64_ST_BIND(symbols[i].st_info) == 1)
                is_global = 1;
        }
    }
    if (!exists) {
        *error_val= -1;
        fclose(file);
        return 0;
    }
    defined = (symbols[index_of_symbol].st_shndx != SHN_UNDEF);
    if (is_global && defined) {
        *error_val = 1;
        fclose(file);
        return (symbols[index_of_symbol].st_value);
    }
    if (is_global && !defined) {
        *error_val = -4;
        Elf64_Addr dyn_addr = get_absolute_addr(symbol_name, file, header1, sectable);
        fclose(file);
        return  dyn_addr;
    }
    if (is_local && !is_global) {
        *error_val = -2;
        fclose(file);
        return 0;
    }
}
pid_t run_target(const char * programname){
    pid_t pid;
    pid=fork();
    if(pid>0){
        return pid;
    }
    else if(pid==0){
    if(ptrace(PTRACE_TRACEME,0,NULL,NULL)<0){
        perror("ptrace");
        return 0;
    }
    execv(programname,&programname);
    }
    else{
        perror("fork");
        exit(1);
    }
}


void run_debugger(pid_t child_pid, unsigned long addr,bool stage5,unsigned long loaded_to,int index,unsigned long plt_addr,char* file_name) {
    int wait_status;
    int icounter = 0;
    int ret_value = 0;
    int first;
    int ret_data;
    struct user_regs_struct regs;
    bool is_first_time = true;
    unsigned long plt_of_data_trap;
    unsigned long real_addr = addr;
    unsigned long long curr_rsp;
    unsigned long data_trap_plt;
    long data_plt;
    unsigned long data;
    unsigned long data_trap;

    if (stage5) {
        wait(&wait_status);
        unsigned long real_plt_addr = get_real_plt_entry_addr(exe_file_name, index);
        data_plt = ptrace(PTRACE_PEEKTEXT, child_pid, (void *) addr, NULL);
        data_trap_plt = (data_plt & 0xFFFFFFFFFFFFFF00) | 0xCC;
        ptrace(PTRACE_POKETEXT, child_pid, (void *) real_addr, (void *) data_trap_plt);
        ptrace(PTRACE_CONT, child_pid, NULL, NULL);
        wait(&wait_status);
        if (WIFEXITED(wait_status)) {
            printf("out");
            return;
        }
        ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
        ptrace(PTRACE_POKETEXT, child_pid, (void *) real_plt_addr, (void *) data_plt);
        regs.rip -= 1;
        ptrace(PTRACE_SETREGS, child_pid, 0, &regs);
        unsigned long original_loaded_to = ptrace(PTRACE_PEEKTEXT, child_pid, (void *) loaded_to, NULL);
        unsigned long curr_loaded_to = original_loaded_to;

        while (original_loaded_to == curr_loaded_to) {
            ptrace(PTRACE_SINGLESTEP, child_pid, NULL, NULL);
            wait(&wait_status);
            if (WIFEXITED(wait_status))
                return;
            //save current memory value
            curr_loaded_to = ptrace(PTRACE_PEEKTEXT, child_pid, (void *) loaded_to, NULL);
        }
        first = false;
        real_addr = curr_loaded_to;
        ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
        while (regs.rip != real_addr) {
            ptrace(PTRACE_SINGLESTEP, child_pid, NULL, NULL);
            wait(&wait_status);
            if (WIFEXITED(wait_status)) {
                return;
            }
            ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
        }


        icounter++;
        ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
        curr_rsp = regs.rsp;
        printf("PRF::#%s first parameter is %s\n", icounter, (int) regs.rdi);
        ptrace(PTRACE_PEEKTEXT, child_pid, (void *) addr, (void *) data);
        bool end = false;
        while (!end && !WIFEXITED(wait_status)) {
            if (ptrace(PTRACE_SINGLESTEP, child_pid, NULL, NULL) < 0) {
                perror("ptrace");
                return;
            }
            wait(&wait_status);
            ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
            if (regs.rsp > curr_rsp) {
                printf("PRF::#%s return with %s\n", icounter, (int) regs.rax);
                end = true;
            }


            data = ptrace(PTRACE_PEEKTEXT, child_pid, (void *) real_addr, NULL);
            data_trap = (data & 0xFFFFFFFFFFFFFF00) | 0xCC;
            ptrace(PTRACE_PEEKTEXT, child_pid, (void *) real_addr, (void *) data_trap);
            ptrace(PTRACE_CONT, child_pid, 0, 0);
        }
    } else {
        wait(&wait_status);
        data = ptrace(PTRACE_PEEKTEXT, child_pid, (void *) real_addr, NULL);
        data_trap = (data & 0xFFFFFFFFFFFFFF00) | 0xCC;
        ptrace(PTRACE_POKETEXT, child_pid, (void *) real_addr, (void *) data_trap);
        ptrace(PTRACE_CONT, child_pid, NULL, NULL);
        while (!WIFEXITED(wait_status)) {
            wait(&wait_status);
            icounter++;
            ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
            curr_rsp = regs.rsp;
            printf("PRF::#%s first parameter is %s\n", icounter, regs.rdi);
            ptrace(PTRACE_PEEKTEXT, child_pid, (void *) addr, (void *) data);
            regs.rip-=1;
            ptrace(PTRACE_SETREGS, child_pid, 0, &regs);
            while (!end) {
                if (ptrace(PTRACE_SINGLESTEP, child_pid, NULL, NULL) < 0) {
                    perror("ptrace");
                    return;
                }
                wait(&wait_status);
                ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
                if (regs.rsp > curr_rsp) {
                    printf("PRF::#%s return with %s\n", icounter, regs.rax);
                    end = true;
                }
            }
            ptrace(PTRACE_PEEKTEXT, child_pid, (void *) addr, (void *) data_trap);
            ptrace(PTRACE_CONT, child_pid, NULL, NULL);

        }












    }










    }





/*
    while (WIFSTOPPED(wait_status)) {
        wait(&wait_status);
        icounter++;
        ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
        curr_rsp = regs.rsp;
        printf("PRF::#%s first parameter is %s\n", icounter, regs.rdi);
        ptrace(PTRACE_PEEKTEXT, child_pid, (void *) addr, (void *) data);
        regs.rip-=1;
        ptrace(PTRACE_SETREGS, child_pid, 0, &regs);
        while (!end) {
            if (ptrace(PTRACE_SINGLESTEP, child_pid, NULL, NULL) < 0) {
                perror("ptrace");
                return;
            }
            wait(&wait_status);
            ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
            if (regs.rsp > curr_rsp) {
                printf("PRF::#%s return with %s\n", icounter, regs.rax);
                end = true;
            }
        }
        ptrace(PTRACE_PEEKTEXT, child_pid, (void *) addr, (void *) data_trap);
        ptrace(PTRACE_CONT, child_pid, NULL, NULL);

    }
}

*/


}
int main(int argc, char *const argv[]) {
    int err = 0;
    unsigned long addr = find_symbol(argv[1], argv[2], &err);
    unsigned long trampo= get_plt(argv[2],)
     if (err == -2)
        printf("%s is not a global symbol! :(\n", argv[1]);
    else if (err == -1)
        printf("%s not found!\n", argv[1]);
    else if (err == -3)
        printf("%s not an executable! :(\n", argv[2]);

    bool stage_5 = false;
    unsigned long address =0;

    if (err== -4) {
        stage_5 = true;
    } else {
        address = addr;
    }
    unsigned long loaded_to = 0;
    unsigned long *output_plt_entry;
    int nop = 0;
    int *index = &nop;

    if (stage_5) {
        loaded_to = addr;
    }
    if (loaded_to == -1) {
        printf("Did not find symbol in dymsym\n");
        return -1;
    }


    if (err == 1||err==-4){
        pid_t child_pid;
        child_pid = run_target(argv[2]);
        run_debugger(child_pid,addr,stage_5,loaded_to,*index,*output_plt_entry,argv[2]);

    }




}