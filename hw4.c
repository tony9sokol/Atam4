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
        fclose(file);
        return 0;
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
        perror("ptrace")
        exit(1);
    }
    execl(programname,programname,NULL);
    }
    else{
        perror("fork");
        exit(1);
    }
}


void run_dubugger(pid_t child_pid, unsigned long addr) {
    int wait_status;
    int icounter = 0;
    struct user_regs_struct regs;
    int curr_rsp;
    bool end = false;
    long data = ptrace(PTRACE_PEEKTEXT, chikd_pid, (void *) addr, NULL);
    unsigned long data_trap = (data & 0xFFFFFFFFFFFFFF00) | 0xCC;
    ptrace(PTRACE_PEEKTEXT, child_pid, (void *) addr, (void *) data_trap);
    ptrace(PTRACE_CONT, child_pid, NULL, NULL);
    while (WIFSTOPPED(wait_status)) {
        end = false;
        wait(&wait_status);
        icounter++;
        ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
        curr_rsp = regs.rsp;
        printf("PRF::#%s first parameter is %s\n", icounter, regs.rdi);
        ptrace(PTRACE_PEEKTEXT, child_pid, (void *) addr, (void *) data);
        regs.rip-=1;
        ptrace(PTRACE_SETREGS, child_pid, 0, &regs);
        while (!end) {
            if (ptrace(PTRACE_SINGLESTEP, chil_pid, NULL, NULL) < 0) {
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





    if(out of return)
        print rax
    printf



}




int main(int argc, char *const argv[]) {
    int err = 0;
    unsigned long addr = find_symbol(argv[1], argv[2], &err);

     if (err == -2)
        printf("%s is not a global symbol! :(\n", argv[1]);
    else if (err == -1)
        printf("%s not found!\n", argv[1]);
    else if (err == -3)
        printf("%s not an executable! :(\n", argv[2]);
    if (err == 1||err==-4){
        pid_t child_pid;
        child_pid = run_target(argv[1]);
        run_debugger(child_pid,addr);

    }




}