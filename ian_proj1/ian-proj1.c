#include <stdio.h>
#include <gelf.h>
#include <libelf.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

//free resources on unexpected exit
#define CLOSEEXIT(FD,ELF,STRING,CODE) do{ \
fprintf(stderr,STRING);\
elf_end(ELF);\
close(FD);\
exit(CODE);}while(0)

//char representation of permission
#define FLAG(C) (pHdr.p_flags & PF_ ## C? #C[0] :'-')

//create switch branch with section type
#define CASE(P_TYPE) case PT_ ## P_TYPE : str = # P_TYPE;break

void parse_elf(int fd){
    Elf *pElf = elf_begin(fd,ELF_C_READ, NULL);
    if(!pElf){
        close(fd);
        exit(2);
    }
    if(elf_kind(pElf) != ELF_K_ELF)
        CLOSEEXIT(fd,pElf,"not elf file",2);

    size_t heads;
    if(elf_getphdrnum(pElf,&heads))
        CLOSEEXIT(fd,pElf,"error reading headers",2);

    //get section header count
    size_t eNdx;
    if(elf_getshdrstrndx(pElf, &eNdx) != 0)
        CLOSEEXIT(fd,pElf,"error reading sections",3);

    printf("Segment Type         Perm Sections");
    //iterate over headers
    for(int i=0;i<heads;i++){
        GElf_Phdr pHdr;
        if(!gelf_getphdr(pElf,i,&pHdr))
            CLOSEEXIT(fd,pElf,"error reading headers",3);
        char *str;

        //using legal values for p_type from elf.h
         switch(pHdr.p_type) {
             CASE(NULL);
             CASE(LOAD);
             CASE(DYNAMIC);
             CASE(INTERP);
             CASE(NOTE);
             CASE(SHLIB);
             CASE(PHDR);
             CASE(TLS);
             CASE(GNU_EH_FRAME);
             CASE(GNU_STACK);
             CASE(GNU_RELRO);
             CASE(GNU_PROPERTY);
             CASE(SUNWBSS);
             CASE(SUNWSTACK);
             default:
                 str = "UNKNOWN";
                 break;
         }

        printf("\n%02d      %-12s %c%c%c ", i, str, FLAG(R),FLAG(W),FLAG(X));
        //iterate over sections
        Elf_Scn *eScn = NULL;
        GElf_Shdr eShdr;
        while((eScn = elf_nextscn(pElf,eScn))){
            if(!gelf_getshdr(eScn,&eShdr))
                CLOSEEXIT(fd,pElf,"error reading sections",3);
            //is segment inside header ?
            if(pHdr.p_vaddr <= eShdr.sh_addr && eShdr.sh_addr+eShdr.sh_size <= pHdr.p_vaddr+pHdr.p_memsz && eShdr.sh_addr != 0) {
                char *name = elf_strptr(pElf,eNdx,eShdr.sh_name);
                printf("%s ", name);
            }
        }
    }

    elf_end(pElf);
}

int main(int argc, char **argv) {
    if(argc != 2)
        return 1;

    //print help
    if(strcmp(argv[1],"-h") == 0  || strcmp(argv[1],"--help") == 0){
        printf("usage: ./ian-proj1 [-h] elf\n print elf section to segment mapping table\n\n\
-h, --help\t\tshow this help message and exit\n elf\t\t\telf file name");
        return 0;
    }

    if (elf_version(EV_CURRENT) ==  EV_NONE)
        return 1;
    int fd = open(argv[1], O_RDONLY, 0);
    if(fd < 0)
        return 2;

    parse_elf(fd);

    close(fd);
    return 0;
}
