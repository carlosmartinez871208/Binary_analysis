/* ELF parser  */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <elf.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <stdint.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifndef EXIT_SUCCESS
 #define EXIT_SUCCESS 0u
#endif

int main (int argc, char** argv)
{
    int fd, i;
    uint8_t *mem;
    struct stat st;
    char *StringTable, *interp;

    Elf64_Ehdr *ehdr;
    Elf64_Phdr *phdr;
    Elf64_Shdr *shdr;

    if (argc < 2)
    {
        printf("Usando: %s <executable>\n",argv[0]);
        exit (0);
    }

    if(fd = (open(argv[1], O_RDONLY)) <0 )
    {
        perror("open");
        exit (-1);
    }

    if(fstat(fd, &st) < 0)
    {
        perror("fstat");
        exit (-1);
    }

    /* Se hace el mapeo en la memoria */
    mem = mmap (NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if(MAP_FAILED == mem)
    {
        perror("mmap");
        exit (-1);
    }

    /* El header inicial comienza en el offste 0 */
    ehdr = (Elf64_Ehdr *)mem;

    /* La tabla de offsets de shdr y phdr esta dada por e_shoff y e_phoff */
    phdr = (Elf64_Phdr *)&mem[ehdr->e_phoff];
    shdr = (Elf64_Shdr *)&mem[ehdr->e_shoff];

    /* Revisa si el ELF magic es igual a: 0x7f E L F */
    if (mem[0] != 0x7f && strcmp(&mem[1], "ELF"))
    {
        fprintf(stderr,"%s no es un archivo ELF\n", argv[1]);
        exit (-1);
    }

    /* Se revisa que se trate de ejecutables solamente */
    if (ehdr->e_type != ET_EXEC)
    {
        fprintf(stderr, "%s no es un ejecutable\n", argv[1]);
        exit (-1);
    }

    printf("Punto de entrada del programa: 0x%lx\n", ehdr->e_entry);

    /* Se encuentra la tabla de cadenas para los nombre del section header con e_shstrndx que de
    ** que despliega el indice de que seccion esta reteniendo la tabla de cadenas.
    */
    StringTable = &mem[shdr[ehdr->e_shstrndx].sh_offset];

    /* Imprime cada nombre del segmento y sus direcciones */
    for(int i =0; i < ehdr->e_shnum; i++)
    {
        printf("%s: 0x%lx\n",&StringTable[shdr[i].sh_name], shdr[i].sh_addr);
    }

    /* Imprime cada nombre de segmento y la direccion, excepto para PT_INTERP se escribe el path de linker dinamico. */
    printf("\nLista de headers de programa\n\n");
    for(int i =0; i < ehdr->e_phnum; i++)
    {
        switch (phdr[i].p_type)
        {
            case PT_LOAD:
                /* Sabemos que el segmento text empieza en el offset 0
                ** Solo hay otro segmento cargable que es data. 
                */
                if(phdr[i].p_offset == 0)
                {
                    printf("Text segment: 0x%lx\n",phdr[i].p_vaddr);
                }
                else
                {
                    printf("Data sgement: 0x%lx\n",phdr[i].p_vaddr);
                }
            break;

            case PT_INTERP:
                interp = strdup((char*)&mem[phdr[i].p_offset]);
                printf("Interprete: %s\n", interp);
            break;

            case PT_NOTE:
                printf("Note segment: 0x%lx\n",phdr[i].p_vaddr);
            break;

            case PT_DYNAMIC:
                printf("Dynamic segment: 0x%lx\n",phdr[i].p_vaddr);
            break;

            case PT_PHDR:
                printf("Phdr segment: 0x%lx\n", phdr[i].p_vaddr);
            break;

            default:
            break;
        }
    }
    return EXIT_SUCCESS;
}
