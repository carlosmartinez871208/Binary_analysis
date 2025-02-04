# Analisis binario en linux
El objetivo de este repositorio es dar explicacion de lo que es el analisis binario en linux.

## Comandos.
### objdump:
Es una herramienta para desensamblar codigo.

> Para ver toda la informacion/codigo de cada seccion de un ejecutable tipo ELF (Executable Linked File), usamos:

    objdum -D elf_or_object

> Para ver solamente el codigo de un archivo ELF, usamos:

    objdump -d elf_or_object

> Para ver todos los simbolos, usamos:

    objdump -tT elf_or_object

### objcopy:
Es una herramienta muy poderosa en el analisis binario, muchas veces es usada para modificar ejecutables o copiar alguna seccion de un ejecutable.

> Para copiar la seccion .data de un archivo ELF a otro archivo, usamos:

    objcopy -only-section=.data elf_or_object destiny_file

### strace:
Esta herramienta puede ser muy util para depuracion (debuggeo) o recolectar informacion acerca de las llamadas de sistema durante la ejecucion del programa (runtime).

> Para rastrear un programa usamos:

    strace /bin/ls -o ls.out

> Para rastrear un proceso existente usamos:

    strace -p pid -o daemon.out

> La primera salida mostrara el archivo que describe cada llamada de sistema y lo toma como argumento, parecido al siguiente ejemplo:

    SYS_read(3, buf, sizeof(buf));

> Para ver toda la informacion que sido leida desde el archivo de descripcion 3, usamos:

    strace -e read=3 /bin/ls

> Para ver los datos de escritura usamos:

    strace -e write=fd /bin/ls

### ltrace:
Esta herramienta es similar a **strace**, **ltrace** usa la informacion de las libreria dinamicas de un programa e imprime las funciones que se estan usando de la libreria.

> **ltrace** esta disenado para proveer mas informacion ya que analiza el segmento dinamico de un ejecutable e imprime los simbolos/funciones de las librerias dinamicas y estaticas.

### readelf:
Esta herramienta es el mas usado para diseccionar los binarios tipo ELF.

> Para obtener el header de una seccion usamos:

    readelf -S object_file

> Para obtener el header de un programa:

    readelf -l object_file

> Para obtener la tabla de simbolos:

    readelf -s object_file

> Para obtener el header del ELF:

    readelf -e object_file

> Para obtener las entradas de relocalizacion:

    readelf -r object_file

> Para obtener un segmento dinamico:

    readelf -d object_file

### Linker Script
Usamos **ld** para hacer el llamado del linker.

> Para ver el linker por default usamos:

    ld -verbose

## ELF file types
Un archivo ejecutable tipo ELf puede ser clasificado en los siguientes tipos:

### ET_NONE:
Este es un tipo desconocido. indica que el tipo de archivo es desconocido y no ha sido definido.

### ET_REL: 
Este es un archivo relocalizable, esto significa que es marcado como una pieza de codigo o algunas veces llamado archivo tipo objeto. Los archivos tipo objeto relocalizable son generalmente piezas de Codigo de posicion independiente (Position Independent code - PIC) que no han sido enlazados en un ejecutable. Estos archivos tienen una extension ***.o** y son archivos que contiene codigo y datos para crear un archivo ejecutable.

### ET_EXEC:
Este es un archivo ejecutable, estos archivos normalmente son llamados **programas**.

### ET_DYN:
Este es una libreria dinamica o shared object. Esta librerias son cargadas y linkeadas en el proceso de imagen de un programa en tiempo de ejecucion (runtime).

### ET_CORE:
Este es un tipo ELF llamado core, un archivo core es una copia del proceso de imagen completo en el momento en que el programa falla o cuando el proceso nos ha devuelto un SIGSEGV signal (violacion de segmentacion).

## ELF File Header.
El encabezado del archivo ELF (ELF file header) empieza en el offset 0 de un archivo tipo ELF y sirve como un mapa del resto del archivo.

Este header contiene:
> 1. ELF type.
> 2. La arquitectura.
> 3. La direccion del punto de entrada donde empieza la ejecucion del archivo.
> 4. Donde debe comenzar la ejecucion.
> 5. Provee los offset con respecto de los otros tipos de ELF headers (secion headers y program headers).

A continuacion se muestra la estructura del header:

    #define EI_NIDENT (16)

    typedef struct
    {
        unsigned char e_ident[EI_NIDENT];     /* Magic number and other info */
        Elf64_Half    e_type;                 /* Object file type */
        Elf64_Half    e_machine;              /* Architecture */
        Elf64_Word    e_version;              /* Object file version */
        Elf64_Addr    e_entry;                /* Entry point virtual address */
        Elf64_Off     e_phoff;                /* Program header table file offset */
        Elf64_Off     e_shoff;                /* Section header table file offset */
        Elf64_Word    e_flags;                /* Processor-specific flags */
        Elf64_Half    e_ehsize;               /* ELF header size in bytes */
        Elf64_Half    e_phentsize;            /* Program header table entry size */
        Elf64_Half    e_phnum;                /* Program header table entry count */
        Elf64_Half    e_shentsize;            /* Section header table entry size */
        Elf64_Half    e_shnum;                /* Section header table entry count */
        Elf64_Half    e_shstrndx;             /* Section header string table index */
    } Elf64_Ehdr;

El archivo **elf.h**  lo puedes encontrar en la siguiente direccion: **/usr/include/elf.h**

Para ver el archivo en consola se puede usar el siguiente comando.

    cat /usr/include/elf.h

o tambien podemos usar:

    nano /usr/include/elf.h

## ELF Program Headers.
Son los que describen los segmentos dentro de un binario y son necesarios para cargar un programa.
Los segmentos son procesados por el kernel durante el tiempo de carga y describe el layout de un ejecutable en el disco y como describirlo en memoria.
La tabla de los program headers pueder accesada referenciando el offset que se encuentra en el ELF file header: **e_phoff** (program header table offset).

A continuacion se muestra la estructura del ELF program header:

    typedef struct
    {
        Elf64_Word    p_type;                 /* Segment type */
        Elf64_Word    p_flags;                /* Segment flags */
        Elf64_Off     p_offset;               /* Segment file offset */
        Elf64_Addr    p_vaddr;                /* Segment virtual address */
        Elf64_Addr    p_paddr;                /* Segment physical address */
        Elf64_Xword   p_filesz;               /* Segment size in file */
        Elf64_Xword   p_memsz;                /* Segment size in memory */
        Elf64_Xword   p_align;                /* Segment alignment */
    } Elf64_Phdr;

## PT_LOAD.
Un archivo ejecutable al menos tiene un segmento **PT_LOAD**. Este tipo de program header describe un segmento que sera cargado, lo cual significa que el segmento va a ser cargado o mapeado en memory.

En el caso de un ejecutable ELF con enlazado dinamico normalmente contiene los siguiente dos segmentos que seran cargados:
> 1. El segmento **text** para el codigo del programa.
> 2. El segmento **data** para variables globales e informacion del enlazado dinamico.

Los dos anteriores seran apeados y alineados en memoria por el valor guardado en p_align (en la estructura de ELF program headers).

> El segmento **text** tambien conocido como el segmento de codigo, generalmente tiene permisos de segmento como el siguiente:

    PF_X | PP_R (READ+EXECUTE)

> El segmento **data** normalmente tiene permisos como el siguiente:

    PF_W | PF_R (READ+WRITE)

Nota: Podria suceder que un archivo infectado con un virus polimorfico cambie los permisos de una manera que el segmento **text** pueda tener el modo escritura **PF_W** flag en el segmento del program header (**p_flags**).

## PT_DYNAMIC - Phdr para el segmento dinamico.
El segmento dinamico es especifico para ejecutables que son dinamicamente enlazados y contiene la informacion necesaria para el linker dinamico. Este segmento contiene valores etiquetados y apuntadores, incluyendo pero no limitados a los siguientes:
> 1. Lista de las libreria dinamicas que deben ser enlazadas al momento de ejecucion (runtime).
> 2. La direccion/localizacion de la tabla global de offsets (Global offset table - GOT).
> 3. Informacion acerca de las entradas de relocalizacion.

A continuacion se muestra la lista completa de etiquetas:

    /* Legal values for d_tag (dynamic entry type).  */

    #define DT_NULL         0               /* Marks end of dynamic section */
    #define DT_NEEDED       1               /* Name of needed library */
    #define DT_PLTRELSZ     2               /* Size in bytes of PLT relocs */
    #define DT_PLTGOT       3               /* Processor defined value */
    #define DT_HASH         4               /* Address of symbol hash table */
    #define DT_STRTAB       5               /* Address of string table */
    #define DT_SYMTAB       6               /* Address of symbol table */
    #define DT_RELA         7               /* Address of Rela relocs */
    #define DT_RELASZ       8               /* Total size of Rela relocs */
    #define DT_RELAENT      9               /* Size of one Rela reloc */
    #define DT_STRSZ        10              /* Size of string table */
    #define DT_SYMENT       11              /* Size of one symbol table entry */
    #define DT_INIT         12              /* Address of init function */
    #define DT_FINI         13              /* Address of termination function */
    #define DT_SONAME       14              /* Name of shared object */
    #define DT_RPATH        15              /* Library search path (deprecated) */
    #define DT_SYMBOLIC     16              /* Start symbol search here */
    #define DT_REL          17              /* Address of Rel relocs */
    #define DT_RELSZ        18              /* Total size of Rel relocs */
    #define DT_RELENT       19              /* Size of one Rel reloc */
    #define DT_PLTREL       20              /* Type of reloc in PLT */
    #define DT_DEBUG        21              /* For debugging; unspecified */
    #define DT_TEXTREL      22              /* Reloc might modify .text */
    #define DT_JMPREL       23              /* Address of PLT relocs */
    #define DT_BIND_NOW     24              /* Process relocations of object */
    #define DT_INIT_ARRAY   25              /* Array with addresses of init fct */
    #define DT_FINI_ARRAY   26              /* Array with addresses of fini fct */
    #define DT_INIT_ARRAYSZ 27              /* Size in bytes of DT_INIT_ARRAY */
    #define DT_FINI_ARRAYSZ 28              /* Size in bytes of DT_FINI_ARRAY */
    #define DT_RUNPATH      29              /* Library search path */
    #define DT_FLAGS        30              /* Flags for the object being loaded */
    #define DT_ENCODING     32              /* Start of encoded range */
    #define DT_PREINIT_ARRAY 32             /* Array with addresses of preinit fct*/
    #define DT_PREINIT_ARRAYSZ 33           /* size in bytes of DT_PREINIT_ARRAY */
    #define DT_SYMTAB_SHNDX 34              /* Address of SYMTAB_SHNDX section */
    #define DT_RELRSZ       35              /* Total size of RELR relative relocations */
    #define DT_RELR         36              /* Address of RELR relative relocations */
    #define DT_RELRENT      37              /* Size of one RELR relative relocaction */
    #define DT_NUM          38              /* Number used */
    #define DT_LOOS         0x6000000d      /* Start of OS-specific */
    #define DT_HIOS         0x6ffff000      /* End of OS-specific */
    #define DT_LOPROC       0x70000000      /* Start of processor-specific */
    #define DT_HIPROC       0x7fffffff      /* End of processor-specific */
    #define DT_PROCNUM      DT_MIPS_NUM     /* Most used by any processor */

El segmento dinamico contiene una serie de estructuras que contiene informacion relevante acerca del enlazado dinamico. 

**d_tag** controla la interpretacion de **d_un**

    typedef struct
    {
        Elf64_Sxword  d_tag;                  /* Dynamic entry type */
        union
        {
            Elf64_Xword d_val;                /* Integer value */
            Elf64_Addr d_ptr;                 /* Address value */
        } d_un;
    } Elf64_Dyn;