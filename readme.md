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

## PT_NOTE
Un segmento de este tipo puede contener informacion auxiliar que es pertinente a un fabricante o sistema en especifico.

Muchas veces los fabricantes o sistemas necesitan marcar un archivo tipo objeto con informacion especial que otros programas revisaran por cuestiones de acuerdos comerciales, compatibilidad, etc. Las secciones de tipo **SHT_NOTE** y los elementos del program header de tipo **PT_NOTE** pueden ser usados para este proposito. Esta informacion en las secciones y los elementos del program header contiene un cierto numero de entradas, cada una de ellas es un array de 4 bytes en el formato del procesador utilizado. Las etiquetas aparecen debajo para explicar lo organizacion de la informacion de **note**, pero estas no forman parte de la especificacion.

Algo interesante es que este segmento es solo usado para especificacion e informacion del Sistema Operativo (Operative System - OS).

## PT_INTERP
Este segmento pequeno contiene solamente la localizacion y tamano de las cadenas (strings) que terminan en **null**, describiendo donde esta el interprete del programa.

    /lib/linux-ld.so.2

Normalmente la direccion anterior es generalmente la direccion del linker que tambien es el interprete del programa.

## PT_PHDR
Este segmento contiene la localizacion y tamano de la tabla del program header. La tabla **PT_PHDR** contiene todas las direcciones fisicas describiendo los segmentos del archivos.

Podemos usar el siguiente comando para ver la tabla **Phdr**

    readelf -l elf_or_object

## ELF section headers.
Primeramente se debe aclarar que una seccion (**section**) no es un segmento (**segment**), los segmentos son necesarios para la ejecucion de un programa y dentro de cada segmento hay codigo e informacion dividido en secciones.

Una tabla **section header** existe para referenciar la localizacion y el tamano de las secciones, normalmente usadas para linkeo y debuggeo.

Los **section headers** no son usados para la ejecucion de un programa y un programa se ejecutara bien sin tener una tabla de **section header**. Esto es porque la tabla de **section headers** no describen el programa en memoria.

La responsabilidad de describir el programa en memoria es de la tabla **program header**. Los **section headers** son complementarios a los **program headers**.

Con el siguiente comando se muestra que secciones estan mapeadas a cuales segmentos y nos ayuda aver las relaciones entre secciones y segmentos.

    readelf -l

Si los **section headers** fueron suprimidos (stripped), no significa que las secciones no esten ahi, solamente no pueden ser referenciadas por **section headers** y menos informacion esta disponible para los debuggers y programas de analisis.

Cada seccion contiene informacion y codigo de algun tipo. Todo esto puede variar desde: variables globales o informacion acerca del enlazamiento dinamico que es necesario para el linker. Como se habia mencionado antes cada ELF tiene secciones, pero no todos los ELF tienen **section headers**.

A continuacion se muestra la estructura de un **section header**.

    typedef struct
    {
        Elf64_Word    sh_name;                /* Section name (string tbl index) */
        Elf64_Word    sh_type;                /* Section type */
        Elf64_Xword   sh_flags;               /* Section flags */
        Elf64_Addr    sh_addr;                /* Section virtual addr at execution */
        Elf64_Off     sh_offset;              /* Section file offset */
        Elf64_Xword   sh_size;                /* Section size in bytes */
        Elf64_Word    sh_link;                /* Link to another section */
        Elf64_Word    sh_info;                /* Additional section information */
        Elf64_Xword   sh_addralign;           /* Section alignment */
        Elf64_Xword   sh_entsize;             /* Entry size if section holds table */
    } Elf64_Shdr;

## La seccion **.text**.
Esta seccion de codigo contiene todas las instrucciones del programa. En un programa ejecutable donde tambie esta el **Phdr's**, esta seccion estaria dentro del rango del segmento **text**.
Esta seccion es de tipo **SHT_PROGBITS**.

## La seccion **.rodata**.
Esta seccion contiene informacion de solo lectura (**read-only**) como por ejemplo cadenas de caracteres de una linea de codigo en C, como por ejemplo:

    printf("Hello World!\n");

Esta seccion es **read-only** y por lo tanto debe existir en un segmento de solo escritura de un ejecutable, **.rodata** esta ubicado dentro del rango del segmento **text** y no el segmento **data**.

Por lo tanto esta seccion es **read-only** y es del tipo **SHT_PROGBITS**.

## La seccion **.plt section**.
La tabla de proceso de linkeo (PLT - Process linkage table) contiene el codigo necesario para el linker dinamico y llamar a las funciones que son importadas desde librerias dinamicas (**shared object**).

Esta seccion tambien reside in el segmento **text** y contiene codigo, por lo tanto tambien es de tipo **SHT_PROGBITS**.

## La seccion **.data**.
La seccion **data** no debe ser confundida con el ***segmento*** **data**, la seccion **data** existe dentro del segmento **data** y contiene las variables globales inicializadas de un programa.

Esta seccion contiene las variables de un programa y es de tipo **SHT_PROGBITS**.

## La seccion **.bss**.
La seccion **bss** contiene variables globales no inicializadas de un programa, esta seccion forma parte del segmento **data** y por lo tanto no toma mas espacio en el disco que 4 bytes la cual representa a la seccion por si misma.

Las variables son inicializadas a cero en el moneto de carga y las variables peuden ser asignadas durante la ejecucion del programa.

Esta seccion es de tipo **SHT_NOBITS** mientras no contenga variables.

## La seccion **.got.plt**. 
La tabla global de offsets (**GOT - Global Offset Table**). Trabaja junto con el **PLT** (Process Linkage Table) para proveer accesos a las libreria dinamicas importadas o **shared objects** y es modificado por linker dinamico cuando el programa esta corriendo (runtime).

Esta seccion esta relacionada con la ejecucion del programa y por lo tanto es de tipo **SHT_PROGBITS**.

## La seccion **.dynsym**.
La seccion **dynsym** contiene informacion de los simbolos dinamicos importados desde las librerias compartidas.

Esta contenido dentro segmento **text** y es de tipo **SHT_DYNSYM**.

## La seccion **.dynstr**.
La seccion **dynstr** contiene la tabla de cadenas para los simbolos dinamicos que tiene el nombre de cada simbolo en una serie de cadenas terminadas en **null**.

## La seccion **.rel.\***
Las secciones de relocalizacion contienen informacion acerca de como las partes de un archivo **ELF** o proceso de imagen deben ser procesadas o modificadas al momento del linkeo o cuando el programa esta corriendo (runtime).

Las secciones de relocalizacion son de tipo **SHT_REL** mientras contengan datos de relocalizacion.

## La seccion **.hash**.
La seccion **hash** muchas veces llamada **gnu.hash**, contiene una tabla de simbolos tipo hash para busqueda de simbolos.

A continuacion se muestra el algoritmo usado para la busqueda de simbolos en un **ELF** de linux.

    uint32_t
    dl_new_hash (const char *s)
    {
        uint32_t h = 5381;
        for (unsigned char c = *s; c != '\0'; c = *++s)
            h = h * 33 + c;
        return h;
    }

## La seccion **.symtab**.
La seccion **symtab** contiene la informacion de los simbolos de tipo ***ElfN_Sym***.

Esta seccion es de tipo **SHT_SYMTAB** ya que contiene informacion de los simbolos.

## La seccion **.strtab**.
La seccion **strtab** contiene la tabla de simbolos de cadena que esta referenciada por **st_name** dentro de la estructura **ElfN_Sym**.

Esta seccion es de tipo **SHT_STRTAB** ya que contiene la tabla de cadenas.

## La seccion **.shstrtab**.
La seccion **shstrtab** contiene la tabla de cadenas del header que un set de cadenas terminadas en **null** que contienen los nombres de cada seccion como: **.text**, **.data**, etcetera. 

Esta seccion esta siendo apuntada por la entrada del header del archivo **ELF** ***e_shstrndx*** que contiene el offset de **.shstrtab**.

Esta seccion es de tipo **SHT_STRTAB** ya que contiene la tabla de cadenas.

## Las secciones **.ctors** y **.dtors**.
Las secciones de los constructores (**ctors**) y destructores (**dtors**) contienen apuntadores a funciones para inicializar (en el caso de los constructores) y finalizar (en el caso de los destructores) codigo que es ejecutado antes del **main()** cuerpo del codigo del programa.

### Hay mas secciones y tipos pero se han cubierto los mas usados en un ejecutable dinamicante enlazado.

Ahora podemos ver como un ejecutable es mapeado con ambos: **phdrs** y **shdrs**.

## El segmento **text** se ve de la siguiente manera.
> [.text]: Contiene el codigo del programa.

> [.rodata]: Contiene la informacion de solo lecura.

> [.hash]: Contiene la tabla de simbolos hash.

> [.dynsym]: Contiene la informacion de los simbolos de las libreria dinamicas (shared object).

> [.dystr]: Contiene los nombres de los simbolos de las librerias dinamicas.

> [.plt]: Esta es la tabla de proceso de enlazado (Procedure linkage table).

> [.rel.got]: Contiene la relocalizacion de datos G.O.T. (Global Offset Table).

## El segmento **data** se ve de la siguiente manera.
> [.data]: Contiene las variables globales inicializadas.

> [.dynamic]: Contiene a las estructuras y objectos dinamicamente enlazables.

> [.got.psl]: Contiene la G.O.T.

> [.bss]: Contiene a las variables globales no inicializadas.

No existen **program headers** en los archivos objectos relocalizables (ELF de tipo ET_REL) porque **\*.o** estan ehchos para ser enlazados en un ejecutbale, sin embargo eso no significa que deban ser cargados directamente en memoria.

Los archivos cargables del kernel de linux son objetos del tipo **ET_REL** y son una excepcion a la regla, ya que estos son cargados directamente en la memoria del kernel y relocalizados en ese momento.

Al generar los objetos se pueden observar muchas de las secciones que se han presentado. El siguiente comando nos ayuda a ver las secciones en un ELF:

    readelf -S objfile.o

Cuando se trata de un ejecutable se puede ver que nuevas secciones han sido agregadas, estas secciones son principalmente de tipo enlazamiento dinamico y relocalizaciones en tiempo de ejecucion. (Se usa el mismo comando anterior).

Ejemplo: Hello World

Source file: main.c 

    #include <stdio.h>

    #ifndef EXIT_SUCCESS
     #define EXIT_SUCCESS 0u
    #endif

    int main (void)
    {
        printf("Hello World\n");
        return EXIT_SUCCESS;
    }

Compilamos pero no linkeamos:

    gcc -c main.c

Usamos el comando:

    readelf -S main.o

Lo cual nos despliega la siguiente informacion:

    There are 13 section headers, starting at offset 0x300:

    Section Headers:
      [Nr] Name              Type             Address           Offset
           Size              EntSize          Flags  Link  Info  Align
      [ 0]                   NULL             0000000000000000  00000000
           0000000000000000  0000000000000000           0     0     0
      [ 1] .text             PROGBITS         0000000000000000  00000040
           0000000000000020  0000000000000000  AX       0     0     4
      [ 2] .rela.text        RELA             0000000000000000  00000238
           0000000000000048  0000000000000018   I      10     1     8
      [ 3] .data             PROGBITS         0000000000000000  00000060
           0000000000000000  0000000000000000  WA       0     0     1
      [ 4] .bss              NOBITS           0000000000000000  00000060
           0000000000000000  0000000000000000  WA       0     0     1
      [ 5] .rodata           PROGBITS         0000000000000000  00000060
           000000000000000c  0000000000000000   A       0     0     8
      [ 6] .comment          PROGBITS         0000000000000000  0000006c
           000000000000002c  0000000000000001  MS       0     0     1
      [ 7] .note.GNU-stack   PROGBITS         0000000000000000  00000098
           0000000000000000  0000000000000000           0     0     1
      [ 8] .eh_frame         PROGBITS         0000000000000000  00000098
           0000000000000038  0000000000000000   A       0     0     8
      [ 9] .rela.eh_frame    RELA             0000000000000000  00000280
           0000000000000018  0000000000000018   I      10     8     8
      [10] .symtab           SYMTAB           0000000000000000  000000d0
           0000000000000150  0000000000000018          11    12     8
      [11] .strtab           STRTAB           0000000000000000  00000220
           0000000000000018  0000000000000000           0     0     1
      [12] .shstrtab         STRTAB           0000000000000000  00000298
           0000000000000061  0000000000000000           0     0     1

Usamos el siguiente comando, para generar nuestro ejecutable.

    gcc main.o -o executable

Nuevamente usamos:

    readelf -S executable

Lo cual nos despliega la siguiente informacion:

    There are 28 section headers, starting at offset 0x10ba8:

    Section Headers:
      [Nr] Name              Type             Address           Offset
           Size              EntSize          Flags  Link  Info  Align
      [ 0]                   NULL             0000000000000000  00000000
           0000000000000000  0000000000000000           0     0     0
      [ 1] .interp           PROGBITS         0000000000000238  00000238
           000000000000001b  0000000000000000   A       0     0     1
      [ 2] .note.gnu.bu[...] NOTE             0000000000000254  00000254
           0000000000000024  0000000000000000   A       0     0     4
      [ 3] .note.ABI-tag     NOTE             0000000000000278  00000278
           0000000000000020  0000000000000000   A       0     0     4
      [ 4] .gnu.hash         GNU_HASH         0000000000000298  00000298
           000000000000001c  0000000000000000   A       5     0     8
      [ 5] .dynsym           DYNSYM           00000000000002b8  000002b8
           00000000000000f0  0000000000000018   A       6     3     8
      [ 6] .dynstr           STRTAB           00000000000003a8  000003a8
           0000000000000092  0000000000000000   A       0     0     1
      [ 7] .gnu.version      VERSYM           000000000000043a  0000043a
           0000000000000014  0000000000000002   A       5     0     2
      [ 8] .gnu.version_r    VERNEED          0000000000000450  00000450
           0000000000000030  0000000000000000   A       6     1     8
      [ 9] .rela.dyn         RELA             0000000000000480  00000480
           00000000000000c0  0000000000000018   A       5     0     8
      [10] .rela.plt         RELA             0000000000000540  00000540
           0000000000000078  0000000000000018  AI       5    21     8
      [11] .init             PROGBITS         00000000000005b8  000005b8
           0000000000000018  0000000000000000  AX       0     0     4
      [12] .plt              PROGBITS         00000000000005d0  000005d0
           0000000000000070  0000000000000000  AX       0     0     16
      [13] .text             PROGBITS         0000000000000640  00000640
           0000000000000138  0000000000000000  AX       0     0     64
      [14] .fini             PROGBITS         0000000000000778  00000778
           0000000000000014  0000000000000000  AX       0     0     4
      [15] .rodata           PROGBITS         0000000000000790  00000790
           0000000000000014  0000000000000000   A       0     0     8
      [16] .eh_frame_hdr     PROGBITS         00000000000007a4  000007a4
           000000000000003c  0000000000000000   A       0     0     4
      [17] .eh_frame         PROGBITS         00000000000007e0  000007e0
           00000000000000b4  0000000000000000   A       0     0     8
      [18] .init_array       INIT_ARRAY       000000000001fd90  0000fd90
           0000000000000008  0000000000000008  WA       0     0     8
      [19] .fini_array       FINI_ARRAY       000000000001fd98  0000fd98
           0000000000000008  0000000000000008  WA       0     0     8
      [20] .dynamic          DYNAMIC          000000000001fda0  0000fda0
           00000000000001f0  0000000000000010  WA       6     0     8
      [21] .got              PROGBITS         000000000001ff90  0000ff90
           0000000000000070  0000000000000008  WA       0     0     8
      [22] .data             PROGBITS         0000000000020000  00010000
           0000000000000010  0000000000000000  WA       0     0     8
      [23] .bss              NOBITS           0000000000020010  00010010
           0000000000000008  0000000000000000  WA       0     0     1
      [24] .comment          PROGBITS         0000000000000000  00010010
           000000000000002b  0000000000000001  MS       0     0     1
      [25] .symtab           SYMTAB           0000000000000000  00010040
           0000000000000840  0000000000000018          26    65     8
      [26] .strtab           STRTAB           0000000000000000  00010880
           000000000000022c  0000000000000000           0     0     1
      [27] .shstrtab         STRTAB           0000000000000000  00010aac
           00000000000000fa  0000000000000000           0     0     1

Como se habia explicado antes, ya en el ejecutable podemos ver que se han agregado las secciones que son enlazadas dinamicamente y en tiempo de ejecucion.

## Simbolo ELF.

Los **simbolos** son referencias a cualuqier tipo de dato o codigdo como variables globales o funciones.Por ejemplo para la funcion **prinft()** va a tomar un simbolo de entrada que apunta a la tabla dinamica de simbolos **.dymsim**. Normalmente para las librerias dinamicas o ejecutable dinamicamente enlazados existen dos tablas de simbolos.

Anteriormente con el comando ***readelf -S*** en el ejecutable se pueden ver las dos secciones: **.dynsym** y **.symtab**.

**.dymsym** contiene simbolos globales que referencian a simbolos de fuentes externas como por ejemplo **libc** con **printf**. 

De hecho los simbolos contenidos en **.symtab** contiene todos los simbolos de **.dynsym**, asi como los simbolos locales del ejecutable tal como las variables globales, funciones locales que se han definido en el codigo.

Por lo tanto **.symtab** contiene todos los simbolos, mientras que **.dynsim** contiene simbolos globales/dinamicos.

Entonces Por que tenemos dos tablas de simbolos, si **.symtab** contiene todo lo que esta en **.dynsym**? Si se revisa con el comando ***readelf -S*** el ejecutable, se puede ver que algunas secciones estan marcadas con **A** (ALLOC) o **WA** (WRITE/ALLOC) o **AX** (ALLOC/EXEC), por lo tanto podemos que **.dynsym**  esta marcada con **ALLOC**, mientras que **.symtab** no tiene bandera alguna.

**ALLOC** significa que la seccion sera llenada en tiempo de ejecucion y cargada en memoria, **.symtab** no es cargada en memoria porque no es necesaria para la ejecucion. 

**.dymsym** contiene simbolos que solo se pueden resolver mientras el programa se ejecuta y por lo tanto hay simbolos requeridos en tiempo de ejecucion por el enlazador dinamico.

Mientras que la tabla **.dymsym** es necesaria para la ejecucion de ejecutable dinamicamente enlazados, la tabla **symtab** existe para propositos de debuggeo y enlazado, por lo tanto puede ser **stripped** (removidos) para los binarios de produccion para liberar espacio.

Asi luce la estructura de los simbolos ELF:

    typedef struct
    {
      Elf64_Word    st_name;                /* Symbol name (string tbl index) */
      unsigned char st_info;                /* Symbol type and binding */
      unsigned char st_other;               /* Symbol visibility */
      Elf64_Section st_shndx;               /* Section index */
      Elf64_Addr    st_value;               /* Symbol value */
      Elf64_Xword   st_size;                /* Symbol size */
    } Elf64_Sym;

Esta estructura la podemos encontrar dentro de las secciones **.symtab** y **.dynsym**, esto es el porque **sh_entsize** (section header entre size) las secciones son equivalentes para ***sizeof(ElfN_Sym)***.

### st_name.
**st_name** contiene un offset en la tabla de strings de la tabla de simbolos (localizada en .dynstr o .strtab), donde el nombre de el simbolo esta localizado, por ejemplo: printf.

### st_value.
**st_value** conserva el valor del simbolo (sea una direccion o offset de su localizacion).

### st_size.
**st_size** contiene el tamano del simbolo. tal como el tamano de una funcion global **ptr**, en el caso de de un sistema de 32 bits seria de 4 bytes.

### st_other.
Este miembro define la visibilidad de un simbolo.

### st_shndx.
Cada entrada de tabla de simbolos es definida en relacion a una seccion. Este miembro contiene el indice del header table.

### st_info.
**st_info** especifica el simbolo de tipo y sus atributos de vinculo. Los simbolos de tipo comienzan con **STT** mientras que los simbolos de vinculo (binding symbols) comienzan con **STB**.

### Simbolos de tipo.
> STT_NOTYPE: Simbolo de tipo indefinido.

> STT_FUNC: El simbolo es asociado con una funcion u otra codigo ejecutable.

> STT_OBJECT: El simbolo es asociado a un **objeto**.

### Simbolos de vinculo.
> STB_LOCAL: Los simbolos locales no son visibles fuera de la rchivo objecto que contenga su definicion, como es el caso de una funcion declarada como static.

> STB_GLOBAL: Los simbolos globales son visibles a todos los archivos objetos siendo combinados. Una definicion de un archivo de un simbolo global va a satisfacer la referencia otro archivo con el mismo simbolo.

> STB_WEAK: Es similar al vinculo global pero con menos precedencia, esto es que si el vinculo es debil puede ser anulado por otro simbolo con el mismo nombre sin la marca de **STB_WEAK**.

Hay macros para empaquetar o desempaquetar los campos de tipos y vinculos.

    /* How to extract and insert information held in the st_info field.  */

    #define ELF32_ST_BIND(val)              (((unsigned char) (val)) >> 4)
    #define ELF32_ST_TYPE(val)              ((val) & 0xf)
    #define ELF32_ST_INFO(bind, type)       (((bind) << 4) + ((type) & 0xf))    

    /* Both Elf32_Sym and Elf64_Sym use the same one-byte st_info field.  */
    #define ELF64_ST_BIND(val)              ELF32_ST_BIND (val)
    #define ELF64_ST_TYPE(val)              ELF32_ST_TYPE (val)
    #define ELF64_ST_INFO(bind, type)       ELF32_ST_INFO ((bind), (type))

ELF64_ST_BIND(val): extrae un vinculo de un valor de **st_info**.

ELF64_ST_TYPE(val): extrae un tipo de de un valor de **st_info**.

ELF64_ST_INFO(bind, type): convierte un vinculo o tipo en un valor de **st_info**.

Echemos un vistazo a la tabla de simbolos del siguiente codigo:

    static inline void foochu()
    { /* Do nothing */ }

    void func1()
    { /* Do nothing */ }

    _start()
    {
        func1();
        foochu();
    }

Con el siguiente comando podemos ver las entradas de la tabla de simbolos para las funciones ***foochu** y ***func***.

    readelf -s yourfile | egrep 'foochu|func1'

Podremos ver que la funcion ***foochu*** tiene un valor de **0x8048da** y es una funcion (STT_FUNC) que tiene un vinculo local de simbolos (STB_LOCAL), esto es porque fue declarado con la palabra reservada **static** en nuestro codigo.


    7: 080480d8 5 FUNC LOCAL  DEFAULT 2 foochu
    8: 080480dd 5 FUNC GLOBAL DEFAULT 2 func1

Recordar que los vinculos locales son aquellos cuyos simbolos no pueden ser vistos afuera del archivo tipo objecto donde han sido definidos.

## ELF Relocations.
La relocalizacion es el proceso para conectar referencias simbolicas con definiciones simbolicas. Los archivos relocalizables deben tener informacion que describa como modificar el contenido de sus secciones, para permitir a los ejecutables, librerias dinamicas tener la informacion correcta de la imagen de un programa.

Imaginemos tener dos archivos tipo objeto enlazados juntos para crear un ejecutable. Tenemos obj1.o y obj2.o que contienen el codigo para llamar a una funcion llamada foo() que esta localizada en obj2.o. Ambos archivos son analizados por el linker y contienen registros de relocalizacion, estos archivos deben ser enlazados para crear un programa ejecutbale completo. Las referencias simbolicas deben ser resueltas en definiciones simbolicas, pero que significa esto? Los archivos tipo objeto son relocalizables, lo que significa que su codigo debe ser relocalizado a una locacion en una direccion dada dentro de un segmento ejecutable. Antes de la relocalizacion, el codigo contiene simbolos y codigo que no puede ser propiamente referenciado sin primero conocer la localidad en memoria.

Entrada de relocalizacion:

    typedef struct
    {
      Elf64_Addr    r_offset;               /* Address */
      Elf64_Xword   r_info;                 /* Relocation type and symbol index */
    } Elf64_Rel;

    /* Relocation table entry with addend (in section of type SHT_RELA).  */

    typedef struct
    {
      Elf64_Addr    r_offset;               /* Address */
      Elf64_Xword   r_info;                 /* Relocation type and symbol index */
      Elf64_Sxword  r_addend;               /* Addend */
    } Elf64_Rela;

    /* RELR relocation table entry */

    typedef Elf32_Word      Elf32_Relr;
    typedef Elf64_Xword     Elf64_Relr;

**r_offset** apunta a la ubicacion que requiere una accion de relocalizacion. Una accion de relocalizacion descrbie los detalles de como escribir el codigo o informacion contenido en **r_offset**.

**r_info** provee el indice de la table de simbolos con respecto a que ubicacion debe hacerse y el tipo de relocalizacion a aplicar.

**r_addend** especifica una constante **addend** usada para calcular el valor guardado en el campo relocalizable.

Echemos un vistazo al siguiente ejemplo:

    _start()
    {
        foo();
    }

Se llama a la funcion **foo()** , esta funcion no esta localizadad directamente dentro de archivo de codigo, cuando se hace la compilacion se hara una entrada de relocalizacion que es necesaria para satisfacer las referencias simbolicas mas tarde.

    $ objdump -d obj1.o

    obj1.o: file format elf32-i386
    Disassembly of section .text:
    00000000 <func>:
        0: 55                     push %ebp
        1: 89 e5                  mov %esp,%ebp
        3: 83 ec 08               sub $0x8,%esp
        6: e8 fc ff ff ff         call 7 <func+0x7>
        b: c9                     leave
        c: c3                     ret

Como se puede ver la llamada de **foo()** contiene el valor ***0xfffffffc*** que es literalmente el **addend** implicito. 

Tambien se debe ver ***call 7***, el numero 7 es el offset de la ubicacion de relocalizacion a ser escrita.

Cuando obj1.o ( es el archivo que llama a foo() que se encuentra en obj2.o) es enlazado con obj2.o para hacer un ejecutable, la entrada de relozalizacion que apunta al offset 7 es procesada por en linker, dando la instruccion de cual localizacion (offset 7) necesita ser modificada.

El linker lo que hace es agregar 4 bytes al offset 7 por lo que va a contener el offset real de la funcion foo(), despues de que ha sido posicionado en alguna ubicacion dentro del ejecutable.

    $ readelf -r obj1.o

    Relocation section '.rel.text' at offset 0x394 contains 1 entries:
     Offset    Info     Type     Sym.Value  Sym. Name
    00000007 00000902 R_386_PC32  00000000   foo

Como se puede ver, el campo de relocalizacion en 7 esta especificado por la entrada de relocalizacion **r_offset**.
> **R_386_PC32** es el tipo de relocalizacion. 

> Para entender estos tipos, se debe leer las especificacion del ELF.

> Cada tipo de relocalizacion requiere un calculo diferente en la relocalizacion dentro del sistema. **R_386_PC32** modifica el sistema con S + A - P.

> S es el valor de el simbolos donde reside el indice en la entrada de relocalizacion.

> A es el **addend** encontrado en la entrada de relocalizacion.

> P es el lugar (seccion de offset o direccion) de la unidad de almacenamiento siendo relocalizada (calculada usando **r_offset**).

Observemos la salida final despues de compilar obj1.o y obj2.o en un sistema de 32 bits.

    gcc -nostdlib obj1.o obj2.o -o relocated
    objdump -d relocated

    test: file format elf32-i386

    Disassembly of section .text:

    080480d8 <func>:
     80480d8: 55                       push %ebp
     80480d9: 89 e5                    mov %esp,%ebp
     80480db: 83 ec 08                 sub $0x8,%esp
     80480de: e8 05 00 00 00           call 80480e8 <foo>
     80480e3: c9                       leave
     80480e4: c3                       ret
     80480e5: 90                       nop
     80480e6: 90                       nop
     80480e7: 90                       nop
     
    080480e8 <foo>:
     80480e8: 55                       push %ebp
     80480e9: 89 e5                    mov %esp,%ebp
     80480eb: 5d                       pop %ebp
     80480ec: c3                       ret

Podemos ver que la llamada de la instruccion (el target de relocalizacion) en ***0x80480de*** ha sido modificado con un offset de 32 bits de 5 el cual apunta a foo(). 5 es el valor de la accion de relocalizacion R386_PC_32.

> S + A - P: 0x80480e8 + 0xfffffffc - 0x80480df = 5

0xfffffffc es igual a -4 si es un entero con signo, asi que el calculo seria como sigue:

> 0x80480e8 + (0x80480df + sizeof(uint32_t))

Para calcular el offset en una direccion virtual, se usa el siguiente calculo:

> direccion_de_llamada + offset + 5 (Donde 5 es la longitud de la instruccion de llamada).

En este caso seria: 0x80480de + 5 + 5 = 0x80480e8

Una direccion puede ser calculado en un offset con el siguiente calculo:

> address - address_of_call - 4 (Donde 4 es la longitud del operador inmediato a la instruccion de llamada que es de 32 bits).

## ELF dynamic linking.
Cuando un programa es cargado en memoria, el enlazador dinamico tambien carga y enlaza las librerias dinamicas necesitadas para direccionar el espacio.

El topico de enlazamiento dinamico no es muy entendido del todo, las librerias dinamicas son compiladas independiente de la posicion y por lo tanto pueden ser facilmente relocalizadas en proceso de direccionamiento de espacio. Una libreria dinamica (shared library) es un objeto ELF dinamico. Si se mira con ***readelf -h lib.so*** se podra ver que el tipo **e_type**(ELF file type) es llamado **ET_DYN**. Los objetos dinamicos son muy similares a los ejecutables aunque en el caso de los objetos dinamicos no se tiene un segmento **PT_INTERP** hasta que son cargados por el interprete y por lo tanto no seran invocado por el interprete.

Cuando una libreria dinamica es cargada en un proceso de direccion de espacio, tiene que estar debidamente ligado a otra librerias dinamicas. El linker dinamico debe modificar GOT (Global Offset Table) del ejecutable (localizado en la seccion .got.plt), que es una tabla de direcciones localizada en el segmento **data**. Es en el segmento **data**  porque se necesita que se pueda escribir (al menos inicialmente). El linker dinamico llena el GOT con las direcciones de las librerias dinamicas resueltas.

## El vector auxiliar.
Cuando un programa se carga en memoria por el **sys_execve()** syscall (llamada de sistema), el ejecutable es mapeado en una pila (stack).

La pila (stack) para ese proceso se prepara de una manera muy especifica para pasar informacion al enlazador dinamico (dynamic linker).

Esta preparacion y arreglo de informacion es conocido como auxiliar vector (vector auxiliar) o auxv. 

El fondo de la pila (que es la direccion de memoria mas alta mientras la pila disminuye) es cargado con la siguiente informacion.

    Auxiliar Vector |
    ----------------|
    environ         |
    ----------------|
    argv            |
    ----------------|
    Stack           |
    ----------------|
    |
    V

    [argc][argv][envp][auxiliary][.ascii data for argv/envp]

El vector auxiliar (auxv) tiene la siguiente estuctura:

    typedef struct
    {
      uint64_t a_type;              /* Entry type */
      union
        {
          uint64_t a_val;           /* Integer value */
          /* We use to have pointer elements added here.  We cannot do that,
             though, since it does not work when using 32-bit definitions
             on 64-bit platforms and vice versa.  */
        } a_un;
    } Elf64_auxv_t;

**a_type** describe la entrada de ***auxv*** y **a_val** provee su valor.

A continuacion se muestran los tipos de entradas mas importantes que requiere el enlazador dinamico (dynamic linker).

    #define AT_NULL         0               /* End of vector */
    #define AT_IGNORE       1               /* Entry should be ignored */
    #define AT_EXECFD       2               /* File descriptor of program */
    #define AT_PHDR         3               /* Program headers for program */
    #define AT_PHENT        4               /* Size of program header entry */
    #define AT_PHNUM        5               /* Number of program headers */
    #define AT_PAGESZ       6               /* System page size */
    #define AT_BASE         7               /* Base address of interpreter */
    #define AT_FLAGS        8               /* Flags */
    #define AT_ENTRY        9               /* Entry point of program */
    #define AT_NOTELF       10              /* Program is not ELF */
    #define AT_UID          11              /* Real uid */
    #define AT_EUID         12              /* Effective uid */
    #define AT_GID          13              /* Real gid */
    #define AT_EGID         14              /* Effective gid */
    #define AT_CLKTCK       17              /* Frequency of times() */

El enlazador dinamico (dynamic linker) procesa la informacion del stack para ejecucion del programa.

El enlazador debe saber donde se encuentran los program headers, el punto de entrada del programa, etcetera.

**auxv** se procesa por una funcion del kernel llamada **create_elf_tables()** que reside en la fuente de codigo de linux **/usr/src/linux/fs/binfmt_elf.c**

El proceso de ejecucion de un programa se ve de la siguiente manera:

> 1. sys_execve() ->
> 2. Calls do_execve_common() ->
> 3. Calls search_binary_handler() ->
> 4. Calls load_elf_binary() ->
> 5. Calls create_elf_tables() ->

A continuacion se muestra codigo de **create_elf_tables()** que reside en la fuente de codigo de linux **/usr/src/linux/fs/binfmt_elf.c** que agrega las entradas de **auxv**.

    NEW_AUX_ENT(AT_PAGESZ, ELF_EXEC_PAGESIZE);
    NEW_AUX_ENT(AT_PHDR, load_addr + exec->e_phoff);
    NEW_AUX_ENT(AT_PHENT, sizeof(struct elf_phdr));
    NEW_AUX_ENT(AT_PHNUM, exec->e_phnum);
    NEW_AUX_ENT(AT_BASE, interp_load_addr);
    NEW_AUX_ENT(AT_ENTRY, exec->e_entry);

Como se puede ver, el punto de entrada del ELF y las direcciones de los program headers, se ubican en el stack con la macro del kernel **NEW_AUX_ENT()**.

Una vez un programa en cargado en memoria y el vector auxiliar ha sido llenado, el control se pasa al enlazador dinamico.

En enlazador dinamico resuelve los simbolos y las relocalizaciones para las libreria dinamicas que son enlazadas en el espacio de direccion de procesos.

Por default, un ejecutable es dinamicamente enlazado con la libreria GNU C **libc.so**.

El comando **lld** mostrara las dependencias de las librerias dinamicas de un ejecutable.

## PLT/GOT
La tabla de linkeo de procesos (procedure linkage table - PLT) y GOT (Global Offset Table) se pueden encontrar en los archivos ejecutable y librerias dinamicas.

Cuando un programa llama a una funcion de alguna libreria dinamica, por ejemplo: **strcpy()** o **printf()**, que no son resueltas en tiempo de ejecucion, existe un mecanismo para dinamiocamente enlazar las librerias dinamicas y resolver las direcciones de las funciones compartidas.

Cuando un programa dinamicamente enlazado es compilado, este maneja llamadas de funciones de una libreria de forma determinada, muy diferente a simple llamada de una funcion local.

Por ejemplo, echemos un vistazo cuando se llama a **libc.so** con la funcion fgets().

    objdump -d test
    ...
    8048481: e8 da fe ff ff call 8048360<fgets@plt>
    ...

La direccion **0x8048360** corresponde a la entrada del PLT para fgets()

    objdump -d test (grep for 8048360)
    ...
    08048360<fgets@plt>:              /* A jmp into the GOT */
    8048360: ff 25 00 a0 04 08        jmp *0x804a000
    8048366: 68 00 00 00 00           push $0x0
    804836b: e9 e0 ff ff ff           jmp 8048350 <_init+0x34>
    ...

La llamada de fgets() apunta a **0x8048360**, que es el salto a la tabla de entradas de PLT para fgets(). Como se puede ver, se trata de un salto indirecto a la direccion almacenada en **0x804a000**.

Esta direccion es un entrada GOT que alberga la direccion actual de la funcion **fgets()** en la libreria dinamica **libc**.

Cuando la funcion es llamada por primera vez, su direccion aun no ha sido resuelto por el enlazador dinamico, cuando el comportamiento por default **lazy linking** esta siendo usado.

**Lazy linkig** significa que el enlazador dinamico no resuelve cada funcion en el momento de carga. Por el contrario, resuelve las funciones conforme son llamadas, que es posible a traves de las secciones **.plt** y **got.plt** (que corresponden al tabla de linkeo de procesos y la tabla global de offsets).

Este comportamiento puede ser cambiado a lo que se llama **strict linking** con la variable de ambiente **LD_BIND_NOW**, de esta manera el linkeo dinamico se hace en el momento de carga del programa.

**Lazy linking** incrementa el rendimiento al momento de carga, pero se puede volver impredecible porque un error de linkeo puede ocurrir en tiempo de ejecucion del programa, sobre todo cuando el programa lleva corriendo un tiempo considerable.

Veamos la relocalizacion de entradas para fgets():

    readelf -r test
    Offset    Info          Type         SymValue  SymName
    ...
    0804a000  00000107  R_386_JUMP_SLOT  00000000  fgets
    ...

Hay que notar que el offset de relocalizacion es la direccion 0x804a000, la misma direccion que **fgets()** PLT salto. Asumiendo que **fgest()** ha sido llamada por primera vez, el linker ha resuelto la direccion de **fgets()**vy puesto su valor en la entrada de GOT para **fgets()**.

Veamos en el GOT:

    08049ff4 <_GLOBAL_OFFSET_TABLE_>:
    8049ff4: 28 9f 04 08 00 00         sub %bl,0x804(%edi)
    8049ffa: 00 00                     add %al,(%eax)
    8049ffc: 00 00                     add %al,(%eax)
    8049ffe: 00 00                     add %al,(%eax)
    804a000: 66 83 04 08 76            addw $0x76,(%eax,%ecx,1)
    804a005: 83 04 08 86               addl $0xffffff86,(%eax,%ecx,1)
    804a009: 83 04 08 96               addl $0xffffff96,(%eax,%ecx,1)
    804a00d: 83                        .byte 0x83
    804a00e: 04 08                     add $0x8,%al

La direccion **0x80403866** es encontrada en la direccion **0x804a000** en el GOT.

Hya que recordar que **little endiand** tiene un orden de bytes inversos, por lo tanto aparece como **66 83 04 08**, este no es la direccion de la funcion **fgets()** mientras no haya sido resuelta por el linker, sin mebargo apunta la entrada de PLT para **fgets()**.

    08048360 <fgets@plt>:
    8048360:        ff 25 00 a0 04 08          jmp *0x804a000
    8048366:        68 00 00 00 00             push $0x0
    804836b:        e9 e0 ff ff ff             jmp 8048350 <_init+0x34>

Entonces, ***jmp \*0x804a000*** brinca a la direccion contenida dentro de 0x80403866, que las instruccion ***push $0x0***.

Esa instruccion push tiene el proposito de poner la entrada GOT para **fgets()** en el stack.

El offset de la enyrada GOT de **fgets()** es 0x0, que corresponde a la primera entrada GOT que esta reservada para un valor de simbolo de una libreria dinamica, la cual es la cuarta entrada. En otras palabras la direcciones de las librerias dinamicas no son conectadas empezando el GOT (GOT[0]) y en realidad comienzan en GOT[3], debido a que las primeras tres estan reservadas para otros propositos.

> 1. GOT[0] contiene direcciones que apuntan al segmento dinamico de un ejecutbale, que es usado por el enlazador dinamico para extraer informacion relacionada con el enlazamiento dinamico.

> 2. GOT[2] contiene direcciones de la estructura **link_map** que es usada por el enlazador dinamico para resolver simbolos.

> 3. GOT[2] contiene direcciones de los enlazadores dinamicos **_dl_runtime_resoolve ()**, esta funcion resulve la direccion actual del simbolo para la funcion de la libreria dinamica.

La ultima instruccion en **fgets()** PLT stub es un salto a **8048350. Esta direccion apunta a la primera entrada de PLT en cada ejecutable, conocida como PLT-0.

PLT-0 de nuestro ejecutable contiene el siguiente codigo.

    8048350:     ff 35 f8 9f 04 08      pushl 0x8049ff8
    8048356:     ff 25 fc 9f 04 08      jmp *0x8049ffc
    804835c:     00 00                  add %al,(%eax)

La primera instruccion push1 nos apunta a la segunda entrada GOT, GOT[1] en el stack, que contiene la direccion de la estructura **link_map**.

El salto \*0x8049ffc hace un salto indirecto a la tercera entrada GOT, GOT[2], que contiene la direccion de el enlazador dinamico **_dl_runtime_resolve()**, por lo tanto se transfiere el control al enlazador dinamico y se resuelve la direccion de **fgets()**.

Una vez **fgets()** ha sido resulta, todas las futuras llamada a la entrada PLT **forfgets()** resultara en brinco a el codigo de **fgets()**.

La proxima vez que **fgets()** sea llamada,la entrada PLT brincara directamente a la funcion, a menos que sea haga el proceso de relocalizacion nuevamente.

## Segmento dinamico.
El segmento dinamico tiene un header que lo referencia, pero tambien tiene un header de programa que lo referencia porque tiene que ser en el momento de ejecucion por el segmento dinamico.

Como los headers de las secciones no se cargan en memoria, deben tener asociado un header de programa para ello.

El segmento dinamico tiene la siguiente estructura:

    typedef struct
    {
      Elf64_Sxword  d_tag;                  /* Dynamic entry type */
      union
    {
          Elf64_Xword d_val;                /* Integer value */
          Elf64_Addr d_ptr;                 /* Address value */
        } d_un;
    } Elf64_Dyn;

**d_tag** contiene una etiqueta que puede emparentarse con alguna de las numerosas definiciones que pueden ser encontradas en un ELF. 

A continuacion se listan las mas importantes usadas por el linker dinamico.

### DT_NEEDED
Contiene el offste de la tabla de cadenas al nombre de la libreria dinamica compartida.

### DT_SYMTAB
Contiene las direcciones de la tabla de los simbolos dinamicos **.dynsym**.

### DT_HASH
Contiene la direcciones de la tabla de simbolos hash **.hash**.

### DT_STRTAB
Contiene las direcciones de la tabla de cadenas de simbolos **.dynstr**.

### DT_PLTGOT
Contiene la direccion de la tabla de offsets globales.

Las etiquetas dinamicas demuestran coma la localizacion de algunas secciones pueden ser enocntradas a traves del segmento dinamico que puede ayudar en la tarea de reconstruccion forense de reconstruir una tabla de headers de secciones.

Si el header de la tabla ha sido borrado, una herramienta puede reconstruir las partes de este a partir del segmento dinamico.

Otros segmentos como **text** y **data** pueden juntar la informacion que se necesita (como **.text** y **.data**).

**d_val** contiene unvalor entero que tiene varias interpretaciones como puede ser el tamano de la entrada de relozalizacion para dar una instancia.

**d_ptr** contiene la direccion virtual de memoria que apunta a distintas localizaciones necesitadas por el linker, un buen ejemplo seria la direccion de la tabla de simbolos.

El enlazador dinamico utiliza **ElfN_Dyn d_tags** para localizar diferentes partes del segmento dinamico que contiene una referencia a una parte del ejecutable a traves de **d_tag** asi como **DT_SYMTAB** para proveer la direccion virtual de la tabla de simbolos.

Cuando el linker dinamico es mapeado en memoria, primero maneja cualquiera de sus propias relocalizaciones si es necesario, ***hay que recordar que el linker o enlazador es en si una libreria dinamica***.

El segmento dinamico de un programa ejecutable es usado por el linker dinamico y busca las etiquetas de **DT_NEDEED** que contienen apuntadores a las cadena o nombres de direcciones de las librerias dinamicas usadas.

Cuando se mapea una libreria dinamica en memoria, se accede al segmento dinamico de la libreria y agrega la tabla de simbolos de la libreria a una tabla de simbolos que existen pararetener la tabla de simbolos de cada libreria mapeada.

El linker crea una estructura de entrada **link_map** para cada libreria dinamica y la agrega en una lista ligada.

    struct link_map
    {
        ElfW(Addr) l_addr;                  /* Base address shared object is loaded at. */
        char *l_name;                       /* Absolute file name object was found in. */
        ElfW(Dyn) *l_ld;                    /* Dynamic section of the shared object. */
        struct link_map *l_next, *l_prev;   /* Chain of loaded objects. */
    };

Una vez que el linker ha terminado la construccion de la lista de sus dependencias, maneja las relocalizaciones de cada libreria, de manera similar a las relocalizaciones que se han discutido anteriormente.

**Lazy linking** aun usa **PLT/GOT** de las librerias dinamicas, por lo tanto las relocalizaciones de GOT no sucederan hasta que la funcion haya sido llamada.

Ver el ejercicio **example1**.
