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

### ltrace
Esta herramienta es similar a **strace**, **ltrace** usa la informacion de las libreria dinamicas de un programa e imprime las funciones que se estan usando de la libreria.