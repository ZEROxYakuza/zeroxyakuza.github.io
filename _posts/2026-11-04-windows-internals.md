---
title: "Windows Internals"
date: 2026-11-04 18:00:00 +0200
description: "Aprendizaje sobre Windows Internals para Evasión y Red Team."
---

## Introducción y breve inciso

Este es el principio de lo que se espera que sea una larga serie documentando y explicando operaciones de Red Team y Evasión en Windows. Posiblemente encontréis este primer post bastante extenso y teórico, pero creo que es importante sentar las bases de cómo funciona windows y su arquitectura antes de ponernos a romper y bypassear cosas. 

Puede que en algunos casos use contenido supervisado por IA para que algunos conceptos queden mejor explicados, me explico, no son posts generados por una Inteligencia Artificial, soy yo (David, un humano) el que escribe estos artículos. Simplemente no descarto que en algunos casos que no sepa como transmitir algo, le pregunte a un chat de IA cómo enseñarlo y plasmarlo mejor. Era un disclaimer que quería hacer, sinceridad ante todo. 

Disculpen por el tocho que se viene, he intentado incluir técnicas interesantes por el final de este artículo, a modo de casos prácticos. Os adelanto que el siguiente post va a ser sobre EDR Internals, así que se viene otro Conde de Montecristo hecho artículo.

## User Mode y Kernel Mode

El procesador de un ordenador que ejecuta Windows funciona en dos modos diferentes: el modo de usuario (user mode) y el modo de núcleo (kernel mode). El procesador alterna entre estos modos en función del tipo de código que esté ejecutando. Las aplicaciones funcionan en user mode. Los componentes principales del sistema operativo funcionan en kernel mode. 

<div align="center">
  <img width="450" height="374" alt="imagen" src="https://github.com/user-attachments/assets/07509fd3-31a1-414b-b7ff-28b18089613b" />
</div>


---

## 1. User Mode

Cuando se inicia una aplicación en modo usuario, Windows crea un proceso para ella. Este proceso proporciona a la aplicación un espacio de direcciones virtuales privado y una tabla de identificadores privada. Dado que el espacio de direcciones virtuales de cada aplicación es privado, una aplicación no puede modificar los datos de otra. Cada aplicación se ejecuta de forma aislada. Este enfoque garantiza que, si una aplicación falla, no afecte a otras aplicaciones ni al sistema operativo.

---

### 1.1 Procesos

Es un contenedor que separa las aplicaciones entre sí. Se encarga de manejar los Threads, Handles, Tokens y la Memoria. Tenemos que tener en cuenta que el Process no ejecuta nada, es el Hilo (thread) el que corre el código.

Presenta varias características:

- Identificado por un PID (Process ID) único, y si el proceso se destruye, otro proceso reusa su PID.

- Un proceso puede ser huérfano o tener un proceso padre (parent process). Si el parent process muere, el proceso hijo (child process) no se ve afectado.

- Todo proceso presenta un nivel de integridad (integrity level) que define lo que puede hacer el proceso.

---

### 1.2 Niveles de Integridad

Tenemos cuatro distintos niveles de integridad para los procesos:

- Low Integrity --> Únicamente puede interactuar con otros procesos de integridad baja.

- Medium Integrity --> Puede interactuar con procesos de integridad media y baja. Es el nivel por defecto para la mayoría de procesos de la capa de usuario.

- High Integrity --> Tiene la capacidad de interactuar con procesos de integridad alta, media y baja. Es usado para aplicaciones que se ejecutan con permisos administrativos.

- System Integrity --> El nivel de integridad más alto, está revervado para los componentes del sistema operativo. Puede interactuar con todos los diferentes niveles de integridad.

---

### 1.3 Mitigaciones

Existen una serie de mecanismos de seguridad implementados en Windows para reducir la superficie de ataque y proteger contra técnicas de explotación:

- Data Execution Prevention (DEP) --> Previene la ejecución de código en el stack y el heap.

- Address Space Layout Randomization (ASLR) --> Hace que las direcciones de memoria de los ejecutables y DLLs se definan de forma aleatoria. Esto mitiga técnicas como Return Oriented Programming (ROP).

- Control Flow Guard (CFG) --> Protege contra exploits de corrupción de memoria.

- Signatures Restricted (Microsoft Only) --> Permite solo la ejecución de código firmado por Microsoft.

- Images Restricted --> Bloquea la carga de ejecutables y DLLs desde recursos compartidos como samba (SMB).

---

### 1.4 Threads

Los hilos se encargan de la ejecución de código. Los tipos de hilos más relevantes son:

- Main Thread --> Ejecuta la función principal.

- Threads creados por el código --> Ejecutan funciones definidas por el programador, corriendo concurrentemente con el hilo principal.

Definimos también tres estados distintos para los hilos:

- Waiting --> El hilo se encuentra esperando para la condición necesaria y que continúe la ejecución.

- Ready --> El hilo está preparado para ejecutar pero está esperando la disponibilidad del procesador.

- Running --> El hilo está ejecutándose.

---

### 1.5 Handles

Un handle es un objeto abstracto que actúa como una referencia numérica indexada a un recurso interno del kernel. Vamos, que es algo que pedimos prestado del kernel mediante un indexador.

Cuando un proceso necesita interactuar con un recurso del sistema, como un archivo, un hilo, una clave del registro o un socket de red, no puede acceder a las estructuras de datos de kernel directamente debido a la separación entre modo usuario y modo kernel. En su lugar, el kernel crea la estructura del objeto en espacio de kernel y le devuelve al proceso un entero de 32 o 64 bits: el handle.

Entonces te preguntarás, ¿el handle es un puntero al objeto creado en el kernel? Pues tengo malas noticias querido lector, no es tan sencillo como eso.

Para visualizar la diferencia entre el handle y el objeto del kernel:

- Objeto de Kernel: Es el abrigo físico colgado en el armario de un guardarropa. Está dentro de una zona restringida (Modo Kernel) y tú no puedes pasar a cogerlo directamente, ya que te encuentras en una zona de usuario.

- Handle: Es el tique de plástico con un número (ej. #42) que te da el encargado al dejar el abrigo.

- Uso: Cuando quieres recuperar o usar el abrigo, le enseñas al encargado el tique #42. El encargado (el kernel) busca el perchero #42 en su lista interna, verifica si el tique es tuyo y te da acceso al abrigo.

---

### 1.6 Tokens

A nivel interno en el kernel, encontramos el token de acceso, el cual almacena el contexto de seguridad de un proceso. Entre sus campos principales se encuentran:

- User SID (Security Identifier) -->  El SID del usuario que posee el proceso (ej. S-1-5-21-...-1001). Identifica quién ejecutó el programa.

- Group SIDs --> Una lista de todos los grupos a los que pertenece el usuario (ej. Administradores, Usuarios, Usuarios del escritorio remoto), indicando cuáles están activos para la sesión actual.

- Privilegios --> La lista de derechos del sistema otorgados al token (ej. SeDebugPrivilege para auditar/depurar otros procesos, SeBackupPrivilege, SeShutdownPrivilege). Cada privilegio puede estar habilitado (Enabled) o deshabilitado (Disabled).

- Nivel de Integridad (Integrity Level) --> Clasifica el proceso en uno de los cuatro niveles principales de integridad.

- Token Type --> Puede ser `TokenPrimary` si el token es asignado por defecto a un proceso, o `TokenImpersonation` cuando un token temporal utilizado por un hilo se utiliza para hacerse pasar por otro usuario.

---

### 1.7 Memoria Virtual

La memoria virtual es la abstracción fundamental de gestión de memoria en Windows. Proporciona a cada proceso la ilusión de tener un espacio de direcciones contiguo, privado y aislado (de 4 GB en 32-bit o hasta 128 TB en 64-bit para espacio de usuario), ocultando la complejidad del hardware y de la memoria RAM física.

Igual algo en este texto te ha provocado una explosión cerebral, ¿cómo es posible tener más memoria virtual que física? Pues por tres conceptos principales:

- El espacio de direcciones no consume RAM por sí solo --> Cuando un programa asigna un bloque de memoria virtual (por ejemplo, pidiendo 10 GB con VirtualAlloc), el kernel solo crea entradas en las tablas de páginas y marca esas direcciones como Reservadas o Comprometidas.

- Paginación bajo demanda --> La RAM física solo se asigna cuando el programa intenta leer o escribir realmente en la memoria asignada. Si una aplicación reserva 100 GB pero solo toca 10 MB, solo consumirá 10 MB de RAM física.

- El archivo de paginación --> Si los procesos terminan necesitando simultáneamente más memoria física de la disponible en los módulos RAM, el gestor de memoria del kernel (Memory Manager) selecciona páginas de RAM que llevan tiempo sin usarse (o que están inactivas) y las escribe en el disco en el archivo `pagefile.sys` , y entonces, al vaciar esa RAM, el marco físico queda libre para que lo use otro proceso.

---

## 2. Kernel Mode

Todo el código que se ejecuta en modo kernel comparte un único espacio de direcciones virtuales. Por ello, un controlador en modo kernel no está aislado de otros controladores ni del sistema operativo. Si un controlador en modo kernel escribe por error en una dirección virtual incorrecta, podría comprometer los datos que pertenecen al sistema operativo o a otro controlador. Si un controlador en modo kernel falla, provoca que todo el sistema operativo se bloquee.

---

### 2.1 EPROCESS

La estructura _EPROCESS (Executive Process) es la estructura de datos central que utiliza el kernel de Windows para representar la parte de alto nivel de un proceso.

Reside exclusivamente en el espacio de memoria del kernel. Mientras que un handle de proceso en modo usuario es simplemente un entero abstracto, en el kernel ese handle referencia internamente al objeto que envuelve a esta estructura.

Sus campos principales son:

- Pcb -->	Estructura de control del microkernel (planificación, CR3, etc.).

- UniqueProcessId	--> El PID (Process ID) del proceso en el sistema.

- ActiveProcessLinks --> Lista doblemente enlazada global que une a todos los procesos activos del sistema.

- Token -->	Referencia rápida con recuento de referencias al Access Token (_TOKEN) del proceso.

- ObjectTable -->	Puntero a la tabla de handles privada del proceso.

- Peb	--> Puntero al Process Environment Block (ubicado en espacio de usuario).
 
- ImageFileName	--> Cadena ASCII de hasta 15 caracteres con el nombre del ejecutable (ej. lsass.exe).

- VirtualSize / WorkingSetPage -->	Métricas de contabilidad y consumo de memoria virtual y física.
  
- MitigationFlags / Protection --> Configuraciones de seguridad.

---

## 3. Process Hiding (Caso Práctico)

He mencionado anteriormente de forma breve la estructura `ActiveProcessLinks`, y la he definido como una lista doblemente enlazada que une a todos los procesos del sistema. Para cada entrada de la lista doblemente enlazada, tenemos dos campos, flink y blink, los cuales apuntan al siguiente y anterior elemento respectivamente. Entonces, os pregunto lo siguiente: ¿Podríamos manipular los campos flink y blink de manera que ocultemos un proceso? Pues esta vez sí que tengo buenas noticias, podemos hacerlo.

Para ocultar el proceso `cmd`, tenemos que modificar la cadena haciendo que el "Flink" de los "ActiveProcessLinks" del proceso anterior apunte a los "ActiveProcessLinks" del proceso siguiente de "cmd". Y que el "Blink" de los "ActiveProcessLinks" del proceso siguiente de "cmd" apunte a los "ActiveProcessLinks" del proceso anterior de "cmd".

<img width="1024" height="572" alt="imagen" src="https://github.com/user-attachments/assets/f68e173b-09da-4e41-8ddc-b7eee104b09e" />


---
