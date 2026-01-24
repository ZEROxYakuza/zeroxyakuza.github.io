## Local Payload Execution

## ¿Qué vamos a ver?
Durante este post echaremos un vistazo tanto a la carga de un DLL malicioso en el proceso actual, como a la inyección directa de shellcode en dicho proceso.

### DLL Injection
Empezaremos con la creación del DLL, lo cual haremos mediante el editor Visual Studio. Para ello, hacemos click en "Crear un proyecto" y posteriormente filtraremos por la palabra clave "dll" y el lenguaje de programación C++. Una vez hecho esto, veremos la opción de "Biblioteca de vínculos dinámicos (DLL)".

---

<img width="883" height="220" alt="imagen" src="https://github.com/user-attachments/assets/de34608e-3f3f-43b6-9c80-9f3325493eb8" />

---

Personalizamos el nombre del proyecto y de la solución.

---

<img width="883" height="387" alt="imagen" src="https://github.com/user-attachments/assets/3c367188-a928-4b33-a33b-c55746708c5f" />

---

Crearemos un DLL que al cargarse en el proceso nos muestre un mensaje por pantalla, haremos uso de la API de Windows para ello. Usaremos bastante esta API durante todos los posts relacionados al desarrollo de Malware, puedes echar un vistazo a la documentación oficial de Microsoft --> https://learn.microsoft.com/en-us/windows/win32/api/


Antes de empezar a diseccionar el esqueleto del DLL generado, vamos a ver qué son los "Precompiled Headers"

### Precompiled Headers
Al crear un DLL mediante la plantilla de Visual Studio se generan también los archivos framework.h, pch.h y pch.cpp, los cuales conocemos como "Precompiled Headers". Estos son archivos que se usan para que la compilación de proyectos grandes sea más rápida. No los vas a necesitar en esta situación, así que recomiendo borrarlos para que la carga del dll no dependa de varios archivos adicionales.

Para ello, borraremos estos tres archivos una vez cargado el proyecto.

---

<img width="261" height="270" alt="imagen" src="https://github.com/user-attachments/assets/8007f4d0-261d-43c8-b0e6-fde642307c75" />

---

También eliminaremos la línea `#include "pch.h"` del archivo dllmain.cpp , y añadiremos en su lugar `#include <Windows.h>` para hacer uso de la API de Windows. No olvides ademas cambiar la extensión de dllmain a ".c" .

---

<img width="261" height="270" alt="imagen" src="https://github.com/user-attachments/assets/92f411d7-c6d0-4bdb-beaf-02ddaf170757" />


---

No nos podemos olvidar de también cambiar una serie de ajustes para que no se intenten buscar dichos archivos durante el compilado. Para ello nos dirigimos a "Proyecto" --> "DLL_Local_Injection Propiedades".

---

<img width="787" height="377" alt="imagen" src="https://github.com/user-attachments/assets/ebdd59bc-949a-41c0-994e-52c81989d685" />

---

Debemos asignarle a la primera opción el siguiente valor.

---

<img width="787" height="377" alt="imagen" src="https://github.com/user-attachments/assets/b9294d12-46e8-4327-a01e-8cc3c1cd7a37" />

---

Una vez hecho todo esto, ya podemos seguir con nuestro trabajo, es decir, el DLL Local Process Injection.

### DLL Injection (ahora sí)
Si hemos seguido todos los pasos correctamente, veremos el siguiente código en dllmain.c :

```c
#include <Windows.h>

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
```

Vamos a modificarlo a lo siguiente:

```c
#include <Windows.h>

VOID MsgBox() {
    MessageBoxA(NULL, "DLL Loaded, hacked by ZEROxYakuza", "You are a noob!", MB_OK | MB_ICONINFORMATION);
}


BOOL APIENTRY DllMain (HMODULE hModule, DWORD dwReason, LPVOID lpReserved){

    switch (dwReason){
        case DLL_PROCESS_ATTACH: {
            MsgBox();
            break;
        };
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }

    return TRUE;
}
```

Vale, ¿qué hemos hecho aquí?. Primero de todo hemos creado la función MsgBox(), la cual muestra el mensaje que deseamos al usuario. Aquí tienes la documentación para MessageBoxA --> https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messageboxa

Posteriormente hemos indicado que cuando el DLL se cargue (DLL_PROCESS_ATTACH), se ejecute nuestra función.

(Post en proceso de creación...)
