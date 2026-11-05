---
title: "Windows Internals"
date: 2026-11-05 18:00:00 +0200
description: "Aprendizaje sobre Windows Internals para Evasión y Red Team."
---

## User Mode y Kernel Mode

El procesador de un ordenador que ejecuta Windows funciona en dos modos diferentes: el modo de usuario (user mode) y el modo de núcleo (kernel mode). El procesador alterna entre estos modos en función del tipo de código que esté ejecutando. Las aplicaciones funcionan en user mode. Los componentes principales del sistema operativo funcionan en kernel mode. 

<div align="center">
  <img width="450" height="374" alt="imagen" src="https://github.com/user-attachments/assets/07509fd3-31a1-414b-b7ff-28b18089613b" />
</div>


---

## 1. User Mode

Cuando se inicia una aplicación en modo usuario, Windows crea un proceso para ella. Este proceso proporciona a la aplicación un espacio de direcciones virtuales privado y una tabla de identificadores privada. Dado que el espacio de direcciones virtuales de cada aplicación es privado, una aplicación no puede modificar los datos de otra. Cada aplicación se ejecuta de forma aislada. Este enfoque garantiza que, si una aplicación falla, no afecte a otras aplicaciones ni al sistema operativo.


### 1.1 Procesos

Es un contenedor que separa las aplicaciones entre sí. Se encarga de manejar los Threads, Handles, Tokens y la Memoria. Tenemos que tener en cuenta que el Process no ejecuta nada, es el Hilo (thread) el que corre el código.

Presenta varias características:

- Identificado por un PID (Process ID) único, y si el proceso se destruye, otro proceso reusa su PID.

- Un proceso puede ser huérfano o tener un proceso padre (parent process). Si el parent process muere, el proceso hijo (child process) no se ve afectado.

- Todo proceso presenta un nivel de integridad (integrity level) que define lo que puede hacer el proceso.

### 1.2 Niveles de Integridad

Tenemos cuatro distintos niveles de integridad para los procesos:

- Low Integrity --> Únicamente puede interactuar con otros procesos de integridad baja.

- Medium Integrity --> Puede interactuar con procesos de integridad media y baja. Es el nivel por defecto para la mayoría de procesos de la capa de usuario.

- High Integrity --> Tiene la capacidad de interactuar con procesos de integridad alta, media y baja. Es usado para aplicaciones que se ejecutan con permisos administrativos.

- System Integrity --> El nivel de integridad más alto, está revervado para los componentes del sistema operativo. Puede interactuar con todos los diferentes niveles de integridad.

-En construcción...-

## 2. Kernel Mode

Todo el código que se ejecuta en modo kernel comparte un único espacio de direcciones virtuales. Por ello, un controlador en modo kernel no está aislado de otros controladores ni del sistema operativo. Si un controlador en modo kernel escribe por error en una dirección virtual incorrecta, podría comprometer los datos que pertenecen al sistema operativo o a otro controlador. Si un controlador en modo kernel falla, provoca que todo el sistema operativo se bloquee.
