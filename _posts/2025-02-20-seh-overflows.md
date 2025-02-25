## SEH Overflows (In Progress)

## What is SEH?

SEH (Structured Exception Handling) in Windows is a built-in mechanism for handling exceptions at the operating system level. It provides a way for applications to catch and handle errors (such as access violations or divide-by-zero errors) in a structured manner.
Key Features of SEH:

1. Exception Handling: SEH allows programs to handle runtime errors and recover gracefully instead of crashing.
2. Stack-Based Mechanism: Exception handlers are stored in a linked list on the stack, so when an exception occurs, Windows walks through the list to find a suitable handler.
3. Support for Unhandled Exceptions: If an exception isn't handled within the application, Windows' default handler steps in, often displaying an error message or generating a crash dump.
4. Hardware and Software Exceptions: SEH can catch both hardware exceptions (like illegal memory access) and software exceptions (such as RaiseException calls).

### How SEH (Structured Exception Handling) is Stored in Windows

SEH (Structured Exception Handling) uses a linked list structure stored on the stack to keep track of registered exception handlers. The Windows kernel relies on this list to locate appropriate handlers when an exception occurs.

![imagen](https://github.com/user-attachments/assets/0bc4b3b6-4685-412e-9935-75e748b522f9)

### SEH Chain in the Stack

- The SEH handlers are stored as a linked list on the thread's stack.
- Each function that registers an exception handler pushes an EXCEPTION_REGISTRATION_RECORD onto the stack.
- The head of this linked list is stored in the Thread Environment Block (TEB) at offset 0x00 on x86 architectures.

### Structure of an SEH Record

Each entry in the SEH chain is represented by the EXCEPTION_REGISTRATION_RECORD structure:

```c
typedef struct _EXCEPTION_REGISTRATION_RECORD {
    struct _EXCEPTION_REGISTRATION_RECORD *Next; // Pointer to the next SEH record
    PEXCEPTION_HANDLER Handler; // Pointer to the exception handler function
} EXCEPTION_REGISTRATION_RECORD, *PEXCEPTION_REGISTRATION_RECORD;
```

- Next: Points to the previous SEH record, forming a linked list.
- Handler: Points to the exception handler function.

### Storage in Stack (SEH Chain Example)

When an exception occurs, Windows follows the linked list stored in the stack:

```c
Stack Memory Layout:
+------------------------+
| SEH Handler 1         | --> Points to Handler Function A
| Next -> SEH Handler 2 | --> Points to Next SEH Record
+------------------------+
| SEH Handler 2         | --> Points to Handler Function B
| Next -> SEH Handler 3 | --> Points to Next SEH Record
+------------------------+
| SEH Handler 3 (Last)  | --> Points to OS default exception handler
| Next -> NULL          |
+------------------------+
```

- The SEH chain is traversed from the most recent record (top of stack) to the oldest.
- If no handler resolves the exception, Windows calls the default unhandled exception handler (e.g., crash dump or termination).

### And what about the TEB?

The Thread Environment Block (TEB) is a structure in Windows that stores per-thread information, such as the thread's stack base, exception handling chain, and various internal states. It is part of the Thread Information Block (TIB) and is accessed via the FS segment register on x86 or the GS segment register on x64.

- On x86 (32-bit): The TEB is located at FS:[0].
- On x64 (64-bit): The TEB is located at GS:[0].

### Structure of TEB

The TEB is a complex structure, but here are some key fields:

```c
typedef struct _TEB {
    PVOID ExceptionList;   // Pointer to SEH chain (FS:[0] in x86)
    PVOID StackBase;       // Base of the thread stack
    PVOID StackLimit;      // Stack limit
    PVOID ThreadLocalStoragePointer; // Pointer to TLS slots
    DWORD LastErrorValue;  // Stores last error (GetLastError)
    DWORD ThreadId;        // Unique thread ID
    // ... many more fields
} TEB, *PTEB;
```

### Examining the TEB with WinDbg

We start dumping the TEB structure:

![imagen](https://github.com/user-attachments/assets/d97bc5d0-65c5-4ff4-a116-950e3cb69a58)

We can see at the start NT_TIB (Native Thread Information Block), which is a Windows structure that stores low-level thread-specific data, including the Structured Exception Handling (SEH) chain, stack boundaries, and the Thread Local Storage (TLS) pointer. It is part of the Thread Environment Block (TEB) and is located at the beginning of the TEB structure.

![imagen](https://github.com/user-attachments/assets/033fae63-74bb-4fc3-9ccc-90634be8bb7e)

The exception_registration_record structure contains two members:

![imagen](https://github.com/user-attachments/assets/53aaaf53-861c-424f-b63c-a5d276c083ad)

The Next member acts as a link between _EXCEPTION_REGISTRATION_RECORD structures in
the singly-linked list. On another hand, the handler is a function pointer that gets called when an exception occurs.

The Handler is a function pointer with the following signature:

```c
typedef EXCEPTION_DISPOSITION (*PEXCEPTION_HANDLER)(
    struct _EXCEPTION_RECORD *ExceptionRecord,
    void *EstablisherFrame,
    struct _CONTEXT *ContextRecord,
    void *DispatcherContext
);
```

## How can I exploit it?
