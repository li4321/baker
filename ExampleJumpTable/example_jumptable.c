#include <stdio.h>
#include <Windows.h>

//
// this example is CRTless
//

typedef int(__CRTDECL *_vsnprintf_t)(
    _Out_writes_opt_(_BufferCount) _Post_maybez_    const char*     buffer, 
    _In_                                            const size_t    bufsize, 
    _In_z_ _Printf_format_string_                   const char*     format, 
                                                    va_list         arglist
    );

_vsnprintf_t p_vsnprintf = NULL;

void load_functions() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    p_vsnprintf = GetProcAddress(ntdll, "_vsnprintf");
}

void crtless_printf(const char* format, ...) {
    char buffer[256];
    DWORD bytes_written;
    HANDLE h_stdout = GetStdHandle(STD_OUTPUT_HANDLE);

    if (h_stdout == INVALID_HANDLE_VALUE)
        return;
    
    va_list args;
    va_start(args, format);
    int len = p_vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    if (len < 0)
        return;

    WriteFile(h_stdout, buffer, len, &bytes_written, NULL);
}

/*
    switch case based jump tables
*/

char* serialize_0_9(int number) {
    switch (number)
    {
    case 0: return "zero";
    case 1: return "one";
    case 2: return "two";
    case 3: return "three";
    case 4: return "four";
    case 5: return "five";
    case 6: return "six";
    case 7: return "seven";
    case 8: return "eight";
    case 9: return "nine";
    default: return "invalid number (only numbers from 0-4 are allowed)";
    }
}

char* serialize_10_19(int number) {
    switch (number)
    {
    case 10: return "ten";
    case 11: return "eleven";
    case 12: return "twelve";
    case 13: return "thirteen";
    case 14: return "fourteen";
    case 15: return "fifthteen";
    case 16: return "sixteen";
    case 17: return "seventeen";
    case 18: return "eighteen";
    case 19: return "nineteen";
    default: return "invalid number (only numbers from 10-19 are allowed)";
    }
}

/*
    pointer based jump table
*/

typedef char* (*func_table_entry_t)();

char* func_20() { return "twenty"; }
char* func_21() { return "twenty_one"; }
char* func_22() { return "twenty_two"; }
char* func_23() { return "twenty_three"; }
char* func_24() { return "twenty_four"; }
char* func_25() { return "twenty_five"; }
char* func_26() { return "twenty_six"; }
char* func_27() { return "twenty_seven"; }
char* func_28() { return "twenty_eight"; }
char* func_29() { return "twenty_nine"; }

const func_table_entry_t func_table[] = {
    func_20,
    func_21,
    func_22,
    func_23,
    func_24,
    func_25,
    func_26,
    func_27,
    func_28,
    func_29
};

char* serialize_20_29(int number) {
    if (number < 20 || number > 29) {
        return "invalid number (only numbers from 20-29 are allowed)";
    }
    
    return func_table[number - 20]();
}


int jumptable_example_main() {
    load_functions();
    
    crtless_printf("0 - 9\n");
    for (int i = 0; i < 10; i++) {
        crtless_printf("%d --> %s\n", i, serialize_0_9(i));
    }

    for (int i = 10; i < 20; i++) {
        crtless_printf("%d --> %s\n", i, serialize_10_19(i));
    }

    for (int i = 20; i < 30; i++) {
        crtless_printf("%d --> %s\n", i, serialize_20_29(i));
    }

    while (TRUE) {
        // so the console does not close
        Sleep(5000);
    }
}