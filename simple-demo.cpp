// Minimal version, without error checking, assume everything works

#include <iostream>
#include <iomanip>
#include <windows.h>
#include <bcrypt.h>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")

void test(const void* mem_addr, const char* symbol, const char* dll_name)
{
    char mem_name[2048] = { 0 };
    HMODULE mem_mod = nullptr;
    HMODULE dll_mod = nullptr;
    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, dll_name, &dll_mod);
    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT | GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, LPCSTR(mem_addr), &mem_mod);
    GetModuleFileNameA(mem_mod, mem_name, DWORD(ARRAYSIZE(mem_name)));
    const void* dll_addr = GetProcAddress(dll_mod, symbol);
    std::cout << symbol << " at " << std::hex << std::setw(8) << uintptr_t(mem_addr) << ", linked from " << mem_name << std::endl;
    std::cout << symbol << " at " << std::hex << std::setw(8) << uintptr_t(dll_addr) << ", loaded from " << dll_name << std::endl;
}

int main(int argc, char* argv[])
{
    test(BCryptEncrypt, "BCryptEncrypt", "bcrypt.dll");
    test(CertOpenStore, "CertOpenStore", "crypt32.dll");
}
