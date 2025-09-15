// Minimal version, without error checking

#include <iostream>
#include <windows.h>
#include <bcrypt.h>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")

void test(const char* name, const void* address)
{
    wchar_t path[2048] = { 0 };
    HMODULE hmod = nullptr;
    const DWORD flags = GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT;
    GetModuleHandleExW(flags, LPCWSTR(address), &hmod);
    GetModuleFileNameW(hmod, path, DWORD(ARRAYSIZE(path)));
    std::wcout << name << " in " << path << std::endl;
}

int wmain(int argc, wchar_t* argv[])
{
    test("BCryptEncrypt", BCryptEncrypt);
    test("CertOpenStore", CertOpenStore);
}
