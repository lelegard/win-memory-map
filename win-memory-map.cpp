//----------------------------------------------------------------------------
// win-memory-map - Copyright (c) 2025, Thierry Lelegard
// BSD 2-Clause License, see LICENSE file.
//----------------------------------------------------------------------------

#define SECURITY_WIN32 1           // used by sspi.h (versus SECURITY_KERNEL)
#define SCHANNEL_USE_BLACKLISTS 1  // for SCH_CREDENTIALS

#include <iostream>
#include <utility>
#include <cassert>
#include <vector>
#include <list>
#include <string>
#include <array>
#include <cwctype>
#include <iomanip>
#include <algorithm>
#include <windows.h>
#include <strsafe.h>
#include <psapi.h>
#include <wininet.h>
#include <subauth.h>
#include <sspi.h>
#include <schannel.h>
#include <bcrypt.h>

// Remove silly macros from VC headers.
#if defined(min)
    #undef min
#endif
#if defined(max)
    #undef max
#endif

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "bcrypt.lib")


//----------------------------------------------------------------------------
// Printf-like format with wide characters.
//----------------------------------------------------------------------------

template <class... Args>
std::wstring Format(const wchar_t* fmt, Args&&... args)
{
    std::array<wchar_t, 2048> buffer;
    StringCbPrintfW(buffer.data(), buffer.size() * sizeof(buffer[0]), fmt, std::forward<Args>(args)...);
    buffer[buffer.size() - 1] = 0;
    return std::wstring(buffer.data());
}


//----------------------------------------------------------------------------
// Get all modules in the process.
//----------------------------------------------------------------------------

void WinGetProcessModules(std::vector<HMODULE>& mods)
{
    DWORD retsize = 0;
    mods.resize(512);
    if (EnumProcessModules(GetCurrentProcess(), mods.data(), DWORD(mods.size() * sizeof(mods[0])), &retsize)) {
        mods.resize(std::min<size_t>(mods.size(), retsize / sizeof(mods[0])));
    }
    else {
        mods.clear();
    }
}


//----------------------------------------------------------------------------
// Get system error message.
//----------------------------------------------------------------------------

std::wstring WinMessage(DWORD code = GetLastError())
{
    std::array<wchar_t, 2048> message;
    DWORD length = FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM, nullptr, code, 0, message.data(), DWORD(message.size()), nullptr);

    // If message is empty, try all loaded modules in the process.
    if (length <= 0) {
        // Get a list of handles for all loaded modules. These handles shall not be closed here.
        std::vector<HMODULE> hmods;
        WinGetProcessModules(hmods);
        // Try all all modules, one by one, until a non-empty message is returned.
        for (size_t i = 0; length <= 0 && i < hmods.size(); ++i) {
            length = FormatMessageW(FORMAT_MESSAGE_FROM_HMODULE, hmods[i], code, 0, message.data(), DWORD(message.size()), nullptr);
        }
    }

    return length > 0 ? std::wstring(message.data()) : Format(L"Error code: 0x%08X", code);
}


//----------------------------------------------------------------------------
// Get a module file name.
//----------------------------------------------------------------------------

std::wstring WinModuleName(HMODULE hmod)
{
    if (hmod == nullptr || hmod == INVALID_HANDLE_VALUE) {
        return std::wstring();
    }
    else {
        std::array<wchar_t, 2048> path;
        const DWORD len = GetModuleFileNameW(hmod, path.data(), DWORD(path.size()));
        return len > 0 ? std::wstring(path.data(), size_t(len)) : WinMessage();
    }
}


//----------------------------------------------------------------------------
// Get the handle of the module containing an address.
//----------------------------------------------------------------------------

HMODULE WinModuleFromAddress(const void* addr)
{
    HMODULE hmod = nullptr;
    static constexpr DWORD flags = GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT;
    return GetModuleHandleExW(flags, reinterpret_cast<LPCWSTR>(addr), &hmod) ? hmod : nullptr;
}


//----------------------------------------------------------------------------
// Application entry point.
//----------------------------------------------------------------------------

int wmain(int argc, wchar_t* argv[])
{
    // Build list of modules.
    std::vector<HMODULE> hmods;
    WinGetProcessModules(hmods);
    std::list<std::wstring> lines;
    for (auto h : hmods) {
        MODULEINFO info = { nullptr, 0, nullptr };
        GetModuleInformation(GetCurrentProcess(), h, &info, DWORD(sizeof(info)));
        lines.push_back(Format(L"0x%08X-0x%08X : ", uintptr_t(info.lpBaseOfDll), uintptr_t(info.lpBaseOfDll) + info.SizeOfImage - 1) + WinModuleName(h));
    }
    lines.sort();

    std::wcout << L"====== Modules (" << hmods.size() << L") ======" << std::endl;
    for (const auto& l : lines) {
        std::wcout << l << std::endl;
    }

    // Build list of symbols.
    lines.clear();
#define _ADD(symbol) lines.push_back(Format(L"0x%08X : %s -> ", uintptr_t(symbol), L#symbol) + WinModuleName(WinModuleFromAddress(symbol)))
    _ADD(wmain);
    _ADD(GetCurrentProcess);
    _ADD(InternetOpenW);
    _ADD(CertOpenStore);
    _ADD(InitializeSecurityContextW);
    _ADD(ApplyControlToken);
    _ADD(EncryptMessage);
    _ADD(BCryptImportKey);
    _ADD(BCryptEncrypt);
#undef _ADD
    lines.sort();

    std::wcout << std::endl << L"====== Some symbols ======" << std::endl;
    for (const auto& l : lines) {
        std::wcout << l << std::endl;
    }
    std::wcout << std::endl;
}
