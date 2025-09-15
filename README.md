## Windows process memory mapping

This sample program displays the memory mapping of modules in the process.

The address of some symbols are displayed, along with the module into which
there are defined.

Problem: Some symbols from BCrypt or SSPI (SChannel) libraries have their
address in the main executable when in debug mode, but not in release mode.
Why?

Sample output in release mode:
~~~
====== Modules (15) ======
0x545F0000-0x545FBFFF : D:\win-memory-map\build\Release-x64\win-memory-map.exe
0x86260000-0x862E8FFF : C:\WINDOWS\SYSTEM32\MSVCP140.dll
0xAFD70000-0xAFD8DFFF : C:\WINDOWS\SYSTEM32\VCRUNTIME140.dll
0xAFE50000-0xAFE5BFFF : C:\WINDOWS\SYSTEM32\VCRUNTIME140_1.dll
0xB7190000-0xB7418FFF : C:\WINDOWS\SYSTEM32\WININET.dll
0xC21D0000-0xC226DFFF : C:\WINDOWS\SYSTEM32\apphelp.dll
0xC2ED0000-0xC2EDCFFF : C:\WINDOWS\SYSTEM32\Secur32.dll
0xC51D0000-0xC5218FFF : C:\WINDOWS\SYSTEM32\SSPICLI.DLL
0xC6040000-0xC6065FFF : C:\WINDOWS\SYSTEM32\bcrypt.dll
0xC6550000-0xC669AFFF : C:\WINDOWS\System32\ucrtbase.dll
0xC6780000-0xC6B72FFF : C:\WINDOWS\System32\KERNELBASE.dll
0xC6B80000-0xC6CF6FFF : C:\WINDOWS\System32\CRYPT32.dll
0xC7AB0000-0xC7B78FFF : C:\WINDOWS\System32\KERNEL32.DLL
0xC7ED0000-0xC7FE7FFF : C:\WINDOWS\System32\RPCRT4.dll
0xC8FC0000-0xC9228FFF : C:\WINDOWS\SYSTEM32\ntdll.dll

====== Some symbols ======
0x545F1A90 : wmain -> D:\win-memory-map\build\Release-x64\win-memory-map.exe
0xB71C0C70 : InternetOpenW -> C:\WINDOWS\SYSTEM32\WININET.dll
0xC51D1C00 : ApplyControlToken -> C:\WINDOWS\SYSTEM32\SSPICLI.DLL
0xC51D1FE0 : InitializeSecurityContextW -> C:\WINDOWS\SYSTEM32\SSPICLI.DLL
0xC51D2D70 : EncryptMessage -> C:\WINDOWS\SYSTEM32\SSPICLI.DLL
0xC604B200 : BCryptEncrypt -> C:\WINDOWS\SYSTEM32\bcrypt.dll
0xC604F590 : BCryptImportKey -> C:\WINDOWS\SYSTEM32\bcrypt.dll
0xC6BDC5F0 : CertOpenStore -> C:\WINDOWS\System32\CRYPT32.dll
0xC7AD4970 : GetCurrentProcess -> C:\WINDOWS\System32\KERNEL32.DLL
~~~

Sample output in debug mode:
~~~
====== Modules (15) ======
0x282B0000-0x284B3FFF : C:\WINDOWS\SYSTEM32\ucrtbased.dll
0x69670000-0x69750FFF : C:\WINDOWS\SYSTEM32\MSVCP140D.dll
0x848D0000-0x84909FFF : D:\test\win-memory-map\build\Debug-x64\win-memory-map.exe
0xB7190000-0xB7418FFF : C:\WINDOWS\SYSTEM32\WININET.dll
0xB7BA0000-0xB7BCFFFF : C:\WINDOWS\SYSTEM32\VCRUNTIME140D.dll
0xC0170000-0xC017EFFF : C:\WINDOWS\SYSTEM32\VCRUNTIME140_1D.dll
0xC2ED0000-0xC2EDCFFF : C:\WINDOWS\SYSTEM32\Secur32.dll
0xC51D0000-0xC5218FFF : C:\WINDOWS\SYSTEM32\SSPICLI.DLL
0xC6040000-0xC6065FFF : C:\WINDOWS\SYSTEM32\bcrypt.dll
0xC6550000-0xC669AFFF : C:\WINDOWS\System32\ucrtbase.dll
0xC6780000-0xC6B72FFF : C:\WINDOWS\System32\KERNELBASE.dll
0xC6B80000-0xC6CF6FFF : C:\WINDOWS\System32\CRYPT32.dll
0xC7AB0000-0xC7B78FFF : C:\WINDOWS\System32\KERNEL32.DLL
0xC7ED0000-0xC7FE7FFF : C:\WINDOWS\System32\RPCRT4.dll
0xC8FC0000-0xC9228FFF : C:\WINDOWS\SYSTEM32\ntdll.dll

====== Some symbols ======
0x848E1055 : wmain -> D:\test\win-memory-map\build\Debug-x64\win-memory-map.exe
0x848E17A3 : EncryptMessage -> D:\test\win-memory-map\build\Debug-x64\win-memory-map.exe
0x848E17EE : BCryptEncrypt -> D:\test\win-memory-map\build\Debug-x64\win-memory-map.exe
0x848E1947 : BCryptImportKey -> D:\test\win-memory-map\build\Debug-x64\win-memory-map.exe
0xB71C0C70 : InternetOpenW -> C:\WINDOWS\SYSTEM32\WININET.dll
0xC51D1C00 : ApplyControlToken -> C:\WINDOWS\SYSTEM32\SSPICLI.DLL
0xC51D1FE0 : InitializeSecurityContextW -> C:\WINDOWS\SYSTEM32\SSPICLI.DLL
0xC6BDC5F0 : CertOpenStore -> C:\WINDOWS\System32\CRYPT32.dll
0xC7AD4970 : GetCurrentProcess -> C:\WINDOWS\System32\KERNEL32.DLL
~~~

Because of ASLR, the addresses are different in each execution. However,
the symbols are always located in the same module.

### Simple demo

The `simple-demo` is a simplified version with minimal code and no error checks.
It exhibits the difference between two symbols: `BCryptEncrypt` from `bcrypt.dll`
and `CertOpenStore` from `crypt32.dll`.

Each symbol is first used as a direct reference in the code. Its address is 
displayed, with the name of the module at that address. Then, the symbol is
explicitly loaded, as a string, from the expected DLL and the returned
address is displayed.

Release mode:
~~~
BCryptEncrypt at 7ff82d9fb200, linked from C:\WINDOWS\SYSTEM32\bcrypt.dll
BCryptEncrypt at 7ff82d9fb200, loaded from bcrypt.dll
CertOpenStore at 7ff82ddec5f0, linked from C:\WINDOWS\System32\CRYPT32.dll
CertOpenStore at 7ff82ddec5f0, loaded from crypt32.dll
~~~

In release mode, for the two symbols, the symbol which was linked from the source
code and the address which was explicitly loaded from the DLL are identical.

Debug mode:
~~~
BCryptEncrypt at 7ff6ee6813d9, linked from D:\shared\win-memory-map\build\Debug-x64\simple-demo.exe
BCryptEncrypt at 7ff82d9fb200, loaded from bcrypt.dll
CertOpenStore at 7ff82ddec5f0, linked from C:\WINDOWS\System32\CRYPT32.dll
CertOpenStore at 7ff82ddec5f0, loaded from crypt32.dll
~~~

In debug mode, the symbol `BCryptEncrypt` behaves differently. The symbol which
is linked from the source code is located inside the main executable. In practice,
this is true for all symbols in `bcrypt.dll`.

So, the obvious idea is that the debug version was linked against a static library
version of `bcrypt.lib` while the release version was linked against the dynamic
library. And this is true for `bcrypt.dll`, not `crypt32.dll`, not any other
library.

However, there is only one version of `bcrypt.lib` for x64 on the disk,
in `C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\um\x64\bcrypt.lib`.
Using command `dumpbin`, there is no specific static code.

Looking at the declarations in the various system headers, we see that
all functions, from all system libraries, have a directive `__declspec(dllimport)`,
except all functions from `bcrypt.h` which do not have this directive.

Questions:
- How can the link operation succeed without `__declspec(dllimport)`?
- Why does the release version link against the DLL while the debug version
  links against some static code?
- Where does this static code come from, since the import library `bcrypt.dll`
  does not contain any code?
