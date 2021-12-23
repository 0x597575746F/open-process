## open-process
A DLL that replaces OpenProcess with a function that steals handles from CSRSS.exe

---

### How to use

Just inject the output DLL into your process. Any injection method will work (LoadLib, MMap, LdrLoad, etc)

### Dependencies

MS Detours - for detouring kernel32's open-process into our open-process.
https://github.com/microsoft/Detours