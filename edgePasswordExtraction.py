import ctypes
import ctypes.wintypes as wintypes
import psutil
import win32api
import win32con
import win32process
import win32security

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

MEM_COMMIT = 0x1000
PAGE_READWRITE = 0x04

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", wintypes.LPVOID),
        ("AllocationBase", wintypes.LPVOID),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


VirtualQueryEx = kernel32.VirtualQueryEx
ReadProcessMemory = kernel32.ReadProcessMemory
OpenProcess = kernel32.OpenProcess
CloseHandle = kernel32.CloseHandle


def get_process_owner(pid):
    try:
        hproc = win32api.OpenProcess(
            win32con.PROCESS_QUERY_INFORMATION,
            False,
            pid
        )

        htok = win32security.OpenProcessToken(
            hproc,
            win32con.TOKEN_QUERY
        )

        sid, _ = win32security.GetTokenInformation(
            htok,
            win32security.TokenUser
        )

        name, domain, _ = win32security.LookupAccountSid(None, sid)

        return f"{domain}\\{name}"

    except Exception:
        return "UNKNOWN"


def scan_memory_regions(pid):
    handle = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        False,
        pid
    )

    if not handle:
        print(f"[-] Failed to open PID {pid}")
        return

    try:
        address = 0
        mbi = MEMORY_BASIC_INFORMATION()

        while VirtualQueryEx(
            handle,
            ctypes.c_void_p(address),
            ctypes.byref(mbi),
            ctypes.sizeof(mbi)
        ):

            readable = (
                mbi.State == MEM_COMMIT and
                mbi.Protect == PAGE_READWRITE
            )

            if readable:
                print(
                    f"[+] PID {pid} "
                    f"Region: 0x{address:016X} "
                    f"Size: {mbi.RegionSize}"
                )

                # SAFE EXAMPLE:
                # Read only first 256 bytes for benign inspection

                try:
                    buffer = ctypes.create_string_buffer(
                        min(mbi.RegionSize, 256)
                    )

                    bytes_read = ctypes.c_size_t()

                    success = ReadProcessMemory(
                        handle,
                        ctypes.c_void_p(address),
                        buffer,
                        len(buffer),
                        ctypes.byref(bytes_read)
                    )

                    if success:
                        data = buffer.raw[:bytes_read.value]

                        # Example benign analysis:
                        if b"https://" in data:
                            print("    Found URL marker")

                except Exception:
                    pass

            address += mbi.RegionSize

    finally:
        CloseHandle(handle)


def main():
    print("[+] Enumerating Edge processes\n")

    checked = set()

    for proc in psutil.process_iter(["pid", "name", "ppid"]):
        try:
            if proc.info["name"].lower() != "msedge.exe":
                continue

            pid = proc.info["pid"]
            ppid = proc.info["ppid"]

            # Skip child Edge processes
            try:
                parent = psutil.Process(ppid)

                if parent.name().lower() == "msedge.exe":
                    continue

            except Exception:
                pass

            owner = get_process_owner(pid)

            key = f"{owner}|{proc.info['name']}"

            if key in checked:
                continue

            checked.add(key)

            print(
                f"Scanning PID: {pid} "
                f"Name: {proc.info['name']} "
                f"Owner: {owner}"
            )

            scan_memory_regions(pid)

        except Exception as e:
            print(f"[-] Error: {e}")


if __name__ == "__main__":
    main()
