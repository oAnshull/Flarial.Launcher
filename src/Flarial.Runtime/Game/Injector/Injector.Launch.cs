using System.Collections.Generic;
using Flarial.Runtime.Core;
using Flarial.Runtime.Services;
using Flarial.Runtime.Unmanaged;
using Windows.Win32.Foundation;
using static Windows.Win32.PInvoke;
using static Windows.Win32.Foundation.WAIT_EVENT;
using static Windows.Win32.System.Memory.PAGE_PROTECTION_FLAGS;
using static Windows.Win32.System.Memory.VIRTUAL_ALLOCATION_TYPE;
using static Windows.Win32.System.Memory.VIRTUAL_FREE_TYPE;
using static Windows.Win32.System.Threading.PROCESS_ACCESS_RIGHTS;
using static Windows.Win32.System.Threading.PROCESS_CREATION_FLAGS;

namespace Flarial.Runtime.Game;

partial class Injector
{
    public unsafe static bool Launch(ModificationLibrary library)
    {
        var path = library.AsPath();
        Dictionary<string, string?> tokenData = new() { ["access_token"] = FlarialClient.AccessToken };
        var description = JsonService.Default.Write(tokenData);

        if (Minecraft.Launch() is not { } processId)
            return false;

        if (PROCESS_ALL_ACCESS.Open(processId) is not { } process)
            return false;

        using (process)
        {
            HANDLE thread = new();
            void* parameter = null;
            var threadStarted = false;
            var threadCompleted = false;
            try
            {
                var size = (nuint)(path.Length + 1) * sizeof(char);

                parameter = VirtualAllocEx(process, null, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (parameter is null)
                    return false;

                nuint bytesWritten = 0;
                fixed (char* buffer = path)
                    if (!WriteProcessMemory(process, parameter, buffer, size, &bytesWritten) || bytesWritten != size)
                        return false;

                thread = CreateRemoteThread(process, null, 0, s_address, parameter, (uint)CREATE_SUSPENDED, null);
                if (thread.IsNull)
                    return false;

                fixed (char* buffer = description)
                    if (SetThreadDescription(thread, buffer).Value < 0)
                        return false;

                if (ResumeThread(thread) == uint.MaxValue)
                    return false;

                threadStarted = true;
                if (WaitForSingleObject(thread, INFINITE) is not WAIT_OBJECT_0)
                    return false;

                threadCompleted = true;
                uint exitCode = 0;
                return GetExitCodeThread(thread, &exitCode) && exitCode != 0;
            }
            finally
            {
                if (!thread.IsNull)
                {
                    if (!threadStarted && !threadCompleted)
                    {
                        if (TerminateThread(thread, 0))
                            threadCompleted = WaitForSingleObject(thread, INFINITE) is WAIT_OBJECT_0;
                        else
                            threadCompleted = WaitForSingleObject(thread, 0) is WAIT_OBJECT_0;
                    }

                    CloseHandle(thread);
                }

                if (parameter is not null && (thread.IsNull || threadCompleted))
                    VirtualFreeEx(process, parameter, 0, MEM_RELEASE);
            }
        }
    }
}
