/* Scenario A fixture: a plain AMD64 EXE with no exports and no cooperative handshake.
 *
 * `analyze breakpoint session --launch-suspended` selects the PE
 * AddressOfEntryPoint by default and requires no PE export, so this target only
 * has to be a normal AMD64 image that reaches its entry point.  The fixture
 * writes one marker file so the driver can prove the process really executed
 * past the entry breakpoint and exited on its own.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

int main(void)
{
    /* The entry breakpoint is armed before the initial suspend is released, so
     * this write can only happen after the driver continued the real stop.
     * The path comes from the environment so the driver controls the exact
     * cleanable location instead of the fixture choosing one. */
    char path[MAX_PATH];
    DWORD length = GetEnvironmentVariableA("CORE_HANDOFF_TARGET_MARKER", path, (DWORD)sizeof(path));
    if (length > 0 && length < sizeof(path)) {
        FILE* stream = NULL;
        fopen_s(&stream, path, "w");
        if (stream) {
            fputs("executed-after-entry-stop\n", stream);
            fclose(stream);
        }
    }
    /* Stay alive briefly so the driver can observe the detached target after
     * the CLI reports a clean close; the exit code stays 0. */
    Sleep(1500);
    return 0;
}
