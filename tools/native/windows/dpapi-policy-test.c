/* Standalone native policy test. No test mode or identity override is compiled
 * into the production helper. */
#define wmain dsh_dpapi_main
#include "dpapi-helper.c"
#undef wmain
#include <sddl.h>

int wmain(int argc, wchar_t **argv) {
    BYTE buffer[SECURITY_MAX_SID_SIZE];
    WELL_KNOWN_SID_TYPE services[] = {WinLocalSystemSid, WinLocalServiceSid, WinNetworkServiceSid};
    PSID regular = NULL;
    size_t index;
    int result = 1;
    (void)argc; (void)argv;
    if ((dsh_protection_flags() & CRYPTPROTECT_LOCAL_MACHINE) != 0 ||
        (dsh_protection_flags() & CRYPTPROTECT_UI_FORBIDDEN) == 0 || !dsh_service_sid(NULL)) goto done;
    for (index = 0; index < sizeof(services) / sizeof(services[0]); index++) {
        DWORD size = sizeof(buffer);
        if (!CreateWellKnownSid(services[index], NULL, buffer, &size) || !dsh_service_sid(buffer)) goto done;
    }
    if (!ConvertStringSidToSidW(L"S-1-5-21-1-2-3-1001", &regular) || dsh_service_sid(regular)) goto done;
    result = 0;
done:
    if (regular != NULL) LocalFree(regular);
    SecureZeroMemory(buffer, sizeof(buffer));
    return result;
}
