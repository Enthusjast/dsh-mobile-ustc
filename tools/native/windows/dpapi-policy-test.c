/* Standalone native policy test. No test mode or identity override is compiled
 * into the production helper. */
#define wmain dsh_dpapi_main
#include "dpapi-helper.c"
#undef wmain
#include <sddl.h>

static BOOL dsh_policy_descriptor(const wchar_t *text, PSID user, BOOL expected) {
    PSECURITY_DESCRIPTOR descriptor = NULL;
    BOOL actual;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(text, SDDL_REVISION_1, &descriptor, NULL)) return FALSE;
    actual = dsh_safe_helper_descriptor(descriptor, user);
    LocalFree(descriptor);
    return actual == expected;
}

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
    if (!dsh_policy_descriptor(L"O:S-1-5-21-1-2-3-1001D:P(A;;FA;;;S-1-5-21-1-2-3-1001)(A;;FA;;;SY)(A;;GRGX;;;WD)", regular, TRUE) ||
        !dsh_policy_descriptor(L"O:SYD:P(A;;FA;;;SY)(A;;GR;;;WD)", regular, TRUE) ||
        !dsh_policy_descriptor(L"O:BAD:P(A;;FA;;;BA)(A;;GRGX;;;BU)", regular, TRUE) ||
        !dsh_policy_descriptor(L"O:WDD:P(A;;FA;;;S-1-5-21-1-2-3-1001)", regular, FALSE) ||
        !dsh_policy_descriptor(L"O:S-1-5-21-1-2-3-1001D:P(A;;GW;;;WD)", regular, FALSE) ||
        !dsh_policy_descriptor(L"O:S-1-5-21-1-2-3-1001D:P(A;;WD;;;BU)", regular, FALSE) ||
        !dsh_policy_descriptor(L"O:S-1-5-21-1-2-3-1001D:P(A;;0x00000040;;;WD)", regular, FALSE) ||
        !dsh_policy_descriptor(L"O:S-1-5-21-1-2-3-1001D:P(D;;GW;;;WD)(A;;GW;;;WD)", regular, FALSE)) goto done;
    {
        SECURITY_DESCRIPTOR descriptor;
        if (!InitializeSecurityDescriptor(&descriptor, SECURITY_DESCRIPTOR_REVISION) ||
            !SetSecurityDescriptorOwner(&descriptor, regular, FALSE) ||
            !SetSecurityDescriptorDacl(&descriptor, TRUE, NULL, FALSE) || dsh_safe_helper_descriptor(&descriptor, regular)) goto done;
    }
    if (!dsh_safe_helper_attributes(FILE_ATTRIBUTE_NORMAL, 1, FALSE) ||
        !dsh_safe_helper_attributes(FILE_ATTRIBUTE_DIRECTORY, 1, TRUE) ||
        dsh_safe_helper_attributes(FILE_ATTRIBUTE_NORMAL, 2, FALSE) ||
        dsh_safe_helper_attributes(FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_REPARSE_POINT, 1, FALSE) ||
        dsh_safe_helper_attributes(FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT, 1, TRUE) ||
        dsh_safe_helper_attributes(FILE_ATTRIBUTE_DIRECTORY, 1, FALSE)) goto done;
    result = 0;
done:
    if (regular != NULL) LocalFree(regular);
    SecureZeroMemory(buffer, sizeof(buffer));
    return result;
}
