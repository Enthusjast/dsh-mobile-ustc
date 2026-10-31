/* Actual file-object policy fixture; no test command enters the production helper. */
#define wmain dsh_dpapi_main
#include "dpapi-helper.c"
#undef wmain
#include <sddl.h>
#include <stdio.h>

static BOOL dsh_fixture_set_acl(wchar_t *path, PSID user, const wchar_t *extra, PSECURITY_DESCRIPTOR *saved) {
    wchar_t *sid = NULL;
    wchar_t text[1024];
    PSECURITY_DESCRIPTOR descriptor = NULL;
    PACL acl = NULL;
    BOOL present = FALSE, defaulted = FALSE, success = FALSE;
    if (*saved == NULL && GetNamedSecurityInfoW(path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, NULL, NULL, saved) != ERROR_SUCCESS) goto done;
    if (!ConvertSidToStringSidW(user, &sid)) goto done;
    if (_snwprintf(text, 1024, L"D:P(A;;FA;;;%ls)(A;;FA;;;SY)%ls", sid, extra) < 0) goto done;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(text, SDDL_REVISION_1, &descriptor, NULL) ||
        !GetSecurityDescriptorDacl(descriptor, &present, &acl, &defaulted) || !present || acl == NULL) goto done;
    success = SetNamedSecurityInfoW(path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                                   NULL, NULL, acl, NULL) == ERROR_SUCCESS;
done:
    if (descriptor != NULL) LocalFree(descriptor);
    if (sid != NULL) LocalFree(sid);
    SecureZeroMemory(text, sizeof(text));
    return success;
}

/* Distinguish an emulator that drops a fine-grained ACE from a validator bug. */
static int dsh_fixture_write_dac_readback(PSECURITY_DESCRIPTOR descriptor) {
    PACL acl = NULL;
    BOOL present = FALSE, defaulted = FALSE;
    DWORD index;
    if (!GetSecurityDescriptorDacl(descriptor, &present, &acl, &defaulted) || !present || acl == NULL || !IsValidAcl(acl)) return -1;
    for (index = 0; index < acl->AceCount; index++) {
        ACE_HEADER *header = NULL;
        ACCESS_ALLOWED_ACE *allow;
        if (!GetAce(acl, index, (void **)&header) || header == NULL) return -1;
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE) continue;
        allow = (ACCESS_ALLOWED_ACE *)header;
        if (header->AceSize < offsetof(ACCESS_ALLOWED_ACE, SidStart) + 8u ||
            *((BYTE *)&allow->SidStart + 1) > SID_MAX_SUB_AUTHORITIES ||
            8u + 4u * *((BYTE *)&allow->SidStart + 1) > header->AceSize - offsetof(ACCESS_ALLOWED_ACE, SidStart) ||
            !IsValidSid((PSID)&allow->SidStart)) return -1;
        if (IsWellKnownSid((PSID)&allow->SidStart, WinBuiltinUsersSid) && (allow->Mask & WRITE_DAC) != 0) return 1;
    }
    return 0;
}

int wmain(int argc, wchar_t **argv) {
    HANDLE token = NULL, checked = INVALID_HANDLE_VALUE, writer = INVALID_HANDLE_VALUE;
    TOKEN_USER *user = NULL;
    PSECURITY_DESCRIPTOR saved = NULL;
    PACL original_acl = NULL;
    BOOL present = FALSE, defaulted = FALSE;
    DWORD needed = 0, allocated = 0, stage = 0;
    wchar_t hardlink[32768];
    BOOL link_created = FALSE, write_dac_unverified = FALSE;
    int result = 1;
    if (argc != 2 || wcslen(argv[1]) > 32000u) goto done;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) goto done;
    if (GetTokenInformation(token, TokenUser, NULL, 0, &needed) || GetLastError() != ERROR_INSUFFICIENT_BUFFER || needed < sizeof(TOKEN_USER) || needed > 65536u) goto done;
    allocated = needed;
    user = (TOKEN_USER *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, allocated);
    if (user == NULL || !GetTokenInformation(token, TokenUser, user, allocated, &needed) || dsh_service_sid(user->User.Sid)) goto done;
    stage++;
    checked = dsh_open_helper_component(argv[1], FALSE, user->User.Sid);
    if (checked == INVALID_HANDLE_VALUE) goto done;
    stage++;
    writer = CreateFileW(argv[1], GENERIC_WRITE | DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
    if (writer != INVALID_HANDLE_VALUE || GetLastError() != ERROR_SHARING_VIOLATION) goto done;
    CloseHandle(checked); checked = INVALID_HANDLE_VALUE;
    stage++;
    writer = CreateFileW(argv[1], GENERIC_WRITE | DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
    if (writer == INVALID_HANDLE_VALUE) goto done;
    CloseHandle(writer); writer = INVALID_HANDLE_VALUE;
    stage++;
    if (!dsh_fixture_set_acl(argv[1], user->User.Sid, L"(A;;GW;;;WD)", &saved)) goto done;
    stage++;
    checked = dsh_open_helper_component(argv[1], FALSE, user->User.Sid);
    if (checked != INVALID_HANDLE_VALUE) goto done;
    stage++;
    if (!dsh_fixture_set_acl(argv[1], user->User.Sid, L"(A;;WD;;;BU)", &saved)) goto done;
    stage++;
    checked = dsh_open_helper_component(argv[1], FALSE, user->User.Sid);
    if (checked != INVALID_HANDLE_VALUE) {
        PSECURITY_DESCRIPTOR actual = NULL;
        int retained = -1;
        if (GetNamedSecurityInfoW(argv[1], SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, NULL, NULL, NULL, NULL, &actual) == ERROR_SUCCESS)
            retained = dsh_fixture_write_dac_readback(actual);
        if (actual != NULL) LocalFree(actual);
        if (retained != 0) goto done;
        write_dac_unverified = TRUE;
        CloseHandle(checked); checked = INVALID_HANDLE_VALUE;
    }
    stage++;
    if (!dsh_fixture_set_acl(argv[1], user->User.Sid, L"(A;;GRGX;;;WD)", &saved)) goto done;
    stage++;
    checked = dsh_open_helper_component(argv[1], FALSE, user->User.Sid);
    if (checked == INVALID_HANDLE_VALUE) goto done;
    CloseHandle(checked); checked = INVALID_HANDLE_VALUE;
    stage++;
    if (_snwprintf(hardlink, 32768, L"%ls.extra-link", argv[1]) < 0 || !CreateHardLinkW(hardlink, argv[1], NULL)) goto done;
    link_created = TRUE;
    stage++;
    checked = dsh_open_helper_component(argv[1], FALSE, user->User.Sid);
    if (checked != INVALID_HANDLE_VALUE) goto done;
    if (!DeleteFileW(hardlink)) goto done;
    link_created = FALSE;
    result = 0;
done:
    if (result != 0) fwprintf(stderr, L"ACL fixture failure stage=%lu code=%lu\n", stage, GetLastError());
    if (writer != INVALID_HANDLE_VALUE) CloseHandle(writer);
    if (checked != INVALID_HANDLE_VALUE) CloseHandle(checked);
    if (link_created) DeleteFileW(hardlink);
    if (saved != NULL) {
        SECURITY_DESCRIPTOR_CONTROL control;
        DWORD revision = 0;
        if (!GetSecurityDescriptorControl(saved, &control, &revision) || !GetSecurityDescriptorDacl(saved, &present, &original_acl, &defaulted) || !present ||
            SetNamedSecurityInfoW(argv[1], SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | ((control & SE_DACL_PROTECTED) ? PROTECTED_DACL_SECURITY_INFORMATION : UNPROTECTED_DACL_SECURITY_INFORMATION),
                                  NULL, NULL, original_acl, NULL) != ERROR_SUCCESS) result = 1;
        LocalFree(saved);
    }
    if (user != NULL) { SecureZeroMemory(user, allocated); HeapFree(GetProcessHeap(), 0, user); }
    if (token != NULL) CloseHandle(token);
    if (result == 0 && write_dac_unverified) {
        static const BYTE marker[] = "ACL_FIXTURE_WRITE_DAC_NOT_RETAINED\n";
        if (!dsh_write_all(GetStdHandle(STD_OUTPUT_HANDLE), marker, (DWORD)sizeof(marker) - 1u)) result = 1;
    }
    SecureZeroMemory(hardlink, sizeof(hardlink));
    return result;
}
