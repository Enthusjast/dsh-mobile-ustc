#ifndef DSH_PRIVATE_HELPER_ACL_H
#define DSH_PRIVATE_HELPER_ACL_H
#include <aclapi.h>
#include <stddef.h>

#define DSH_HELPER_PATH_MAX 32768u
#define DSH_HELPER_DEPTH_MAX 128u

typedef struct {
    HANDLE handles[DSH_HELPER_DEPTH_MAX];
    DWORD count;
} DSH_HELPER_GUARD;

static BOOL dsh_trusted_sid(PSID sid, PSID user) {
    return sid != NULL && IsValidSid(sid) && (EqualSid(sid, user) ||
        IsWellKnownSid(sid, WinLocalSystemSid) || IsWellKnownSid(sid, WinBuiltinAdministratorsSid));
}

/* Read/execute grants are normal for an installed program. Reject any other
 * principal that can replace the image, its path, ACL or file attributes.
 * Denies do not excuse an unsafe allow; uncommon/object/callback ACEs fail closed. */
static BOOL dsh_safe_helper_descriptor(PSECURITY_DESCRIPTOR descriptor, PSID user) {
    PSID owner = NULL;
    PACL acl = NULL;
    BOOL present = FALSE, defaulted = FALSE;
    DWORD index;
    GENERIC_MAPPING mapping = {FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE, FILE_ALL_ACCESS};
    const DWORD dangerous = FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES |
        FILE_DELETE_CHILD | DELETE | WRITE_DAC | WRITE_OWNER;
    if (descriptor == NULL || !IsValidSecurityDescriptor(descriptor) || user == NULL || !IsValidSid(user) ||
        !GetSecurityDescriptorOwner(descriptor, &owner, &defaulted) || !dsh_trusted_sid(owner, user) ||
        !GetSecurityDescriptorDacl(descriptor, &present, &acl, &defaulted) || !present || acl == NULL || !IsValidAcl(acl)) return FALSE;
    for (index = 0; index < acl->AceCount; index++) {
        ACE_HEADER *header = NULL;
        ACCESS_ALLOWED_ACE *allow;
        DWORD rights;
        if (!GetAce(acl, index, (void **)&header) || header == NULL) return FALSE;
        if (header->AceType == ACCESS_DENIED_ACE_TYPE) continue;
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE || header->AceSize < sizeof(ACCESS_ALLOWED_ACE)) return FALSE;
        allow = (ACCESS_ALLOWED_ACE *)header;
        if (header->AceSize < offsetof(ACCESS_ALLOWED_ACE, SidStart) + 8u ||
            *((BYTE *)&allow->SidStart + 1) > SID_MAX_SUB_AUTHORITIES ||
            8u + 4u * *((BYTE *)&allow->SidStart + 1) > header->AceSize - offsetof(ACCESS_ALLOWED_ACE, SidStart) ||
            !IsValidSid((PSID)&allow->SidStart)) return FALSE;
        rights = allow->Mask;
        MapGenericMask(&rights, &mapping);
        if (!dsh_trusted_sid((PSID)&allow->SidStart, user) && (rights & dangerous) != 0) return FALSE;
    }
    return TRUE;
}

static BOOL dsh_safe_helper_attributes(DWORD attributes, DWORD links, BOOL directory) {
    return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0 &&
        (((attributes & FILE_ATTRIBUTE_DIRECTORY) != 0) == (directory != FALSE)) && (directory || links == 1);
}

static HANDLE dsh_open_helper_component(const wchar_t *path, BOOL directory, PSID user) {
    HANDLE file = INVALID_HANDLE_VALUE;
    PSECURITY_DESCRIPTOR descriptor = NULL;
    BY_HANDLE_FILE_INFORMATION information;
    BOOL safe = FALSE;
    file = CreateFileW(path, GENERIC_READ | READ_CONTROL | FILE_READ_ATTRIBUTES, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                       FILE_FLAG_OPEN_REPARSE_POINT | (directory ? FILE_FLAG_BACKUP_SEMANTICS : FILE_ATTRIBUTE_NORMAL), NULL);
    if (file == INVALID_HANDLE_VALUE) goto done;
    if (!GetFileInformationByHandle(file, &information) ||
        !dsh_safe_helper_attributes(information.dwFileAttributes, information.nNumberOfLinks, directory)) goto done;
    if (GetSecurityInfo(file, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                        NULL, NULL, NULL, NULL, &descriptor) != ERROR_SUCCESS || !dsh_safe_helper_descriptor(descriptor, user)) goto done;
    safe = TRUE;
done:
    if (descriptor != NULL) LocalFree(descriptor);
    if (!safe && file != INVALID_HANDLE_VALUE) { CloseHandle(file); file = INVALID_HANDLE_VALUE; }
    return file;
}

static void dsh_close_helper_guard(DSH_HELPER_GUARD *guard) {
    while (guard->count != 0) CloseHandle(guard->handles[--guard->count]);
}

static BOOL dsh_lock_helper_image(DSH_HELPER_GUARD *guard) {
    HANDLE token = NULL;
    TOKEN_USER *user = NULL;
    DWORD needed = 0, allocated = 0, length;
    wchar_t *path = NULL;
    BOOL directory = FALSE, safe = FALSE;
    guard->count = 0;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) goto done;
    if (GetTokenInformation(token, TokenUser, NULL, 0, &needed) || GetLastError() != ERROR_INSUFFICIENT_BUFFER ||
        needed < sizeof(TOKEN_USER) || needed > 65536u) goto done;
    allocated = needed;
    user = (TOKEN_USER *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, allocated);
    path = (wchar_t *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, DSH_HELPER_PATH_MAX * sizeof(wchar_t));
    if (user == NULL || path == NULL || !GetTokenInformation(token, TokenUser, user, allocated, &needed) || dsh_service_sid(user->User.Sid)) goto done;
    length = GetModuleFileNameW(NULL, path, DSH_HELPER_PATH_MAX);
    if (length < 4u || length >= DSH_HELPER_PATH_MAX || path[1] != L':' || path[2] != L'\\' ||
        !((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z'))) goto done;
    for (;;) {
        HANDLE file;
        wchar_t *separator;
        if (guard->count >= DSH_HELPER_DEPTH_MAX) goto done;
        file = dsh_open_helper_component(path, directory, user->User.Sid);
        if (file == INVALID_HANDLE_VALUE) goto done;
        guard->handles[guard->count++] = file;
        if (directory && wcslen(path) == 3u) break;
        separator = wcsrchr(path, L'\\');
        if (separator == NULL || separator < path + 2) goto done;
        if (separator == path + 2) path[3] = L'\0'; else *separator = L'\0';
        directory = TRUE;
    }
    safe = TRUE;
done:
    if (!safe) dsh_close_helper_guard(guard);
    if (path != NULL) { SecureZeroMemory(path, DSH_HELPER_PATH_MAX * sizeof(wchar_t)); HeapFree(GetProcessHeap(), 0, path); }
    if (user != NULL) { SecureZeroMemory(user, allocated); HeapFree(GetProcessHeap(), 0, user); }
    if (token != NULL) CloseHandle(token);
    return safe;
}
#endif
