/* Current-user DPAPI protocol primitive. No filesystem or journal enablement.
 * Callers must separately verify the helper and provide Windows private ACLs. */
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <wincrypt.h>
#include <stdint.h>
#include <string.h>
#include <wchar.h>

#define DSH_CONTEXT_MAX 16384u
#define DSH_WRAPPED_MAX 16384u
#define DSH_KEY_SIZE 32u
#define DSH_HEADER_SIZE 16u
#define DSH_REQUEST_MAX (DSH_HEADER_SIZE + DSH_CONTEXT_MAX + DSH_WRAPPED_MAX)
static const BYTE request_magic[8] = {'D','S','H','D','P','Q','0','1'};
static const BYTE response_magic[8] = {'D','S','H','D','P','R','0','1'};
static const BYTE entropy_domain[] = "dsh-mobile-ustc/journal-dpapi/v1";

static DWORD dsh_protection_flags(void) { return CRYPTPROTECT_UI_FORBIDDEN; }

static BOOL dsh_service_sid(PSID sid) {
    return sid == NULL || !IsValidSid(sid) || IsWellKnownSid(sid, WinLocalSystemSid) ||
        IsWellKnownSid(sid, WinLocalServiceSid) || IsWellKnownSid(sid, WinNetworkServiceSid);
}

static BOOL dsh_current_user_allowed(void) {
    HANDLE token = NULL;
    DWORD needed = 0, allocated = 0;
    TOKEN_USER *user = NULL;
    BOOL allowed = FALSE;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) goto done;
    if (GetTokenInformation(token, TokenUser, NULL, 0, &needed) || GetLastError() != ERROR_INSUFFICIENT_BUFFER ||
        needed < sizeof(TOKEN_USER) || needed > 65536u) goto done;
    allocated = needed;
    user = (TOKEN_USER *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, allocated);
    if (user == NULL || !GetTokenInformation(token, TokenUser, user, allocated, &needed)) goto done;
    allowed = !dsh_service_sid(user->User.Sid);
done:
    if (user != NULL) { SecureZeroMemory(user, allocated); HeapFree(GetProcessHeap(), 0, user); }
    if (token != NULL) CloseHandle(token);
    return allowed;
}

static uint32_t dsh_read_u32(const BYTE *input) {
    return (uint32_t)input[0] | ((uint32_t)input[1] << 8) | ((uint32_t)input[2] << 16) | ((uint32_t)input[3] << 24);
}
static void dsh_write_u32(BYTE *output, uint32_t value) {
    output[0] = (BYTE)value; output[1] = (BYTE)(value >> 8);
    output[2] = (BYTE)(value >> 16); output[3] = (BYTE)(value >> 24);
}

/* Pipes need an explicit EOF. Never allocate or wait based on an untrusted size. */
static BOOL dsh_read_request(BYTE *buffer, DWORD *length) {
    HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
    DWORD total = 0;
    if (input == NULL || input == INVALID_HANDLE_VALUE) return FALSE;
    for (;;) {
        DWORD received = 0;
        BOOL success = ReadFile(input, buffer + total, DSH_REQUEST_MAX + 1u - total, &received, NULL);
        if (!success) {
            if (GetLastError() != ERROR_BROKEN_PIPE) return FALSE;
            received = 0;
        }
        total += received;
        if (total > DSH_REQUEST_MAX) return FALSE;
        if (received == 0) break;
    }
    *length = total;
    return TRUE;
}
static BOOL dsh_write_all(HANDLE output, const BYTE *data, DWORD length) {
    DWORD total = 0;
    if (output == NULL || output == INVALID_HANDLE_VALUE) return FALSE;
    while (total < length) {
        DWORD written = 0;
        if (!WriteFile(output, data + total, length - total, &written, NULL) || written == 0) return FALSE;
        total += written;
    }
    return TRUE;
}

int wmain(int argc, wchar_t **argv) {
    BYTE *request = NULL;
    DATA_BLOB input = {0, NULL}, entropy = {0, NULL}, output = {0, NULL};
    BYTE header[12] = {0};
    DWORD length = 0;
    uint32_t context_size = 0, data_size = 0;
    BOOL protect = FALSE, success = FALSE;
    int result = 1;
    if (argc != 2 || (wcscmp(argv[1], L"journal-protect-v1") != 0 && wcscmp(argv[1], L"journal-unprotect-v1") != 0)) goto done;
    protect = wcscmp(argv[1], L"journal-protect-v1") == 0;
    if (!dsh_current_user_allowed()) goto done;
    request = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, DSH_REQUEST_MAX + 1u);
    if (request == NULL || !dsh_read_request(request, &length) || length < DSH_HEADER_SIZE || memcmp(request, request_magic, sizeof(request_magic)) != 0) goto done;
    context_size = dsh_read_u32(request + 8); data_size = dsh_read_u32(request + 12);
    if (context_size == 0 || context_size > DSH_CONTEXT_MAX || data_size == 0 || data_size > DSH_WRAPPED_MAX ||
        length != DSH_HEADER_SIZE + context_size + data_size || (protect && data_size != DSH_KEY_SIZE)) goto done;
    entropy.cbData = (DWORD)sizeof(entropy_domain) + context_size;
    entropy.pbData = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, entropy.cbData);
    if (entropy.pbData == NULL) goto done;
    memcpy(entropy.pbData, entropy_domain, sizeof(entropy_domain));
    memcpy(entropy.pbData + sizeof(entropy_domain), request + DSH_HEADER_SIZE, context_size);
    input.cbData = data_size; input.pbData = request + DSH_HEADER_SIZE + context_size;
    if (protect) {
        /* Never CRYPTPROTECT_LOCAL_MACHINE, never a prompt or fallback. */
        success = CryptProtectData(&input, L"DSH Host journal key v1", &entropy, NULL, NULL, dsh_protection_flags(), &output);
    } else {
        success = CryptUnprotectData(&input, NULL, &entropy, NULL, NULL, dsh_protection_flags(), &output);
    }
    if (!success || output.pbData == NULL || (protect ? (output.cbData < 48u || output.cbData > DSH_WRAPPED_MAX) : output.cbData != DSH_KEY_SIZE)) goto done;
    memcpy(header, response_magic, sizeof(response_magic)); dsh_write_u32(header + 8, output.cbData);
    if (!dsh_write_all(GetStdHandle(STD_OUTPUT_HANDLE), header, sizeof(header)) ||
        !dsh_write_all(GetStdHandle(STD_OUTPUT_HANDLE), output.pbData, output.cbData)) goto done;
    result = 0;
done:
    if (output.pbData != NULL) { SecureZeroMemory(output.pbData, output.cbData); LocalFree(output.pbData); }
    if (entropy.pbData != NULL) { SecureZeroMemory(entropy.pbData, entropy.cbData); HeapFree(GetProcessHeap(), 0, entropy.pbData); }
    if (request != NULL) { SecureZeroMemory(request, DSH_REQUEST_MAX + 1u); HeapFree(GetProcessHeap(), 0, request); }
    SecureZeroMemory(header, sizeof(header));
    if (result != 0) {
        static const BYTE message[] = "DPAPI operation unavailable\n";
        (void)dsh_write_all(GetStdHandle(STD_ERROR_HANDLE), message, (DWORD)sizeof(message) - 1u);
    }
    return result;
}
