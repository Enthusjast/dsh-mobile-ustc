# Android task-focused navigation

## Scope and baseline

This is the first implementation slice of `android-ui-ux-plan.md` §16.2: basic theme/components, session-first navigation, current-runtime directory, computer details, and settings. Chat reading/composer replacement and field-based approval review are subsequent slices; no protocol or persistence changes are included.

Baseline source: `HomeScreen.kt` previously placed registration success, refresh, notifications, updates, binding and logout before the runtime cards. Opening a displayed session required its separate `读取会话` button in `SessionsScreen.kt`. Three source-defined paths:

| Task | Previous path | New path |
| --- | --- | --- |
| Open an existing session | Registered home → scroll to computer → view sessions → read button | Sessions → current computer directory → tap row |
| Send text | Open session → existing queue/steer composer → existing coordinator | Unchanged after opening session |
| Review approval | Open session → approval entry → full paged JSON → explicit page acknowledgements → decision → platform identity | Unchanged after opening session |

These are path descriptions, not task-time measurements. Existing public synthetic screenshots are in the ignored `.local/android-showcase-20261027/screenshots/` gallery (23 images, API 36, 720 × 1280); the gallery's banner and separately expanded panels are not production navigation. This slice keeps before/after captures and actual verification logs in the ignored `.local/android-ui-navigation/` directory. A capture must record pixel dimensions, density, font scale, theme, build and scene. No production secure-window flag is disabled.

## Page and state inventory

| Area | States / owner | Boundary |
| --- | --- | --- |
| Account setup | Unconfigured/invalid config, sign-in, recovery failure, reauthentication, enrollment, enrollment unknown; `LoginController` | Outside main navigation; no synthetic authenticated fallback |
| Sessions | Current verified runtime, directory loading/error/empty, directory-only grant, readable/archived/unavailable rows | No all-runtime transcript fetch or unread inference |
| Computers | Authorized runtimes, unknown presence, list/create capabilities, details, binding entry | Runtime IDs remain distinct authority subjects, including same-name hosts |
| Settings | Account/device, notifications, updates, about, explicit logout | Account success and management are not session-list content |
| Chat | Connecting/syncing/live/offline/cache/denied, bounded history, outbox, questions/files/approval entry | Existing single reader and business coordinators |
| Approval | Current online context, paged complete action, identity, original decision reconciliation | Existing review coverage, expiry, rejection and callback retirement remain authoritative |
| Binding / creation | Existing staged business state, unknown result, reconciliation | No retained unsubmitted selections or confirmation authority in navigation |
| Platform work | Browser, biometric, document/save picker, installer | Existing operation tokens and account/navigation generations receive callbacks |

## Data-source decisions

| Display | Source | Fallback / restriction |
| --- | --- | --- |
| Computer label/version | Verified host alias and `RuntimeDirectoryEntry` | No inferred online state; full runtime/host/organization IDs in details |
| Session identity/workspace/state/update time | `SessionDirectoryEntry` | Short ID + workspace ID; timestamp means directory update, not last reply |
| Body read capability | Current runtime grant + `SessionDirectoryEntry.viewScope` | Directory-only row is not actionable; opening still uses controller validation |
| Task title/summary/unread count | Not supplied by current directory contract | Not fabricated; no bulk body reads to populate the list |
| Pending actions | Current foreground session's validated native state | Existing session entries only; not claimed as global inbox |

## Navigation and retirement contract

- Main destinations: Sessions (default), Computers, Settings. Chat, full approval, binding, creation, notification settings and application updates remain child pages, without bottom navigation.
- Navigation holds only destination, current directory runtime ID and `LazyListState` in memory. It is not saved-instance-state authority and never stores drafts, credentials, binding codes, approval handles, or question answers.
- Navigation is scoped to the READY account/device composition. Leaving READY or changing identity destroys it; a new account does not inherit the old destination or directory position.
- Only the current runtime's directory is requested automatically. The first eligible authorized runtime supplies the initial list. Switching computer revalidates through `openRuntime`; opening a row uses `openSession` and its existing scoped ticket/read path.
- Back from chat calls the existing controller `back`, retiring the reader, question scope, approvals, uploads/exports and callbacks before rendering the same safe directory. The list's stable keys and in-memory position remain available within that account composition.
- Switching to Computers/Settings first leaves the current directory through controller `back`; no hidden child page owns a retained connection. Returning to Sessions re-queries the selected runtime rather than displaying an authority cache.
- A directory entered from Computers returns to Computers; settings child pages return to Settings. A notification's known-session path still resolves the exact resource independently of broader directory enumeration and returns to reminders.
- Background/foreground, grant changes, expiry and late platform results continue through existing controller generations. UI navigation must not make an old interaction executable again.

## Layout decision

Low-fidelity 320dp layout targets, not screenshots or claims that later chat/approval slices are implemented. Wider windows retain a bounded single-column directory (max 800dp) in this slice, without additional readers.

```svg
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 960 430" fill="none" stroke="var(--border)" stroke-width="1">
  <g font-size="14" font-family="sans-serif">
    <g transform="translate(8 8)">
      <rect width="300" height="412" rx="12"/>
      <path d="M0 56H300M0 356H300"/>
      <g fill="currentColor" stroke="none">
        <text x="16" y="32">会话</text><text x="186" y="32">刷新　新建</text>
        <text x="16" y="86">当前电脑 / 运行环境　⌄</text>
        <text x="16" y="114" fill="var(--muted)">仅当前获授权范围，非全量索引</text>
        <text x="16" y="160">会话 短 ID　　　　　　　　›</text>
        <text x="16" y="188" fill="var(--muted)">已知状态 / 工作区 / 目录更新时间</text>
        <text x="16" y="244">会话 短 ID　　　　　　　　›</text>
        <text x="16" y="272" fill="var(--muted)">整行进入；目录授权不授予读取权</text>
        <text x="28" y="390">会话　　　电脑　　　设置</text>
      </g>
      <path d="M16 210H284M16 294H284"/>
    </g>
    <g transform="translate(330 8)">
      <rect width="300" height="412" rx="12"/>
      <path d="M0 68H300M0 310H300"/>
      <g fill="currentColor" stroke="none">
        <text x="16" y="28">返回　会话名称　　　　　　更多</text>
        <text x="58" y="52" fill="var(--muted)">电脑 / 工作区 · 连接状态</text>
        <text x="16" y="110">消息正文</text>
        <text x="16" y="144">代码 / 工具摘要 / 文件引用</text>
        <text x="16" y="200" fill="var(--muted)">稳定阅读锚点，历史前插不抢位置</text>
        <text x="174" y="282">回到底部 ↓</text>
        <text x="16" y="340">待处理入口（存在时）</text>
        <text x="16" y="370">排队 / 补充　　　附件</text>
        <text x="16" y="396">消息输入　　　　　　　　发送</text>
      </g>
    </g>
    <g transform="translate(652 8)">
      <rect width="300" height="412" rx="12"/>
      <path d="M0 56H300M0 310H300"/>
      <g fill="currentColor" stroke="none">
        <text x="16" y="32">返回　完整工具审批</text>
        <text x="16" y="88">当前来源 / 有效期 / 工具</text>
        <text x="16" y="124">完整参数、工作区、资源</text>
        <text x="16" y="160" fill="var(--muted)">每个值可完整阅读；可切原 JSON</text>
        <text x="16" y="208">本页显式核对　　上一页 / 下一页</text>
        <text x="16" y="252">核对进度 / 全部确认</text>
        <text x="16" y="282" fill="var(--muted)">滚动不代表允许；拒绝独立可达</text>
        <text x="16" y="344">仅本次允许并确认身份</text>
        <text x="16" y="380">拒绝并确认身份 / 查询原结果</text>
      </g>
    </g>
  </g>
</svg>
```

Material surfaces, paired light/dark colors, system fonts, spacing tokens and growing controls are shared through `core:ui`. Icons use vectors with semantic labels for actions; decorative arrows have no duplicate announcement. Controls target at least 48dp and no critical content relies on color alone. No motion is needed for main-navigation changes.

## Verification

2026-10-28, debug build, dedicated `dsh-remote-api26` emulator, Android 8.0 x86_64 under software emulation. Display override 720 × 1280 / 320 dpi; physical screenshot buffer 1080 × 1920. The synthetic Compose captures record their actual Compose root, density, font scale and theme in accompanying JSON. The device used its previously provisioned secure PIN and strong biometric; no enrollment or global ADB reset was performed for this run.

- `./gradlew --no-daemon --max-workers=2 -Pkotlin.compiler.execution.strategy=in-process '-Dorg.gradle.jvmargs=-Xmx1024m -Dfile.encoding=UTF-8' check :app:assembleDebug :app:assembleDebugAndroidTest` — passed, including Android lint and JVM checks.
- Actual default `MainActivity` startup displayed the unconfigured-school gate. The production window retained `FLAG_SECURE`; no authenticated demo mode was added.
- `DshAppShellTest` and `HomeNavigationTest`: 14 instrumentation cases passed. They cover list-only grants, single-row opening with the exact session ticket scope, same-name and colliding runtime identifiers, logout confirmation, narrow / 2× text / landscape actions, both back paths, real TLS reader retirement, account switching and known-session notification access without directory enumeration.
- The independently packaged synthetic showcase completed a ten-scene native walkthrough: directory → row → chat → back, computer details, settings → notifications / updates, logout confirmation and dark directory. This exercises presentation and navigation only, not a real server submission.
- Focused existing Android regressions: 69 instrumentation cases passed, including onboarding, account recovery, platform biometric enrollment callback, session/cache authorization, notifications, composer, questions, approval UI, binding, creation, uploads and updates. These were targeted runs, not the full device suite.
- The public synthetic baseline contains 14 saved states from the previous isolated showcase; the final shell has six light/dark and large-text synthetic captures with metadata. API 36 also captured seven earlier baseline images before that software emulator crashed. For the API 26 baseline, `wm size` reported the override but screenshots used the physical 1080 × 1920 buffer; no before/after pixel or timing comparison is claimed.
- Measured static text/background contrast for selected light/dark body, secondary, primary-button and error-container pairs ranged from 6.87:1 to 16.07:1. This does not replace full accessibility or contrast auditing.

The tested APKs and immutable logs/metadata are in ignored `.local/android-ui-navigation/`. Debug APK SHA-256: `1f0b29163f98a6ccea647693b180131a32738fa72c2928354aae8eb1cddf105c`; instrumentation APK: `6ee50a7cfd6f2cc62e764daaa5ddc5ffbb2c7e31e1986585458fafb80288e20e`. Synthetic screenshots demonstrate layout only; TLS/controller, platform key and physical-device evidence remain separate. School identity, physical-device/OEM background delivery, full U2–U6 performance and production release acceptance are not established by this slice.
