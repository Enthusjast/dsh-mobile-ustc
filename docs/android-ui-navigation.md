# Android task-focused navigation

## Scope and baseline

The first implementation slice introduced the task-focused navigation in §16.2; the subsequent reading, input and interaction changes reuse the existing protocol and persistence boundaries. The historical baseline and its verification record remain below.

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

### Optional metadata and aggregation

No optional U5 protocol extension is included in this UI work. Task titles and message summaries need a separately versioned producer, authorization scope and deletion/retention contract; unread counts additionally need durable, account-isolated read cursors and revocation semantics. Local aliases would require account-isolated storage and deletion on sign-out/revocation. Cross-runtime aggregation and a complete pending-work list require a bounded, paginated authorized query independent of push; QR binding requires a versioned, expiry-checked payload and a non-Google-services implementation. Until those contracts are approved, the UI uses existing directory IDs and validated current-session references only. It does not infer unread counts, fetch all transcripts or claim a global inbox.

## Navigation and retirement contract

- Main destinations: Sessions (default), Computers, Settings. Chat, full approval, binding, creation, notification settings and application updates remain child pages, without bottom navigation.
- Navigation holds only destination, current directory runtime ID, an in-memory filter and bounded directory/reading positions. Recent visits contain resource identifiers only and are revalidated against current authorized rows before display or opening. No saved-instance-state authority, drafts, credentials, binding codes, approval handles, or question answers are stored.
- Navigation is scoped to the READY account/device composition. Leaving READY or changing identity destroys it; a new account does not inherit the old destination or directory position.
- Only the current runtime's directory is requested automatically. The first eligible authorized runtime supplies the initial list. Switching computer revalidates through `openRuntime`; opening a row uses `openSession` and its existing scoped ticket/read path.
- Back from chat calls the existing controller `back`, retiring the reader, question scope, approvals, uploads/exports and callbacks before rendering the same safe directory. The list's stable keys and in-memory position remain available within that account composition.
- Switching to Computers/Settings first leaves the current directory through controller `back`; no hidden child page owns a retained connection. Returning to Sessions re-queries the selected runtime rather than displaying an authority cache.
- A directory entered from Computers returns to Computers; settings child pages return to Settings. A notification's known-session path still resolves the exact resource independently of broader directory enumeration and returns to reminders.
- Background/foreground, grant changes, expiry and late platform results continue through existing controller generations. UI navigation must not make an old interaction executable again.

## Reading, interaction and delivery boundaries

- Chat uses stable message keys, an account-scoped bounded in-memory anchor and explicit bottom-follow. Opening a previously visited message restores only when its key exists in the newly authorized snapshot; older-page requests remain owned and bounded by the existing reader. A visible new-message action returns to the latest content.
- The composer keeps queue/steer selection, explicit offline-only saving, current attachment readiness and the original submission callback. Selecting, removing from this message and deleting a stored transfer record are distinct actions. Original delivery facts and identifiers are shown separately from native transcript messages.
- Complete approval projection traverses the validated immutable context, including arbitrary nested values, unknown keys and binding fields. It uses bounded Unicode-safe pages and explicit per-page acknowledgements plus independent consent. Switching structured/raw representation clears confirmations. Projection is computed off the main thread and never replaces canonical signature bytes; leaving the foreground retires the ephemeral review.
- Question summaries never claim timed ownership. Explicitly opening a form may claim the current eligible timed question; closing or retiring the handle releases it. Plan continuation requires the complete displayed plan and explicit review, and unsubmitted form state is not restored.
- Uploads distinguish preparation, scanning, host staging, message selection and local record deletion. Exports use only authorized sources and retain the existing readback-verified saved state. Phone confirmation, host confirmation and binding grant remain separate; creation, notification and update screens distinguish original-request reconciliation, background delivery and installation results.
- Current pending entries are limited to validated state in the active session and do not imply a complete cross-device inbox. Notification configuration is not a prerequisite for answering foreground interactions.

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

## Initial navigation verification (commit 77b19cc)

2026-10-28, debug build, dedicated `dsh-remote-api26` emulator, Android 8.0 x86_64 under software emulation. Display override 720 × 1280 / 320 dpi; physical screenshot buffer 1080 × 1920. The synthetic Compose captures record their actual Compose root, density, font scale and theme in accompanying JSON. The device used its previously provisioned secure PIN and strong biometric; no enrollment or global ADB reset was performed for this run.

- `./gradlew --no-daemon --max-workers=2 -Pkotlin.compiler.execution.strategy=in-process '-Dorg.gradle.jvmargs=-Xmx1024m -Dfile.encoding=UTF-8' check :app:assembleDebug :app:assembleDebugAndroidTest` — passed, including Android lint and JVM checks.
- Actual default `MainActivity` startup displayed the unconfigured-school gate. The production window retained `FLAG_SECURE`; no authenticated demo mode was added.
- `DshAppShellTest` and `HomeNavigationTest`: 14 instrumentation cases passed. They cover list-only grants, single-row opening with the exact session ticket scope, same-name and colliding runtime identifiers, logout confirmation, narrow / 2× text / landscape actions, both back paths, real TLS reader retirement, account switching and known-session notification access without directory enumeration.
- The independently packaged synthetic showcase completed a ten-scene native walkthrough: directory → row → chat → back, computer details, settings → notifications / updates, logout confirmation and dark directory. This exercises presentation and navigation only, not a real server submission.
- Focused existing Android regressions: 69 instrumentation cases passed, including onboarding, account recovery, platform biometric enrollment callback, session/cache authorization, notifications, composer, questions, approval UI, binding, creation, uploads and updates. These were targeted runs, not the full device suite.
- The public synthetic baseline contains 14 saved states from the previous isolated showcase; the final shell has six light/dark and large-text synthetic captures with metadata. API 36 also captured seven earlier baseline images before that software emulator crashed. For the API 26 baseline, `wm size` reported the override but screenshots used the physical 1080 × 1920 buffer; no before/after pixel or timing comparison is claimed.
- Measured static text/background contrast for selected light/dark body, secondary, primary-button and error-container pairs ranged from 6.87:1 to 16.07:1. This does not replace full accessibility or contrast auditing.

The tested APKs and immutable logs/metadata are in ignored `.local/android-ui-navigation/`. Debug APK SHA-256: `1f0b29163f98a6ccea647693b180131a32738fa72c2928354aae8eb1cddf105c`; instrumentation APK: `6ee50a7cfd6f2cc62e764daaa5ddc5ffbb2c7e31e1986585458fafb80288e20e`. Synthetic screenshots demonstrate layout only; TLS/controller, platform key and physical-device evidence remain separate. School identity, physical-device/OEM background delivery, full U2–U6 performance and production release acceptance are not established by this slice.

## Expanded interaction and acceptance evidence

The subsequent reading, composer, approval, question and supporting-flow changes were exercised on the dedicated `dsh-remote-api26` Android 8.0 x86_64 software emulator, at 720 × 1280 / 320 dpi with the system-default font scale. These are debug builds and public synthetic fixtures, not production account data.

- `:app:assembleDebug :app:assembleDebugAndroidTest` and `check` passed after the final source changes. The application APK SHA-256 is `e10067925c5bd4afa67dd1961741127f53266bc56bfb001b16682bd34f79505b`.
- Six targeted batches on the earlier application APK `8b303e2cc50428cd5b421af16889a41a59fab8c3336dba883d65ed50c492b539` passed 122 instrumentation cases, including account/reader transitions, approval delivery with the emulator's existing strong biometric, question and chat delivery, file selection, export selection and the individual UI screens. These are targeted batches, not the complete device test suite.
- After the subsequent link accessibility action, attachment availability and owner-authority pending-hint changes, the current application APK passed 41 focused instrumentation cases (`ChatReadingTest`, `SessionComposerTest`, `SessionsScreenTest`, `HomeNavigationTest`, `DshAppShellTest`, `UploadsPanelTest`) with test APK `61bb36dd22a4aeab1b2c92eb3f3313da0b1572e03564b079dcb4d105d55e0d77`. The final test APK `f3aac85db2876fb2f25cd443214097bf8e1408b14869e80d25e892da4d8fe4c5` subsequently passed the question-form screenshot case; its only later change was the timing of that screenshot. Three reading, approval and question scenarios also passed with all three Android animation scales set to zero; the existing settings were restored. The emulator had no enabled accessibility service, so these checks do not claim a TalkBack walkthrough.
- A separately packaged synthetic showcase using the same fixture data as the pre-change baseline captured 11 current scenes, including directory, chat, offline, approval, question, transfers, binding, creation, notifications and updates. Both runs report the same display override and physical screenshot buffer; timestamps and scroll positions differ, so the images support visual review rather than pixel or timing comparisons. Real activity/Compose tests are separate from the showcase; the production `FLAG_SECURE` policy was not disabled.
- At 360dp width, default density-independent font scale and no attachments, the measured composer is 122dp high. In one debug long-history/incremental-update instrumentation sample on this software renderer, `gfxinfo` reported 137/137 janky frames and a 350ms median. This is a diagnostic observation, not a 60Hz performance pass or a device-independent benchmark. Startup, directory and network timing, peak memory, actual task completion time and comparative production performance remain unmeasured.

Synthetic screenshots, Compose root/density/font-scale metadata, raw instrumentation results and APK hashes remain under ignored `.local/uiux-acceptance-current/` and `.local/uiux-acceptance-final/`; pre-change captures remain under `.local/android-ui-navigation/before-api26/`. Physical-device/OEM behavior, TalkBack, production identity/server flows and release-build performance require separate acceptance and are not inferred from these fixtures.
