## v121 — Keep app background clear behind creation panels
- Updated only the Create Post, Create Story, and Create Group modal surface styling.
- Removed the dimming/blur effect from behind those creation panels and the Story camera overlay; the app behind them stays unchanged.
- Preserved Story viewer/playback styles and live-video mode.

## v121 — Make creation designs consistent across app modes

- Fixed the actual local/offline fallback post composer, which was still opening the old form.
- Fixed the fallback Story composer to use the same modal styling, media drop zone, caption field, and existing Story-save callback.
- Fixed the fallback Create Group flow to open the matching styled modal while using the existing local group-save logic.
- Kept the server-backed dialogs, camera Story creator, media/player logic, authentication, header/navigation, and feed handlers intact.
- Updated the local launcher and API build marker to v121.

## v119 — Create Post, Story, and Group design polish

- Reworked the live Create a post modal to match the supplied white/light-blue reference, with a 500-character counter, public/friends visibility, drag-and-drop media area, visible file selection status, voice-note controls, and expandable media library.
- Restyled the Story camera panel to match the provided camera layout: light panel, blue effect controls, live-camera badge, top-right flip-camera shortcut, caption/mentions, and responsive controls. Existing capture and recording handlers are preserved.
- Reworked the Create group dialog to match the same style and improved the Groups/Circles card treatment. Existing group API submit/reload logic is preserved.
- Kept the upper navigation/layout, section animations, logo assets, Story viewer/player, authentication and existing data routes unchanged.
- Updated local launcher/API build marker to v121.

## v118 — Section animations and cleaner opening sequence

- Added a subtle 260 ms fade-and-lift transition whenever an app section opens, using opacity and transform only.
- Respects the device/browser reduced-motion preference by disabling the new section animation.
- Removed the visible “ENTER INNERCLY” button from the opening animation; the existing automatic dismissal and keyboard dismissal remain.
- No Story renderer/player code, navigation structure, upper layout geometry, database behavior, or feature logic was changed.
- Preserved the v40 and v80 master backups unchanged.

## v114 — Story and Home initialization recovery

- Fixed a scope error in the standalone account-header synchronization helper: it referenced `runtime`, `esc`, and `accountBadgeMarkup` from another script callback's lexical scope. This could throw during authenticated startup and prevent Home/Stories initialization from finishing.
- The helper now uses `window.__INNERCLY_REALTIME__`, `window.__INNERCLY_ACCOUNT_BADGE_MARKUP__`, and its own HTML escaping function.
- Story creation, playback, rendering, camera/capture flow, and Story CSS were not edited. The v40 and v80 master backups remain unchanged.

## v113 — Home feed refresh reliability

- Fixed an overlapping-request race in `refreshPosts`: the newest request started no longer cancels an older successful response if the newest request fails. Once a newer response successfully applies, older responses are ignored.
- Malformed feed responses are treated as errors rather than valid empty feeds, preventing cached posts from being cleared by an incomplete payload.
- Initial Home feed fetch retries twice after short delays while cached content remains visible, reducing the chance that a brief startup/network race leaves the feed incomplete.
- Exposed the canonical refresh function to existing feature integration helpers.
- No changes to the Stories renderer or upper app layout. The v40/v80 master backups are unchanged.

## v112 — Session-hint recovery and Home feed reload
- Fixed a concrete stale-session hint risk: the page bootstrap previously read `sessionStorage` before `localStorage`, while the auth flow writes `localStorage` first. If a stale tab hint survived a failed sessionStorage update, the page could repeatedly select the wrong state namespace after reload and leave the Home feed stale or incomplete.
- The early bootstrap and session-hint reader now compare both stores and prefer the newest timestamped hint; older hints fall back to localStorage.
- If the durable hint write succeeds but writing sessionStorage fails, the app removes the stale tab hint when possible.
- Added no changes to the Stories renderer or the upper app layout. v40/v80 master backups are unchanged.

## v111 — Authenticated startup blank-screen recovery

- Fixed a concrete recovery flaw carried in v109/v110: if `startRuntime()` set the realtime `ready` flag and then threw before a view was activated, the recovery path skipped its retry, hid the sign-in overlay, and reported success. That could leave the app looking empty.
- Recovery now retries authenticated runtime activation even when `ready` is already true, and makes the existing Home view visible if startup leaves every `.view` inactive.
- If authentication is valid but rendering still has a problem, the user stays signed in and gets a visible notice instead of an empty screen or a false request to sign in again.
- The Stories renderer and upper app layout were not changed by this patch; v40/v80 master backups are unchanged.

## v110 — Consistent build identification

- Corrected the stale sign-in-screen label from `INNERCLY BUILD · V107` to `INNERCLY BUILD · V110`. The previous v109 package already reported v109 through its API and launcher, but the leftover visible label made it look like v107 was opening.
- Aligned the browser title, API build values, launcher-required build, launch URL cache-buster, and launcher status messages to v110.
- Carried forward the v109 session-restoration handling and other app features without intentional changes to their behavior.
- Preserved the v40 and v80 master backups byte-for-byte.

## v109 — Session restoration error handling

- Fixed a startup-path bug that could treat a client-side app initialization exception as a failed saved login, even when `/api/auth/me` had already confirmed the server session.
- Added limited retries for transient connection/server errors during session restoration.
- A real HTTP 401 still opens the sign-in prompt. Other HTTP errors now show their status and do not claim the session was lost or ask the user to sign in as though the password were wrong.
- Kept changes limited to session restoration messaging/flow and version identifiers; feature layout and behavior elsewhere were not intentionally changed.
- v40 and v80 backup files were carried forward unchanged.

## v108 — Stable local session origin

- Traced the repeated-login path in the saved v107 project. The server session is stored in an HttpOnly cookie scoped to the exact local host and port; the launcher previously could silently choose a different port when the remembered port was occupied, making the saved cookie unavailable at the new address.
- The launcher now keeps the remembered local port stable and warns instead of silently switching to a different origin when an unrelated process occupies it. If an InnerCly server is detected, existing safe replacement behavior is retained.
- No login UI, feed, Stories, badges, or social features were changed. v40 and v80 backup files are preserved unchanged.

## v107 — Session restoration and immediate Home feed

- Fixed local HTTP cookie security by basing the cookie Secure attribute on the actual request origin; loopback HTTP does not receive an unusable Secure cookie.
- Start server-session validation while the existing intro animation is playing so Home/feed loads in parallel.
- Check that the newly issued server cookie authenticates successfully before forcing the account-state reload; display a clear error when cookie persistence cannot be confirmed.
- Render the current account's compact cached feed immediately, then replace it with the fresh server response. Large inline media is excluded from the cache to avoid browser storage exhaustion.
- Kept header/top-navigation markup and app layout structure unchanged. Badge management from v105 remains present.
- Preserved v40 and v80 master backups byte-for-byte.

## v105 — Restore session persistence and instant Home feed

- Kept the v104 global badge rendering and dedicated badge-management page.
- Local launcher now reuses a running v105 server only when it confirms local-development cookie settings; it replaces a misconfigured server that would issue Secure cookies over HTTP.
- Authentication restoration no longer lets a transient second check reopen the login overlay after a session is already active.
- Home is selected after session restoration; the feed placeholder renders immediately and the post list appears as soon as the posts API returns, without waiting for unrelated sections.
- Preserved the existing header/navigation structure and all original features.
- Left v40 and v80 backup files unchanged.

## v104 — Active badges displayed across InnerCly

- Added a shared account-name badge formatter used across posts, comments, friend lists and requests, followers, Discover, profiles, group/event owners, group/direct/marketplace/delivery chats, Marketplace sellers, moderation safety lists, and owner role/badge search results.
- Stories now retain badge data from the API and display active badges on story cards.
- Standardized active-badge serialization and included it in story, owner user-search, blocked-user, and muted-user responses so those surfaces have the data needed to display badges.
- Kept the dedicated Creator Verification & Badges page and the existing Roles & Permissions controls.
- Kept v40 and v80 master backup files unchanged.

## v104 badge-visibility additions

- Covered top account name/header refresh after sign-in, profile updates, and an Owner granting a badge to their own account.
- Added safe self-account badge rendering to the legacy local feed comments, Marketplace seller/order cards, and local seller/order chat labels.
- Added active badge data to moderation report targets and reporters so the Safety UI can render them.

## Validation

- Python syntax checked.
- Inline JavaScript syntax checked.
- ZIP integrity checked.
- Isolated API badge-grant smoke test passed in v104.


## v115 — Reels, Circles, Saved, Notifications, Creator Dashboard polish

- Replaced the local-only Reels gallery with a server-backed vertical video feed using existing post visibility, block, mute, and permission checks; added muted visible-card playback, pause-on-scroll, view tracking, like/comment/save/share/follow/report/delete actions, retry and empty states.
- Renamed the Groups view heading to Circles and added client-side search plus All/Joined/Created-by-me filters, without changing the existing group database or chat flows.
- Added search and collection filters to Saved; all save entry points now use a consistent collection picker.
- Added unread notification filtering, read-all, and navigation to related posts/chats/groups and other supported features.
- Improved creator analytics to show total post count, measured interaction-per-view rate, and posts ranked by recorded activity.
- Kept the Stories renderer/player and upper UI structure intact apart from the existing build marker text. The safety/privacy controls were already implemented and were not rewritten.


## v116 — Original logo fix
- Replaced the circular blue logo treatment on the opening and sign-in screens with the supplied full-logo artwork.
- Kept the compact header and landing page in their existing dimensions, using the original square-corner mark with the existing blue wordmark.
- Removed circular clipping/rings from active brand-mark displays.
- Updated the app build marker and Windows launcher check to v116 so it will not silently reuse a running v115 process.
- Did not modify Stories functionality, authentication logic, database logic, upper layout structure, or the v40/v80 backup files.


## v117 — Circular logo correction
- Corrected v116, which mistakenly changed the logo back to a square-corner treatment.
- Added a transparent circular-mask PNG derived from the existing InnerCly icon.
- Restored circular logo display on the phone/desktop header, opening screen, sign-in screen, verified-creators panel, and landing page.
- Preserved the existing wordmark, upper layout geometry, Stories renderer/player, login/database logic, and v40/v80 backup files.
