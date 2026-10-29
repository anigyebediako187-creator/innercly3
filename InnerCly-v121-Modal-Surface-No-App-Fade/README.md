# InnerCly v121 — Create Flow Design Polish

This package builds on v120. v121 fixes the remaining local/offline fallback creation flows so they use the same white/light-blue design as the authenticated creation dialogs. It refreshes the Create a post composer, camera-based Create a story interface, and Create group dialog to match InnerCly’s white and light-blue styling, while preserving the existing publishing, camera, Story recording, and group-creation logic.

## Run locally
1. Extract the ZIP into a new folder.
2. Double-click `START_INNERCLY.bat`.
3. Keep the black Command Prompt window open while using InnerCly.
4. Sign in with your existing account.

Do not open `index.html` directly; run the launcher so the app can use its local API and database. The launcher checks for build v121. This is a separate update package; it does not modify other folders or the live Render service by itself.

## Scope and safeguards
- Section animations use opacity and transform only and take 260 ms.
- The animation is disabled when the device/browser requests reduced motion.
- The Story renderer/player, Story creation and camera/capture logic, navigation structure, upper layout geometry, database/authentication logic, and other feature code were not redesigned.
- The v40 and v80 master backups are included unchanged.


## v121 detail
Only the creation dialog surfaces and their backdrop treatment were adjusted. The app behind the dialogs is not dimmed or blurred. Story playback and other app sections remain unchanged.
