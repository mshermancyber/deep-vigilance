# Planned work — mobile / responsive layout

> **Status: not implemented.** This is the task brief for adding a mobile-optimized view,
> kept with the release as a specification for future work. It is not a description of
> current behaviour. The existing UI is responsive but desktop-first.

---

Act as a Principal Frontend Engineer specializing in responsive design and mobile web optimization. I have a desktop-optimized web application in this repository. I want you to implement a dual-view or redirected workflow specifically optimized for mobile devices (Android and iPhone) by detecting the browser's User-Agent.

Before modifying any files, analyze the current repository structure and perform these steps:

1. ARCHITECTURE SELECTION:
- Identify if the app uses client-side routing (e.g., React, Vue, Vanilla JS) or server-side rendering (e.g., Node/Express, Next.js, Python, PHP).
- If server-side, propose a middleware/detector that sniffs the User-Agent and serves a separate mobile layout template or redirects to a `/m` or `/mobile` sub-path.
- If client-side, create an adaptive root component or custom hook (e.g., `useDeviceType`) that returns 'desktop', 'android', or 'ios' based on regex checking of `navigator.userAgent`.

2. USER-AGENT DETECTION SPECIFICATION:
Implement robust detection rules. Ensure it matches:
- Android: /Android/i
- iPhone: /iPhone|iPad|iPod/i
Ensure it accounts for edge cases like tablets (if they should receive the mobile or desktop experience) and modern desktop Safari/Chrome simulation.

3. MOBILE FRONTEND SPECIFICATION:
- Read the main layout components of our desktop view.
- Create corresponding mobile components or style wrappers that convert grid/large column layouts into mobile-friendly vertical stacks.
- Enforce standard mobile touch targets (minimum 48x48px), eliminate desktop-only `:hover` dependency states, and ensure proper `<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">` headers are injected for mobile agents.
- Specifically tailor UI nuances: use native-feeling rounded corners and iOS-safe area paddings (`env(safe-area-inset-bottom)`) if the user agent is an iPhone.

Please provide a step-by-step breakdown of your proposed implementation plan first, show me which files you intend to create or modify, and ask for my confirmation before executing the code edits.
