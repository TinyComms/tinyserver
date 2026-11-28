# custom-auth-pages

Proves that TinyServer serves its own `/favicon.svg` (`ts` mark), bespoke dark/light TinyServer styling, and Copy/Download recovery code controls on `/v1/auth/passkey` and `/v1/auth/passkey/claim` while keeping strict CSP and zero pre-peek server disclosure.

Fails on `main` (which has no `/favicon.svg` route, uses the `tc` icon path, dark-only flat styling, and no Copy/Download recovery buttons) and passes on this branch.
