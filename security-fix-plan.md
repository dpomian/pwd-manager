Good question — the answer is "phased rollout with lazy migration and key wrapping", not "big bang". Here's the strategy I'd recommend.

## Guiding principles

1. **Never bulk-migrate in one shot.** Migrate per-user, on login, lazily. A failed migration affects one user, not everyone.
2. **Don't re-encrypt existing ciphertexts.** Use **key wrapping** so the data-encryption key (DEK) stays the same and all existing ciphertexts/attachments remain valid.
3. **Keep the old `encryption_key` column for one release after migration** as a fallback. Don't delete what we can't recreate.
4. **Gate every behaviour change behind a feature flag** so we can roll back without a redeploy of code logic.
5. **Take a DB backup before each phase and test restore on a copy.**
6. **Add regression tests for current behaviour first** — they become the safety net for every change.

## The key insight that makes C1/C2 safe

The current DEK in `User.encryption_key` is a random 32-byte key. We do **not** need to change it. We only need to change **how it's stored**:

- Today: plaintext in the DB.
- Tomorrow: wrapped (encrypted) with a KEK derived from the master password via Argon2id + per-user salt.

Because the DEK itself doesn't change, **every existing ciphertext, every attachment on disk, every note stays valid**. We're only re-wrapping a single 32-byte value per user, on login, in a transaction. That's the lowest-risk possible approach to fixing C1.

## Phased rollout

### Phase 0 — Safety net (no behaviour change)
- Add integration tests covering: register, login, add/edit/delete secret, document CRUD, attachment upload/download/preview, Markdown render.
- Add automated DB backup (e.g. `sqlite3 ... .backup`) + a restore test on a copy.
- Add a `FEATURE_FLAGS` env mechanism (e.g. `ENABLE_KEY_WRAPPING=0`).

### Phase 1 — Non-breaking hardening (no schema change, no migration)
Ship these first — they don't touch encryption or the DB:

| Fix | Risk | Mitigation |
|-----|------|------------|
| H2 debug=False | Low | Opt-in via `FLASK_DEBUG=1` |
| H5 `secrets` module | Low | Pure drop-in |
| M1 generic errors | Low | Log full trace server-side |
| M2 security headers | Low | `after_request` hook; verify CSP doesn't break Bootstrap CDN |
| M4 SQL wildcard escape | Low | Pure filter change |
| M5 `chmod 750` | Low | New image only; existing volumes unaffected |
| M6 HSTS | Medium | Only enable behind HTTPS; off by default |
| L1, L3 | Low | — |

The two Phase-1 items that **can** break UX:

- **H1 `SECRET_KEY` fail-closed**: changing the key invalidates every session (users get logged out, not data loss). Mitigation: announce ahead of time; pick one strong key and keep it stable. Don't fail-closed on first release — instead **warn loudly** if the key is a known default, and fail-closed in the release after.
- **C3 CSRF**: most disruptive Phase-1 change. Add `Flask-WTF` `CSRFProtect(app)`, render `{{ csrf_token() }}` in all ~6 forms (register, login, add_secret, edit_secret, document_form, inline delete forms in `index.html` and `library/index.html`), and require `X-CSRFToken` header on JSON endpoints (attachment upload/clipboard/delete). Risk: a missed form → 400 on every submit. Mitigation: the regression tests from Phase 0 must POST to every form and assert 200; manually click-test every form before deploy. Testing config already has `WTF_CSRF_ENABLED=False`.

- **C4 Markdown sanitisation**: add `bleach.clean` with a strict allowlist before `Markup(...)`. Risk: existing notes that legitimately use now-stripped tags will render differently. Mitigation: run a one-off script over a DB copy to count how many notes contain `<script>`, `<iframe>`, inline event handlers, etc. — almost certainly zero, but verify.
- **C5 inline-JS interpolation**: replace `onclick="copyToClipboard(this, '{{ password }}')"` with `data-password` + an event listener. Pure template change; no DB impact.

### Phase 2 — Key wrapping migration (the only DB-touching change)

**Schema migration (additive only — no drops, no rewrites):**
```
ALTER TABLE user ADD COLUMN kdf_salt        VARCHAR(64)  NULL;
ALTER TABLE user ADD COLUMN kdf_iterations  INTEGER      NULL;
ALTER TABLE user ADD COLUMN wrapped_dek     VARCHAR(255) NULL;
ALTER TABLE user ADD COLUMN key_version     INTEGER      NOT NULL DEFAULT 0;
-- key_version=0  => legacy: plaintext DEK in encryption_key
-- key_version=1  => wrapped: KEK = Argon2id(password, kdf_salt), DEK in wrapped_dek
```
All new columns nullable/defaulted → existing rows keep working unchanged.

**Registration (new users):**
1. Generate random DEK (32 bytes).
2. Generate random salt.
3. Derive KEK = Argon2id(password, salt).
4. `wrapped_dek = Fernet(KEK).encrypt(DEK)`.
5. Insert with `key_version=1`, `encryption_key=NULL`.

**Login (existing users) — lazy migration:**
```
user = User.query.filter_by(username=...).first()
if user.key_version == 0:                       # legacy
    if not user.check_password(password): reject
    dek = b64decode(user.encryption_key)        # old plaintext DEK
    # promote: wrap DEK with password-derived KEK
    salt = os.urandom(16)
    kek = argon2.derive(password, salt)
    user.wrapped_dek = Fernet(kek).encrypt(dek)
    user.kdf_salt = b64encode(salt)
    user.kdf_iterations = ARGON2_PARAMS
    user.key_version = 1
    # KEEP user.encryption_key for now (fallback until next release)
    db.session.commit()
elif user.key_version == 1:
    kek = argon2.derive(password, b64decode(user.kdf_salt))
    dek = Fernet(kek).decrypt(user.wrapped_dek)  # raises if password wrong
# keep dek in memory only (e.g. session['dek'] encrypted with app SECRET_KEY,
# or a process-local cache keyed by session id)
```

**Why this is safe:**
- The DEK never changes → all existing ciphertexts and on-disk attachments decrypt unchanged.
- Migration is one row, one transaction, per user, at login. Failure → rollback → user retries; data still readable via the old `encryption_key` we haven't deleted.
- `key_version` lets old and new users coexist indefinitely.
- If Argon2 params need to change later, bump `key_version` and re-wrap on next login.

**`get_user_encryption_key()` change:** instead of reading `user.encryption_key` from the DB on every request, read the in-memory DEK stashed at login. This is actually a behaviour change worth flagging — today the key is fetched fresh from the DB on every request; tomorrow it must survive across requests in the session. Options:
- Store DEK in `session['dek']` encrypted with a key derived from `SECRET_KEY` (acceptable; `SECRET_KEY` is now strong after H1).
- Use a server-side session store (Flask-Session with filesystem/redis backend) so the DEK never leaves the server.

Either way, **logout clears it** (already does `session.pop('user_id')` — extend to clear `dek`).

### Phase 3 — Cleanup (one release after Phase 2 is confirmed)
- Once monitoring shows all active users have `key_version=1`, ship a migration that **drops the `encryption_key` column**.
- Remove the legacy branch from login.
- Remove the feature flag.

## Per-fix risk notes for the trickier ones

- **C1/C2**: risk is "user types wrong password during migration and we wrap with a wrong KEK". Prevented by: only migrate after `check_password` succeeds (legacy path) or after `Fernet(kek).decrypt(wrapped_dek)` succeeds (post-migration). Never persist a wrap that hasn't been verified by a round-trip.
- **H1**: rotating `SECRET_KEY` logs everyone out. Pick the final key **before** Phase 2, because Phase 2 stores DEKs in session encrypted with it.
- **C3**: highest UX risk in Phase 1. Add a `/health/csrf` test route that exercises every form in CI.
- **C4**: back-run `bleach.clean` over a DB copy to confirm no legitimate content is destroyed.
- **H4 session regeneration**: call `session.clear()` before setting `user_id`. Risk: users with "remember me" tabs get logged out — acceptable, one-time.

## Suggested first step

Start with Phase 0: add the regression test suite and a backup script. That gives every subsequent change a safety net and is itself zero-risk. Then do Phase 1's non-disruptive fixes (H2, H5, M1, M2, M4, M5) as one small PR each, then C3 + C4 + C5 as a focused "XSS/CSRF hardening" PR with the new tests gating it. Only then start Phase 2.

Want me to start with Phase 0 — scaffold the regression tests and a backup helper — or would you rather I draft the Phase 2 schema migration + login-flow change first so you can review the riskiest piece on paper before any code lands?