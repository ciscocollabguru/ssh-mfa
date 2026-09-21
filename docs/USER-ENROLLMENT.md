# Setting up your SSH authenticator code

*Hand this to users. It assumes they can still log in — run it before strict
enforcement begins.*

From now on, logging into this server over SSH needs two things: your usual
SSH key (or password), **and** a 6-digit code from an app on your phone.

You need an authenticator app. Any TOTP app works — Google Authenticator,
Microsoft Authenticator, Authy, 1Password, Bitwarden, KeePassXC, Aegis.

---

## Enrol (about two minutes)

**1. Log into the server as you normally do.**

**2. Run:**

```bash
google-authenticator -t -d -f -w 3 -r 3 -R 30
```

What the flags do: time-based codes, no code reuse, don't ask redundant
questions, tolerate ~90 s of clock skew, and allow at most 3 attempts per
30 seconds.

**3. Scan the QR code** that appears with your authenticator app.

If the QR code is unreadable because your terminal is too small, enlarge the
window and re-run, or type in the `Your new secret key is:` string manually.

**4. Save your emergency scratch codes.**

You will see something like:

```
Your emergency scratch codes are:
  17482915
  90371164
  ...
```

Each works **once**, in place of a code from your phone. They are your only
self-service way back in if you lose your phone. Put them in a password
manager or somewhere safe that is **not** the phone holding the app.

**5. Test it before you log out.** In a *second* terminal, leaving your
current session open:

```bash
ssh you@server
```

You should be asked for a `Verification code:`. Enter the current 6-digit
code from your app.

> **Do not close your original session until a new login works.** If
> something is wrong, that open session is how it gets fixed.

---

## What a login looks like now

```
$ ssh you@server
Verification code: 123456
[you@server ~]$
```

The code changes every 30 seconds. Type the one showing at that moment; if it
is about to roll over, wait for the next one.

---

## Things that come up

**"Invalid verification code" even though I typed it correctly.**
Usually your phone's clock has drifted. Turn on automatic date & time in your
phone's settings (iOS: Settings → General → Date & Time → Set Automatically;
Android: Settings → System → Date & time → Set time automatically). Codes
cannot be reused — if you just used one, wait for the next.

**It asks for a code too quickly and rejects everything.**
There is a rate limit of 3 attempts per 30 seconds. Wait a minute and try
once, carefully.

**I lost my phone / got a new one.**
Use a scratch code to log in, then re-enrol with the command in step 2 (your
old secret is replaced). If you are out of scratch codes, contact your
administrator — they will need to reset your token for you.

**I never see a code prompt.**
Either you are on an exempt account, or you have not been switched over yet.
Not a problem you need to fix.

**Can I use the same app entry on two phones?**
Yes — scan the same QR code with both. Anything holding that secret can
generate valid codes, so treat both devices accordingly.

**Do `scp`, `rsync` and `git` over SSH need a code too?**
Yes, each new connection does. For repeated transfers, reuse one
authenticated connection by adding this to your local `~/.ssh/config`:

```
Host server
    ControlMaster auto
    ControlPath ~/.ssh/cm-%r@%h:%p
    ControlPersist 10m
```

You will be prompted once, and subsequent commands reuse that connection for
10 minutes.

---

## Keep in mind

- Your secret lives in `~/.google_authenticator`. Don't copy it off the
  server, don't put it in a repo, and don't move or delete it.
- Nobody legitimate will ever ask you for a code. Anyone who does is
  attacking you — a code read aloud or pasted into a chat is a working
  credential for the next 30 seconds.
