# Contributing

## Before changing anything

Read [`CHANGELOG.md`](CHANGELOG.md). It records the defects found while
running this on real hosts, and almost every one presented as something
other than its cause. The same failure modes recur.

## Run the tests

```bash
./tests/test-pam-stack.sh        # PAM generator: jump arithmetic, idempotency
./tests/test-selfenroll-flags.sh # enrolment asks the user nothing
./tests/test-os-detect.sh        # distribution detection
```

They need no root, no target distribution and no PAM, so they run on a
laptop. All three must pass.

```bash
bash -n <script>
shellcheck -S warning install.sh scripts/*.sh scripts/lib/common.sh helpers/* tests/*.sh
```

## What cannot be tested off-host

SELinux policy cannot be compiled outside the target family, and the
`ForceCommand` enrolment flow, the sudoers rule and everything touching
`dnf`, `systemctl` or `runuser` need a real machine. Test those in a VM of
the distribution you are targeting, and **say in the pull request what you
ran it on** — "untested on a host" is a fine thing to write, and far better
than leaving a reviewer to assume.

## Two rules worth stating explicitly

**The PAM jump counts are positional.** `pam_block()` emits
`[success=N]` values that count modules to skip. Adding one line
invalidates every jump above it, and the failure mode is a fleet that
cannot log in. The tests assert each jump's declared count *and* the line
it lands on, for every mode and gate combination. Extend them when you
change the block.

**A test that reimplements what it checks proves nothing.** This project's
validator passed a broken host three times because it encoded the same
assumption as the code. Drive the real function — `detect_os` takes an
os-release path for exactly this reason — and confirm a new test fails when
you deliberately break the thing it covers.

## Style

Match the surrounding code. Every mutating script takes `--dry-run`, calls
`backup_file` before touching `/etc`, gates sshd reloads on
`sshd_validate`, and uses `systemctl reload` rather than `restart` because
the operator is usually applying the change over SSH.

Comments explain *why*, particularly where the code works around something
non-obvious. Several exist because the obvious version was wrong.
