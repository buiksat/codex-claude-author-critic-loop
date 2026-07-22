# Fixed author-service replacement

The broker pins the normalized Python-source closure of the whole installed
`agent_loop` package. Consequently, changing any package source file requires a
version-matched replacement of the root-owned service; updating only the `pipx`
installation is intentionally rejected.

Replacement is two bounded transactions: the exact old installation is removed
by `uninstall.sh`, then the new wheel is installed by the failure-atomic,
retryable `install.sh`. Build and verify the new wheel before stopping the old
socket. Neither transaction reads, moves, or deletes agent credential stores.

Run the following as root after substituting reviewed absolute paths and digest
values. Keep the staging directory until the new installer reports success so a
failed install can be retried without another source copy.

```sh
set -eu
umask 077
replace_stage=$(mktemp -d /run/agent-loop-author-replace.XXXXXX)
old_wheel_sha256='<wheel_sha256 from the current root-owned install record>'
new_wheel='/absolute/path/to/agent_loop-1.1.0-py3-none-any.whl'
new_wheel_sha256='<reviewed sha256 of new_wheel>'
codex_closure_sha256='<reviewed normalized Codex installation digest>'
operator_name='<unprivileged operator account>'

install -d -o root -g root -m 0755 "$replace_stage"
install -o root -g root -m 0555 \
  /absolute/reviewed/source/support/author-service/uninstall.sh \
  "$replace_stage/uninstall.sh"
install -o root -g root -m 0555 \
  /absolute/reviewed/source/support/author-service/install.sh \
  "$replace_stage/install.sh"
install -o root -g root -m 0444 "$new_wheel" \
  "$replace_stage/agent_loop-1.1.0-py3-none-any.whl"

"$replace_stage/uninstall.sh" "$old_wheel_sha256"
"$replace_stage/install.sh" \
  "$replace_stage/agent_loop-1.1.0-py3-none-any.whl" \
  "$operator_name" "$new_wheel_sha256" "$codex_closure_sha256"

rm -f -- "$replace_stage/uninstall.sh" "$replace_stage/install.sh" \
  "$replace_stage/agent_loop-1.1.0-py3-none-any.whl"
rmdir -- "$replace_stage"
```

`uninstall.sh` requires the old wheel digest, validates every fixed external
file against the installed wheel/configuration, and publishes a private
transaction marker before changing anything. If it is interrupted, invoke the
same command with the same digest; it validates all surviving paths and resumes.
It removes only the fixed service paths and deliberately preserves shared
`/etc/agent-loop` and `/run/agent-loop` contents. The new installer rejects a
remaining uninstall marker, so the two phases cannot overlap.
