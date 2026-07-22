#!/bin/sh
set -eu

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset CDPATH ENV BASH_ENV PYTHONPATH PYTHONHOME

fail() { echo "agent-loop author bootstrap: $*" >&2; exit 2; }

absent() {
    [ ! -e "$1" ] && [ ! -L "$1" ] || fail "$1 already exists; refusing to overwrite it"
}

safe_shared_directory() {
    directory=$1
    [ -d "$directory" ] && [ ! -L "$directory" ] || \
        fail "$directory is not a real directory"
    [ "$(stat -c %u "$directory")" -eq 0 ] || fail "$directory is not root-owned"
    directory_mode=$(stat -c %a "$directory")
    directory_mode_value=$((0$directory_mode))
    [ $((directory_mode_value & 022)) -eq 0 ] || fail "$directory is group/world writable"
}

[ "$(id -u)" -eq 0 ] || fail "installer must run once as root"
[ "$#" -eq 4 ] || \
    fail "usage: ROOT_OWNED_INSTALLER WHEEL USER EXPECTED_SHA256 NORMALIZED_CODEX_CLOSURE_SHA256"

self=$(readlink -f -- "$0") || fail "cannot resolve installer path"
[ -f "$self" ] || fail "installer path is not a regular file"
[ "$(stat -c %u "$self")" -eq 0 ] || fail "installer must be root-owned"
self_mode=$(stat -c %a "$self")
case "$self_mode" in
    500|550|555) ;;
    *) fail "installer mode must be 0500, 0550, or 0555" ;;
esac
ancestor=$(dirname -- "$self")
while :; do
    [ "$(stat -c %u "$ancestor")" -eq 0 ] || fail "installer has a non-root ancestor"
    ancestor_mode=$(stat -c %a "$ancestor")
    ancestor_mode_value=$((0$ancestor_mode))
    [ $((ancestor_mode_value & 022)) -eq 0 ] || fail "installer has a writable ancestor"
    [ "$ancestor" = / ] && break
    ancestor=$(dirname -- "$ancestor")
done

wheel=$1
operator=$2
expected_sha256=$3
codex_closure_sha256=$4
wheel_name=$(basename -- "$wheel")
[ "$wheel_name" = agent_loop-1.1.0-py3-none-any.whl ] || \
    fail "wheel filename must be agent_loop-1.1.0-py3-none-any.whl"
case "$wheel" in
    /*) ;;
    *) fail "wheel path must be absolute" ;;
esac
case "$expected_sha256" in
    *[!0-9a-f]*|'') fail "expected wheel SHA-256 is malformed" ;;
esac
[ "${#expected_sha256}" -eq 64 ] || fail "expected wheel SHA-256 is malformed"
case "$codex_closure_sha256" in
    *[!0-9a-f]*|'') fail "normalized Codex closure SHA-256 is malformed" ;;
esac
[ "${#codex_closure_sha256}" -eq 64 ] || \
    fail "normalized Codex closure SHA-256 is malformed"
[ -f "$wheel" ] || fail "wheel is missing"
operator_uid=$(id -u "$operator") || fail "operator account is missing"
[ "$operator_uid" -gt 0 ] || fail "operator must be unprivileged"

source_before=$(sha256sum -- "$wheel" | cut -d ' ' -f 1)
[ "$source_before" = "$expected_sha256" ] || fail "wheel hash differs from reviewed value"

install_root=/opt/agent-loop-author-service
socket_unit=/etc/systemd/system/agent-loop-author.socket
service_unit=/etc/systemd/system/agent-loop-author@.service
config_directory=/etc/agent-loop
config_file=$config_directory/author-service.conf
install_record=$config_directory/author-service-install.txt
uninstall_marker=$config_directory/author-service-uninstall.txt
dropin_directory=/etc/systemd/system/agent-loop-author.socket.d
dropin_file=$dropin_directory/operator.conf
wants_directory=/etc/systemd/system/sockets.target.wants
enable_link=$wants_directory/agent-loop-author.socket
runtime_directory=/run/agent-loop
runtime_socket=/run/agent-loop/author.sock

# This is a one-time bootstrap, never an upgrade operation.  Complete this
# preflight before creating staging state so a stale/partial installation is
# rejected without touching any existing path.
safe_shared_directory /opt
safe_shared_directory /etc
safe_shared_directory /etc/systemd
safe_shared_directory /etc/systemd/system
safe_shared_directory /run
absent "$install_root"
absent "$socket_unit"
absent "$service_unit"
absent "$config_file"
absent "$install_record"
absent "$uninstall_marker"
absent "$dropin_directory"
absent "$dropin_file"
absent "$enable_link"
absent "$runtime_socket"
if [ -e "$config_directory" ] || [ -L "$config_directory" ]; then
    safe_shared_directory "$config_directory"
fi
if [ -e "$wants_directory" ] || [ -L "$wants_directory" ]; then
    safe_shared_directory "$wants_directory"
fi
# systemd owns creation of this directory for ListenStream.  It is never added
# to created_directories or removed by this installer because other runtime
# state may legitimately share it.
if [ -e "$runtime_directory" ] || [ -L "$runtime_directory" ]; then
    safe_shared_directory "$runtime_directory"
fi

committed=0
install_root_created=0
created_files=
created_directories=
temporary_files=
staging=

rollback() {
    status=$?
    trap - 0 HUP INT TERM
    if [ "$committed" -eq 1 ]; then
        exit "$status"
    fi
    set +e
    if [ "$install_root_created" -eq 1 ]; then
        /usr/bin/systemctl stop agent-loop-author.socket >/dev/null 2>&1
        /usr/bin/systemctl disable agent-loop-author.socket >/dev/null 2>&1
        if [ -L "$enable_link" ] && \
            [ "$(readlink -f -- "$enable_link" 2>/dev/null)" = "$socket_unit" ]; then
            rm -f -- "$enable_link"
        fi
        [ ! -e "$runtime_socket" ] && [ ! -L "$runtime_socket" ] || \
            rm -f -- "$runtime_socket"
    fi
    for created_file in $created_files; do
        rm -f -- "$created_file"
    done
    if [ "$install_root_created" -eq 1 ]; then
        chmod -R u+w -- "$install_root" >/dev/null 2>&1
        rm -rf -- "$install_root"
    fi
    if [ -n "$staging" ]; then
        chmod -R u+w -- "$staging" >/dev/null 2>&1
        rm -rf -- "$staging"
    fi
    for temporary_file in $temporary_files; do
        rm -f -- "$temporary_file"
    done
    if [ "$install_root_created" -eq 1 ]; then
        /usr/bin/systemctl daemon-reload >/dev/null 2>&1
    fi
    # Directories are prepended when created, so children are attempted first.
    # rmdir deliberately preserves any directory that is no longer empty.
    for created_directory in $created_directories; do
        rmdir -- "$created_directory" >/dev/null 2>&1
    done
    exit "$status"
}

trap rollback 0
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

ensure_shared_directory() {
    directory=$1
    if [ -e "$directory" ] || [ -L "$directory" ]; then
        safe_shared_directory "$directory"
        return
    fi
    mkdir -m 0755 -- "$directory"
    created_directories="$directory $created_directories"
}

install_absent_file() {
    source_file=$1
    target_file=$2
    target_mode=$3
    absent "$target_file"
    target_parent=$(dirname -- "$target_file")
    temporary_file=$(mktemp "$target_parent/.agent-loop-author-install.XXXXXX")
    temporary_files="$temporary_file $temporary_files"
    install -o root -g root -m "$target_mode" -- "$source_file" "$temporary_file"
    # A hard link publishes the fully-written file atomically and refuses to
    # replace a target that appeared after the initial preflight.
    ln -- "$temporary_file" "$target_file" || \
        fail "$target_file appeared during installation; refusing to overwrite it"
    created_files="$target_file $created_files"
    rm -f -- "$temporary_file"
}

staging=$(mktemp -d /opt/agent-loop-author-service.install.XXXXXX)
wheel_copy=$staging/$wheel_name
install -o root -g root -m 0444 -- "$wheel" "$wheel_copy"
source_after=$(sha256sum -- "$wheel" | cut -d ' ' -f 1)
copy_before=$(sha256sum -- "$wheel_copy" | cut -d ' ' -f 1)
[ "$source_before" = "$source_after" ] || fail "wheel changed while being copied"
[ "$copy_before" = "$expected_sha256" ] || fail "root-owned wheel copy failed verification"

/usr/bin/python3 -m venv "$staging/runtime"
"$staging/runtime/bin/python" -m pip install --no-deps --no-index "$wheel_copy"
copy_after=$(sha256sum -- "$wheel_copy" | cut -d ' ' -f 1)
[ "$copy_after" = "$expected_sha256" ] || fail "wheel changed during installation"
chown -R root:root "$staging"
chmod -R go-w "$staging"
find "$staging" -type d -exec chmod 0755 {} +
runtime_package=$staging/runtime/lib/python3.14/site-packages/agent_loop
[ -d "$runtime_package" ] || fail "installed wheel omitted the agent_loop runtime package"
find "$runtime_package" -type d -exec chmod 0555 {} +
find "$runtime_package" -type f -exec chmod 0444 {} +
asset_root=$staging/runtime/share/agent-loop/support/author-service
[ -d "$asset_root" ] || fail "installed wheel omitted fixed author-service assets"
# pip honors the invoking root shell's umask when materializing wheel data.
# Normalize the two templates inspected at runtime so a defensive 0077 umask
# cannot make the reviewed assets unreadable to the authorized operator.
chmod 0644 \
    "$asset_root/agent-loop-author.socket" \
    "$asset_root/agent-loop-author@.service"

package_version=$($staging/runtime/bin/python -c \
    'import importlib.metadata; print(importlib.metadata.version("agent-loop"))')
[ "$package_version" = 1.1.0 ] || fail "installed package version is not exactly 1.1.0"

# Generate all configuration inputs before publishing the immutable install.
umask 077
{
    printf 'AGENT_LOOP_AUTHOR_ALLOWED_UID=%s\n' "$operator_uid"
    printf 'AGENT_LOOP_AUTHOR_CODEX_CLOSURE_SHA256=%s\n' "$codex_closure_sha256"
} > "$staging/author-service.conf"

{
    printf '%s\n' '[Socket]'
    printf 'SocketUser=%s\n' "$operator_uid"
    printf '%s\n' 'SocketGroup=root' 'SocketMode=0600'
} > "$staging/operator.conf"

{
    printf 'wheel_sha256=%s\n' "$expected_sha256"
    printf 'package_version=%s\n' "$package_version"
    printf 'operator_uid=%s\n' "$operator_uid"
    printf 'codex_closure_sha256=%s\n' "$codex_closure_sha256"
} > "$staging/author-service-install.txt"

# Publish the install root first; every subsequent path is recorded immediately
# after creation so the EXIT trap can remove only this invocation's work.
staging_identity=$(stat -c '%d:%i' "$staging")
mv -T -n -- "$staging" "$install_root"
[ ! -e "$staging" ] || fail "$install_root appeared during installation"
install_root_created=1
[ "$(stat -c '%d:%i' "$install_root")" = "$staging_identity" ] || \
    fail "published install root did not match the verified staging directory"
staging=
asset_root=$install_root/runtime/share/agent-loop/support/author-service

ensure_shared_directory "$config_directory"
ensure_shared_directory "$dropin_directory"
ensure_shared_directory "$wants_directory"
install_absent_file "$asset_root/agent-loop-author.socket" "$socket_unit" 0644
install_absent_file "$asset_root/agent-loop-author@.service" "$service_unit" 0644
install_absent_file "$install_root/author-service.conf" "$config_file" 0644
install_absent_file "$install_root/operator.conf" "$dropin_file" 0644
install_absent_file "$install_root/author-service-install.txt" "$install_record" 0644
rm -f -- \
    "$install_root/author-service.conf" \
    "$install_root/operator.conf" \
    "$install_root/author-service-install.txt"

/usr/bin/systemd-analyze verify "$socket_unit" "$service_unit"
/usr/bin/systemctl daemon-reload
/usr/bin/systemctl enable agent-loop-author.socket
[ -L "$enable_link" ] || fail "systemctl did not create the expected socket enable link"
[ "$(readlink -f -- "$enable_link")" = "$socket_unit" ] || \
    fail "systemctl created an unexpected socket enable link"
/usr/bin/systemctl start agent-loop-author.socket

committed=1
trap - 0 HUP INT TERM
echo "installed fixed author broker for UID $operator_uid; ordinary runs need no sudo" >&2
