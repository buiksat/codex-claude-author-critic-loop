#!/bin/sh
set -eu
set -f

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
LC_ALL=C
export LC_ALL
unset CDPATH ENV BASH_ENV PYTHONPATH PYTHONHOME

fail() { echo "agent-loop author uninstall: $*" >&2; exit 2; }

safe_root_file() {
    path=$1
    mode=$2
    [ -f "$path" ] && [ ! -L "$path" ] || fail "$path is not a regular file"
    [ "$(stat -c %u "$path")" -eq 0 ] && [ "$(stat -c %g "$path")" -eq 0 ] || \
        fail "$path is not root-owned"
    [ "$(stat -c %a "$path")" = "$mode" ] || fail "$path has an unexpected mode"
    [ "$(stat -c %h "$path")" -eq 1 ] || fail "$path has an unexpected link count"
}

safe_root_directory() {
    path=$1
    [ -d "$path" ] && [ ! -L "$path" ] || fail "$path is not a real directory"
    [ "$(stat -c %u "$path")" -eq 0 ] && [ "$(stat -c %g "$path")" -eq 0 ] || \
        fail "$path is not root-owned"
    directory_mode=$(stat -c %a "$path")
    directory_mode_value=$((0$directory_mode))
    [ $((directory_mode_value & 022)) -eq 0 ] || fail "$path is group/world writable"
}

sha256_file() { sha256sum -- "$1" | cut -d ' ' -f 1; }

record_value() {
    name=$1
    file=$2
    value=$(sed -n "s/^${name}=//p" "$file")
    [ -n "$value" ] || fail "$file omits $name"
    [ "$(grep -c "^${name}=" "$file")" -eq 1 ] || fail "$file repeats $name"
    printf '%s\n' "$value"
}

valid_sha256() {
    value=$1
    case "$value" in
        *[!0-9a-f]*|'') return 1 ;;
    esac
    [ "${#value}" -eq 64 ]
}

[ "$(id -u)" -eq 0 ] || fail "uninstaller must run as root"
[ "$#" -eq 1 ] || fail "usage: ROOT_OWNED_UNINSTALLER EXPECTED_INSTALLED_WHEEL_SHA256"
expected_wheel_sha256=$1
valid_sha256 "$expected_wheel_sha256" || fail "expected installed wheel SHA-256 is malformed"

self=$(readlink -f -- "$0") || fail "cannot resolve uninstaller path"
[ -f "$self" ] || fail "uninstaller path is not a regular file"
[ "$(stat -c %u "$self")" -eq 0 ] || fail "uninstaller must be root-owned"
self_mode=$(stat -c %a "$self")
case "$self_mode" in
    500|550|555) ;;
    *) fail "uninstaller mode must be 0500, 0550, or 0555" ;;
esac
ancestor=$(dirname -- "$self")
while :; do
    [ "$(stat -c %u "$ancestor")" -eq 0 ] || fail "uninstaller has a non-root ancestor"
    ancestor_mode=$(stat -c %a "$ancestor")
    ancestor_mode_value=$((0$ancestor_mode))
    [ $((ancestor_mode_value & 022)) -eq 0 ] || fail "uninstaller has a writable ancestor"
    [ "$ancestor" = / ] && break
    ancestor=$(dirname -- "$ancestor")
done

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
runtime_socket=$runtime_directory/author.sock
reviewed_wheel=$install_root/agent_loop-1.1.0-py3-none-any.whl
installed_asset_root=$install_root/runtime/share/agent-loop/support/author-service
installed_socket_asset=$installed_asset_root/agent-loop-author.socket
installed_service_asset=$installed_asset_root/agent-loop-author@.service

for directory in /opt /etc /etc/systemd /etc/systemd/system "$config_directory" \
    "$wants_directory" /run "$runtime_directory"; do
    safe_root_directory "$directory"
done

if [ ! -e "$uninstall_marker" ] && [ ! -L "$uninstall_marker" ]; then
    safe_root_directory "$install_root"
    safe_root_file "$install_record" 644
    safe_root_file "$config_file" 644
    safe_root_file "$socket_unit" 644
    safe_root_file "$service_unit" 644
    safe_root_file "$dropin_file" 644
    safe_root_file "$reviewed_wheel" 444
    safe_root_file "$installed_socket_asset" 644
    safe_root_file "$installed_service_asset" 644

    [ "$(sha256_file "$reviewed_wheel")" = "$expected_wheel_sha256" ] || \
        fail "installed reviewed wheel differs from the expected digest"
    [ "$(record_value wheel_sha256 "$install_record")" = "$expected_wheel_sha256" ] || \
        fail "install record names a different wheel"
    [ "$(record_value package_version "$install_record")" = 1.1.0 ] || \
        fail "installed package version is not exactly 1.1.0"
    operator_uid=$(record_value operator_uid "$install_record")
    case "$operator_uid" in *[!0-9]*|'') fail "installed operator UID is malformed" ;; esac
    [ "$operator_uid" -gt 0 ] || fail "installed operator UID must be unprivileged"
    codex_closure_sha256=$(record_value codex_closure_sha256 "$install_record")
    valid_sha256 "$codex_closure_sha256" || fail "installed Codex closure digest is malformed"
    [ "$(record_value AGENT_LOOP_AUTHOR_ALLOWED_UID "$config_file")" = "$operator_uid" ] || \
        fail "installed configuration names a different operator"
    [ "$(record_value AGENT_LOOP_AUTHOR_CODEX_CLOSURE_SHA256 "$config_file")" = \
        "$codex_closure_sha256" ] || fail "installed Codex closure configuration changed"
    [ "$(wc -l < "$install_record")" -eq 4 ] || fail "install record has extra fields"
    [ "$(wc -l < "$config_file")" -eq 2 ] || fail "installed configuration has extra fields"
    cmp -s -- "$socket_unit" "$installed_socket_asset" || \
        fail "installed socket unit differs from its reviewed asset"
    cmp -s -- "$service_unit" "$installed_service_asset" || \
        fail "installed service unit differs from its reviewed asset"
    expected_dropin=$(printf \
        '[Socket]\nSocketUser=%s\nSocketGroup=root\nSocketMode=0600' "$operator_uid")
    [ "$(cat "$dropin_file")" = "$expected_dropin" ] || \
        fail "installed socket policy changed"
    if [ -e "$enable_link" ] || [ -L "$enable_link" ]; then
        [ -L "$enable_link" ] && \
            [ "$(readlink -f -- "$enable_link")" = "$socket_unit" ] || \
            fail "installed enable link changed"
    fi

    # Publish a small root-only transaction witness before changing systemd or
    # deleting anything.  If the process is interrupted, a later invocation can
    # validate every surviving target against these hashes and finish safely.
    marker_temporary=$(mktemp "$config_directory/.agent-loop-author-uninstall.XXXXXX")
    cleanup_marker_temporary() {
        status=$?
        trap - 0 HUP INT TERM
        rm -f -- "$marker_temporary"
        exit "$status"
    }
    trap cleanup_marker_temporary 0
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM
    umask 077
    {
        printf 'format=1\n'
        printf 'wheel_sha256=%s\n' "$expected_wheel_sha256"
        printf 'install_root_device=%s\n' "$(stat -c %d "$install_root")"
        printf 'install_root_inode=%s\n' "$(stat -c %i "$install_root")"
        printf 'socket_unit_sha256=%s\n' "$(sha256_file "$socket_unit")"
        printf 'service_unit_sha256=%s\n' "$(sha256_file "$service_unit")"
        printf 'config_sha256=%s\n' "$(sha256_file "$config_file")"
        printf 'install_record_sha256=%s\n' "$(sha256_file "$install_record")"
        printf 'dropin_sha256=%s\n' "$(sha256_file "$dropin_file")"
    } > "$marker_temporary"
    chown root:root "$marker_temporary"
    chmod 0600 "$marker_temporary"
    ln -- "$marker_temporary" "$uninstall_marker" || \
        fail "uninstall transaction appeared concurrently"
    rm -f -- "$marker_temporary"
    trap - 0 HUP INT TERM
else
    safe_root_file "$uninstall_marker" 600
fi

safe_root_file "$uninstall_marker" 600
[ "$(wc -l < "$uninstall_marker")" -eq 9 ] || fail "uninstall transaction is malformed"
[ "$(record_value format "$uninstall_marker")" = 1 ] || \
    fail "uninstall transaction format changed"
[ "$(record_value wheel_sha256 "$uninstall_marker")" = "$expected_wheel_sha256" ] || \
    fail "uninstall transaction names a different wheel"

for field in socket_unit_sha256 service_unit_sha256 config_sha256 \
    install_record_sha256 dropin_sha256; do
    valid_sha256 "$(record_value "$field" "$uninstall_marker")" || \
        fail "uninstall transaction contains a malformed digest"
done
for field in install_root_device install_root_inode; do
    value=$(record_value "$field" "$uninstall_marker")
    case "$value" in *[!0-9]*|'') fail "uninstall transaction contains malformed identity" ;; esac
done

check_remaining_file() {
    path=$1
    mode=$2
    digest_field=$3
    if [ -e "$path" ] || [ -L "$path" ]; then
        safe_root_file "$path" "$mode"
        [ "$(sha256_file "$path")" = "$(record_value "$digest_field" "$uninstall_marker")" ] || \
            fail "$path changed after uninstall began"
    fi
}

check_remaining_file "$socket_unit" 644 socket_unit_sha256
check_remaining_file "$service_unit" 644 service_unit_sha256
check_remaining_file "$config_file" 644 config_sha256
check_remaining_file "$install_record" 644 install_record_sha256
check_remaining_file "$dropin_file" 644 dropin_sha256
if [ -e "$install_root" ] || [ -L "$install_root" ]; then
    safe_root_directory "$install_root"
    [ "$(stat -c %d "$install_root")" = \
        "$(record_value install_root_device "$uninstall_marker")" ] && \
        [ "$(stat -c %i "$install_root")" = \
        "$(record_value install_root_inode "$uninstall_marker")" ] || \
        fail "install root identity changed after uninstall began"
    # An interrupted recursive removal may already have unlinked the wheel.
    # If it survives, it must still be the reviewed file; otherwise the
    # transaction witness plus the unchanged install-root inode confines the
    # resumed deletion.
    if [ -e "$reviewed_wheel" ] || [ -L "$reviewed_wheel" ]; then
        safe_root_file "$reviewed_wheel" 444
        [ "$(sha256_file "$reviewed_wheel")" = "$expected_wheel_sha256" ] || \
            fail "reviewed wheel changed after uninstall began"
    fi
fi
if [ -e "$enable_link" ] || [ -L "$enable_link" ]; then
    [ -L "$enable_link" ] && [ "$(readlink -f -- "$enable_link")" = "$socket_unit" ] || \
        fail "installed enable link changed"
fi

if [ -e "$socket_unit" ] || [ -L "$socket_unit" ]; then
    /usr/bin/systemctl stop agent-loop-author.socket
    # Accept=yes broker instances and already-started author jobs outlive their
    # listening socket.  Re-snapshot and stop both fixed name classes until no
    # loaded instance remains.  This avoids treating an empty systemd glob as a
    # fatal missing-unit error while still failing closed on a real stop error.
    stop_round=0
    remaining_units=initial
    while [ "$stop_round" -lt 5 ]; do
        stop_round=$((stop_round + 1))
        unit_listing=$(/usr/bin/systemctl list-units --all --plain --no-legend \
            --no-pager 'agent-loop-author@*.service' \
            'agent-loop-author-[0-9]*.service') || \
            fail "cannot enumerate remaining fixed author units"
        remaining_units=
        unit_count=0
        while IFS= read -r unit_line; do
            set -- $unit_line
            [ "$#" -gt 0 ] || continue
            case "$1" in
                *.service) unit_name=$1 ;;
                *)
                    [ "$#" -ge 2 ] || fail "systemd returned malformed unit output"
                    unit_name=$2
                    ;;
            esac
            case "$unit_name" in
                agent-loop-author@*.service|agent-loop-author-[0-9]*.service) ;;
                *) fail "systemd returned an unexpected author unit name" ;;
            esac
            unit_count=$((unit_count + 1))
            [ "$unit_count" -le 128 ] || fail "too many fixed author units remain"
            remaining_units="$remaining_units $unit_name"
        done <<AGENT_LOOP_FIXED_UNITS
$unit_listing
AGENT_LOOP_FIXED_UNITS
        [ -n "$remaining_units" ] || break
        for unit_name in $remaining_units; do
            /usr/bin/systemctl stop "$unit_name"
        done
    done
    [ -z "$remaining_units" ] || fail "fixed author units survived bounded shutdown"
elif [ -e "$runtime_socket" ] || [ -L "$runtime_socket" ]; then
    fail "author socket remains although its fixed unit is absent"
fi
if [ -e "$enable_link" ] || [ -L "$enable_link" ]; then
    /usr/bin/systemctl disable agent-loop-author.socket
fi
[ ! -e "$runtime_socket" ] && [ ! -L "$runtime_socket" ] || \
    fail "author socket survived fixed-unit shutdown"
[ ! -e "$enable_link" ] && [ ! -L "$enable_link" ] || \
    fail "author socket enable link survived disable"

rm -f -- "$socket_unit" "$service_unit" "$config_file" "$dropin_file" "$install_record"
rmdir -- "$dropin_directory" 2>/dev/null || :
if [ -e "$install_root" ] || [ -L "$install_root" ]; then
    [ -d "$install_root" ] && [ ! -L "$install_root" ] || \
        fail "install root changed before deletion"
    # The installed Python package is deliberately normalized to read-only
    # directories.  Make only directories on this exact filesystem writable;
    # a nested mount is neither traversed here nor crossed by rm below.
    find "$install_root" -xdev -type d -exec chmod u+w -- {} +
    rm -rf --one-file-system -- "$install_root"
fi
[ ! -e "$install_root" ] && [ ! -L "$install_root" ] || \
    fail "install root could not be removed without crossing a filesystem"

/usr/bin/systemctl daemon-reload
rm -f -- "$uninstall_marker"

echo "removed the exact fixed author broker installation; shared state was preserved" >&2
