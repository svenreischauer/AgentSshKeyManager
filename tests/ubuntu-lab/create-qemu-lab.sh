#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
    echo "usage: create-qemu-lab.sh TARGET_MOUNT EXPECTED_UUID HOST_SSH_PORT" >&2
    exit 64
fi

target_mount=$1
expected_uuid=$2
host_ssh_port=$3
vm_name=agent-ssh-acceptance
image_name=ubuntu-24.04-server-cloudimg-amd64.img
image_base_url=https://cloud-images.ubuntu.com/releases/server/24.04/release

if [[ $EUID -ne 0 ]]; then
    echo "run as root" >&2
    exit 77
fi
if [[ ! $host_ssh_port =~ ^[0-9]+$ ]] || (( host_ssh_port < 1024 || host_ssh_port > 65535 )); then
    echo "invalid host SSH port" >&2
    exit 64
fi
if [[ ! $expected_uuid =~ ^[0-9a-fA-F-]{36}$ ]]; then
    echo "invalid expected filesystem UUID" >&2
    exit 64
fi

target_mount=$(readlink -f -- "$target_mount")
[[ -d $target_mount ]] || { echo "target mount does not exist" >&2; exit 78; }
[[ $target_mount =~ ^/[A-Za-z0-9._/-]+$ ]] || { echo "unsupported target mount path" >&2; exit 78; }
actual_uuid=$(findmnt -n -o UUID --target "$target_mount" | awk 'NF { value=$1 } END { print value }')
if [[ $actual_uuid != "$expected_uuid" ]]; then
    echo "refusing target: filesystem UUID does not match" >&2
    exit 78
fi
if ss -H -ltn "sport = :$host_ssh_port" | grep -q .; then
    echo "refusing target: host port is already in use" >&2
    exit 78
fi

for command_name in qemu-img qemu-system-x86_64 cloud-localds curl sha256sum puttygen openssl systemctl; do
    command -v "$command_name" >/dev/null 2>&1 || {
        echo "missing required command: $command_name" >&2
        exit 69
    }
done
[[ -c /dev/kvm ]] || { echo "/dev/kvm is unavailable" >&2; exit 69; }

images_dir=$target_mount/images
guest_parent=$target_mount/guest
logs_dir=$target_mount/logs
guest_dir=$guest_parent/$vm_name
base_image=$images_dir/$image_name
disk_image=$guest_dir/system.qcow2
seed_image=$guest_dir/seed.img
secrets_dir=$guest_dir/fixtures
service_file=/etc/systemd/system/$vm_name.service

for target_dir in "$images_dir" "$guest_parent" "$logs_dir"; do
    if [[ -L $target_dir ]]; then
        echo "refusing a symlinked lab directory" >&2
        exit 78
    elif [[ -d $target_dir ]]; then
        [[ $(readlink -f -- "$target_dir") == "$target_dir" ]] || {
            echo "refusing a redirected lab directory" >&2
            exit 78
        }
    else
        install -d -m 0750 -o root -g root "$target_dir"
    fi
done
if [[ -e $guest_dir || -L $guest_dir || -e $service_file || -L $service_file ]]; then
    echo "refusing to overwrite an existing acceptance VM" >&2
    exit 73
fi
if [[ -L $base_image ]]; then
    echo "refusing a symlinked base image" >&2
    exit 78
fi
install -d -m 0700 -o root -g root "$guest_dir" "$secrets_dir"
resolved_guest_dir=$(readlink -f -- "$guest_dir")
expected_guest_dir=$target_mount/guest/$vm_name
if [[ $resolved_guest_dir != "$expected_guest_dir" || $resolved_guest_dir == / || $resolved_guest_dir == "$target_mount" ]]; then
    echo "refusing unsafe guest directory" >&2
    exit 78
fi

cleanup_on_error() {
    local status=$?
    if (( status != 0 )); then
        systemctl stop "$vm_name.service" >/dev/null 2>&1 || true
        rm -f "$service_file"
        systemctl daemon-reload >/dev/null 2>&1 || true
        rm -rf --one-file-system -- "$resolved_guest_dir"
    fi
    exit "$status"
}
trap cleanup_on_error EXIT

checksums=$guest_dir/SHA256SUMS
curl --fail --location --silent --show-error --retry 3 \
    "$image_base_url/SHA256SUMS" -o "$checksums"
if [[ ! -f $base_image ]]; then
    download=$guest_dir/$image_name.download
    curl --fail --location --silent --show-error --retry 3 \
        "$image_base_url/$image_name" -o "$download"
    expected_hash=$(awk -v file="$image_name" '$2 == file || $2 == "*" file { print $1; exit }' "$checksums")
    [[ $expected_hash =~ ^[0-9a-fA-F]{64}$ ]] || { echo "image checksum is unavailable" >&2; exit 65; }
    printf '%s  %s\n' "$expected_hash" "$download" | sha256sum --check --status
    mv "$download" "$base_image"
    chmod 0644 "$base_image"
else
    expected_hash=$(awk -v file="$image_name" '$2 == file || $2 == "*" file { print $1; exit }' "$checksums")
    actual_hash=$(sha256sum "$base_image" | awk '{print $1}')
    [[ $actual_hash == "$expected_hash" ]] || { echo "existing base-image checksum mismatch" >&2; exit 65; }
fi

key_passphrase=$(openssl rand -base64 30 | tr -d '\r\n')
guest_password=$(openssl rand -base64 24 | tr -d '\r\n')
printf '%s' "$key_passphrase" > "$secrets_dir/sudo-key-passphrase.txt"
printf '%s' "$guest_password" > "$secrets_dir/bootstrap-password.txt"
chmod 0600 "$secrets_dir"/*.txt

puttygen -q -t ed25519 -C agent-ssh-lab-root \
    --new-passphrase /dev/null -o "$secrets_dir/root-bootstrap.ppk"
puttygen "$secrets_dir/root-bootstrap.ppk" -O public-openssh \
    -o "$secrets_dir/root-bootstrap.pub"

puttygen -q -t ed25519 -C agent-ssh-lab-sudo \
    --new-passphrase "$secrets_dir/sudo-key-passphrase.txt" \
    -o "$secrets_dir/sudo-bootstrap-temporary.ppk"
puttygen "$secrets_dir/sudo-bootstrap-temporary.ppk" \
    --old-passphrase "$secrets_dir/sudo-key-passphrase.txt" \
    -O private-openssh-new -o "$secrets_dir/sudo-bootstrap"
puttygen "$secrets_dir/sudo-bootstrap-temporary.ppk" \
    --old-passphrase "$secrets_dir/sudo-key-passphrase.txt" \
    -O public-openssh -o "$secrets_dir/sudo-bootstrap.pub"
rm -f "$secrets_dir/sudo-bootstrap-temporary.ppk"
chmod 0600 "$secrets_dir/root-bootstrap.ppk" "$secrets_dir/sudo-bootstrap"
chmod 0644 "$secrets_dir/root-bootstrap.pub" "$secrets_dir/sudo-bootstrap.pub"

root_public_key=$(cat "$secrets_dir/root-bootstrap.pub")
sudo_public_key=$(cat "$secrets_dir/sudo-bootstrap.pub")
password_hash=$(printf '%s\n' "$guest_password" | openssl passwd -6 -stdin)

cat > "$guest_dir/user-data" <<EOF
#cloud-config
hostname: agent-ssh-ubuntu
manage_etc_hosts: true
ssh_pwauth: false
disable_root: false
users:
  - name: root
    lock_passwd: true
    ssh_authorized_keys:
      - $root_public_key
  - name: bootstrap
    gecos: Bootstrap acceptance-test user
    groups: [sudo]
    shell: /bin/bash
    lock_passwd: false
    passwd: '$password_hash'
    ssh_authorized_keys:
      - $sudo_public_key
chpasswd:
  expire: false
write_files:
  - path: /etc/ssh/sshd_config.d/90-agent-ssh-acceptance.conf
    owner: root:root
    permissions: '0644'
    content: |
      PasswordAuthentication no
      KbdInteractiveAuthentication no
      PubkeyAuthentication yes
      PermitRootLogin prohibit-password
runcmd:
  - [systemctl, restart, ssh]
EOF
chmod 0600 "$guest_dir/user-data"

cat > "$guest_dir/meta-data" <<EOF
instance-id: $vm_name-1
local-hostname: agent-ssh-ubuntu
EOF
chmod 0600 "$guest_dir/meta-data"

qemu-img create -q -f qcow2 -F qcow2 -b "$base_image" "$disk_image" 32G
cloud-localds "$seed_image" "$guest_dir/user-data" "$guest_dir/meta-data"
chmod 0600 "$disk_image" "$seed_image"

cat > "$service_file" <<EOF
[Unit]
Description=Disposable Ubuntu VM for Agent SSH Key Manager acceptance tests
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/qemu-system-x86_64 -name $vm_name -enable-kvm -machine q35,accel=kvm -cpu host -smp 2 -m 4096 -drive file=$disk_image,if=virtio,format=qcow2,cache=none -drive file=$seed_image,if=virtio,format=raw,readonly=on -netdev user,id=net0,hostfwd=tcp:0.0.0.0:$host_ssh_port-:22 -device virtio-net-pci,netdev=net0 -display none -serial file:$logs_dir/$vm_name-serial.log -monitor unix:$guest_dir/monitor.sock,server=on,wait=off -no-reboot
Restart=on-failure
RestartSec=5
TimeoutStopSec=30
KillMode=mixed

[Install]
WantedBy=multi-user.target
EOF
chmod 0644 "$service_file"
systemctl daemon-reload
systemctl enable --now "$vm_name.service"

for _ in $(seq 1 120); do
    if timeout 1 bash -c "</dev/tcp/127.0.0.1/$host_ssh_port" 2>/dev/null; then
        break
    fi
    sleep 2
done
systemctl is-active --quiet "$vm_name.service"
timeout 1 bash -c "</dev/tcp/127.0.0.1/$host_ssh_port"

rm -f "$checksums"
trap - EXIT
echo "VM_READY name=$vm_name port=$host_ssh_port storage=$guest_dir"
