# Outcrop

[日本語](README.md) | English

Generate an SBOM from Linux filesystems with Syft and assess vulnerabilities with Grype. A privileged Worker reads disks; a separate Web process displays the results.

## Requirements

- Host: Ubuntu Server 22.04 / 24.04 LTS, amd64, Perl 5.34 or later.
- Run Worker as root and Web as a dedicated unprivileged user.
- Install Syft, Grype, `lsblk`, `findmnt`, `mount`, `umount`, and XFS tools.
- Clone disks must use ext4 or XFS on a single disk. LVM and RAID are unsupported. GPT BIOS boot partitions may coexist but are excluded from scanning.

The target OS may differ from the host OS. Outcrop reads package information from systems such as Ubuntu and CentOS without executing target code. Package detection continues even if the OS cannot be identified.

## Installation

```sh
sudo apt update
sudo apt install perl cpanminus build-essential git curl ca-certificates util-linux mount xfsprogs
```

### External tools

CPAN installation does not download Syft or Grype, create users, or register services.

```sh
outcrop_download_dir=$(mktemp -d)
cd "$outcrop_download_dir"

# Syft
curl -fLO https://github.com/anchore/syft/releases/download/v1.55.0/syft_1.55.0_linux_amd64.tar.gz
curl -fLO https://github.com/anchore/syft/releases/download/v1.55.0/syft_1.55.0_checksums.txt
sha256sum --check --ignore-missing syft_1.55.0_checksums.txt && \
  tar -xzf syft_1.55.0_linux_amd64.tar.gz syft && \
  sudo install -o root -g root -m 0755 syft /usr/local/bin/syft

# Grype
curl -fLO https://github.com/anchore/grype/releases/download/v0.121.0/grype_0.121.0_linux_amd64.tar.gz
curl -fLO https://github.com/anchore/grype/releases/download/v0.121.0/grype_0.121.0_checksums.txt
sha256sum --check --ignore-missing grype_0.121.0_checksums.txt && \
  tar -xzf grype_0.121.0_linux_amd64.tar.gz grype && \
  sudo install -o root -g root -m 0755 grype /usr/local/bin/grype
```

### CPAN installation

Install Outcrop and its dependencies in a dedicated prefix. Set `outcrop_prefix` to an absolute path managed by root. Before the first CPAN release, use a local distribution archive.

```sh
outcrop_prefix=/opt/outcrop-perl

# After the CPAN release, replace the archive name with App::Outcrop
sudo cpanm --local-lib-contained "$outcrop_prefix" --exclude-vendor ./App-Outcrop-0.01.tar.gz

# Apply these permissions only to the dedicated prefix
sudo chown -R root:root "$outcrop_prefix"
sudo chmod -R go-w "$outcrop_prefix"
export PATH="$outcrop_prefix/bin:$PATH"

outcrop --version
outcrop_exec="$outcrop_prefix/bin/outcrop"
outcrop_working_dir=/
outcrop_units_dir="$outcrop_prefix/lib/perl5/App/Outcrop/share/systemd"
```

The installed CLI loads modules from its dedicated prefix and Perl's core libraries. It does not use shared site or vendor libraries or require `PERL5LIB`. Worker checks that the prefix, parent directories, loaded code, and external tools are owned by root and deny group and other writes. Symlinks inside the prefix are unsupported. Do not start Worker from a user-owned prefix.

### GitHub installation

Set `outcrop_source` to a location managed by root. This example uses `/opt/outcrop`.

```sh
sudo apt install carton
outcrop_source=/opt/outcrop
sudo git clone https://github.com/viasnake/outcrop.git "$outcrop_source"
cd "$outcrop_source"
sudo sh -c 'umask 0022; PERL_CARTON_MIRROR=https://cpan.metacpan.org /usr/bin/carton install --deployment --without develop'
sudo chown -R root:root "$outcrop_source"
sudo chmod -R go-w "$outcrop_source"
outcrop_units_dir="$outcrop_source/systemd"
outcrop_exec="/usr/bin/carton exec /usr/bin/perl script/outcrop"
outcrop_working_dir="$outcrop_source"
```

### Start with systemd

Run these commands in the shell where you set the variables for your chosen installation. They set the actual `ExecStart` and `WorkingDirectory` paths. Installation paths must not contain spaces or systemd special characters. Remove any `source.conf` overrides created by earlier installation instructions from both services' `.service.d` directories before switching.

```sh
sudo useradd --system --user-group --home-dir /nonexistent --shell /usr/sbin/nologin outcrop
for mode in worker web; do
  sed -e "s|^ExecStart=.*|ExecStart=$outcrop_exec $mode|" \
      -e "s|^WorkingDirectory=.*|WorkingDirectory=$outcrop_working_dir|" \
      "$outcrop_units_dir/outcrop-$mode.service" | \
    sudo tee "/etc/systemd/system/outcrop-$mode.service" >/dev/null
done
sudo systemctl daemon-reload
sudo systemctl enable --now outcrop-worker.service outcrop-web.service
sudo systemctl --no-pager --full status outcrop-worker.service outcrop-web.service
```

For manual operation, stop the services and start Worker first. This example uses the CPAN installation. For a GitHub installation, run from the installation directory and replace `outcrop` with `carton exec perl script/outcrop`.

```sh
sudo install -d -o outcrop -g outcrop -m 0750 /run/outcrop-web
sudo "$outcrop_prefix/bin/outcrop" worker
# In another terminal
sudo -u outcrop "$outcrop_prefix/bin/outcrop" web
```

## Usage and limitations

The interface supports Japanese and English. On your first visit, it follows your browser's language preference and defaults to English for unsupported languages. Choose **日本語** or **English** from the language dropdown in the header to save your choice in the browser for one year. Dates remain in UTC. Scan results, logs, tags, and notes retain their original content.

Open [http://127.0.0.1:8080](http://127.0.0.1:8080) on the host. By default, Web accepts connections only from localhost. Use SSH port forwarding from another machine, or explicitly configure a remote listener when LAN access is required.

```sh
sudo systemctl edit outcrop-web.service
```

```ini
[Service]
Environment=OUTCROP_LISTEN=http://0.0.0.0:8080
```

```sh
sudo systemctl restart outcrop-web.service
```

For LAN access, open `http://<host IP address or hostname>:8080`. Outcrop has no authentication; restrict access to trusted machines with a firewall or equivalent controls.

Attach an independent clone to a dedicated VM with automatic mounting disabled, select the disk, and start a scan. Confirm it is unmounted before disconnecting it. Scans of the host itself exclude virtual filesystems, other mounts, and Outcrop's storage.

Inaccessible locations produce warnings identifying the path and reason, and scanning continues for the available scope. Outcrop does not mount NFS, EFS, or separate filesystems such as `/usr` or `/var`. “Completed” means processing finished for the inspected scope. Scanning stops if disk identity or read-only state cannot be verified, or if unmounting fails.

Only root-relative `/var/log`, `/var/crash`, and `/var/lib/systemd/coredump` are excluded. Package data, applications, user files, caches, and temporary files remain included. These exclusions do not apply to matching directory names inside applications or to symlinks pointing elsewhere.

Results, queues, tags, and notes are stored in `/var/lib/outcrop`; runtime files use `/run/outcrop` and `/run/outcrop-web`. GitHub and CPAN installations share the same storage paths and formats. Allow additional disk space for result-list SQLite databases and Grype databases.

The default concurrency is two scans, configurable from 1 to 64. Wait for running scans to finish before changing it.

```sh
sudo systemctl edit outcrop-worker.service
```

```ini
[Service]
Environment=OUTCROP_WORKER_JOBS=4
```

```sh
sudo systemctl daemon-reload
sudo systemctl restart outcrop-worker.service
```

Restarting interrupts running scans and attempts to unmount their filesystems. Interrupted scans are not replayed automatically; queued requests resume after restart. Each execution slot has its own Grype cache.

## Updating

Wait for running scans to finish, then stop both services.

```sh
sudo systemctl stop outcrop-web.service outcrop-worker.service
```

For a CPAN installation, install the new archive or CPAN version into the same dedicated prefix using the installation steps, then restore the prefix ownership and permissions.

For a GitHub installation, update the checkout and restore ownership and permissions.

```sh
cd /opt/outcrop  # Use the actual installation path
sudo sh -eu <<'SH'
umask 0022
git pull --ff-only
PERL_CARTON_MIRROR=https://cpan.metacpan.org /usr/bin/carton install --deployment --without develop
chown -R root:root .
chmod -R go-w .
SH
```

If service definitions changed, regenerate them with the installation variables and commands before starting. If Worker reports `Root must own ... and deny group/other writes`, inspect ownership and permissions on the reported path and its parent directories.

```sh
sudo systemctl daemon-reload
sudo systemctl start outcrop-worker.service outcrop-web.service
sudo systemctl --no-pager --full status outcrop-worker.service outcrop-web.service

# Reload Web-only code changes
sudo systemctl reload outcrop-web.service
```

## Development and distribution

```sh
# Requires mise and build-essential
mise trust
mise install
mise run setup
mise run test
mise run format:check

# Build a distribution archive after installing dependencies
perl Makefile.PL
make
make test
make disttest
make dist
```

The main Perl tests do not require root or real disks. Set `OUTCROP_TEST_SYFT=/usr/local/bin/syft mise run test` for additional checks using an actual Syft executable.

```sh
# Japanese/English display and browser-cache tests (Node.js 22 or later)
npm ci
npx playwright install chromium
mise run test:results

# Benchmark large results; outputs are written to var/results-benchmark/
carton exec perl script/benchmark-results
```

## License

[Apache-2.0](LICENSE)
