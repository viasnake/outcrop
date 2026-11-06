# Outcrop

Linux ファイルシステムから Syft で SBOM を生成し、Grype で脆弱性を評価する Web アプリケーションです。ディスクを読み取る Worker と、結果を表示する Web を別プロセスで実行します。

## 対応環境

- 実行ホスト: Ubuntu Server 22.04 / 24.04 LTS、amd64、Perl 5.34 以降。
- Worker は root、Web は専用の非特権ユーザーで実行します。
- Syft、Grype、`lsblk`、`findmnt`、`mount`、`umount`、XFS ツールが必要です。
- クローンディスクは単一ディスクの ext4 / XFS に対応します。LVM・RAID は対象外です。GPT 上の BIOS boot partition は同居できますが、スキャンしません。

対象 OS は実行ホストと異なっていても構いません。Ubuntu・CentOS などのパッケージ情報を読み取り、対象 OS のコードは実行しません。OS を識別できなくてもパッケージ検出を続けます。

## インストール

```sh
sudo apt update
sudo apt install perl cpanminus build-essential git curl ca-certificates util-linux mount xfsprogs
```

### 外部 CLI

CPAN のインストール処理は Syft・Grype の取得、ユーザー作成、サービス登録を行いません。

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

### CPAN 版

初回公開前はローカルの配布アーカイブを使用します。CPAN 公開後はモジュール名でインストールできます。

```sh
# 公開前
sudo sh -c 'umask 0022; cpanm ./App-Outcrop-0.01.tar.gz'

# CPAN 公開後
sudo sh -c 'umask 0022; cpanm App::Outcrop'

outcrop --version
# Ubuntu の site ライブラリのディレクトリ権限を設定
sudo perl -MConfig -e 'exec "find", @Config{qw(installsitelib installsitearch)}, "-type", "d", "-exec", "chmod", "go-w", "{}", "+"'
outcrop_units_dir=$(perl -MApp::Outcrop::Paths -e 'print App::Outcrop::Paths::assets()->child("systemd")')
```

Worker が読み込む Perl・モジュール・外部 CLI と、それらの親ディレクトリは root 所有で、グループ・その他のユーザーによる書き込みが禁止されている必要があります。Ubuntu の標準インストーラーは site ライブラリのディレクトリをグループ書き込み可能にするため、上のコマンドで明示的に禁止します。この設定は、その Perl の site ライブラリ全体に適用されます。Worker 用には管理者が専有するシステム Perl を使い、ユーザー所有の `local::lib` を使用しないでください。

### GitHub 版

`outcrop_source` には root が管理する配置先を指定します。以下は `/opt/outcrop` を使う例です。

```sh
sudo apt install carton
outcrop_source=/opt/outcrop
sudo git clone https://github.com/viasnake/outcrop.git "$outcrop_source"
cd "$outcrop_source"
sudo sh -c 'umask 0022; PERL_CARTON_MIRROR=https://cpan.metacpan.org /usr/bin/carton install --deployment --without develop'
sudo chown -R root:root "$outcrop_source"
sudo chmod -R go-w "$outcrop_source"
outcrop_units_dir="$outcrop_source/systemd"
```

GitHub 版では、サービスに配置先と Carton 経由の起動を指定します。

```sh
sudo mkdir -p /etc/systemd/system/outcrop-worker.service.d /etc/systemd/system/outcrop-web.service.d
sudo tee /etc/systemd/system/outcrop-worker.service.d/source.conf >/dev/null <<EOF_WORKER
[Service]
WorkingDirectory=$outcrop_source
ExecStart=
ExecStart=/usr/bin/carton exec /usr/bin/perl script/outcrop worker
EOF_WORKER
sudo tee /etc/systemd/system/outcrop-web.service.d/source.conf >/dev/null <<EOF_WEB
[Service]
WorkingDirectory=$outcrop_source
ExecStart=
ExecStart=/usr/bin/carton exec /usr/bin/perl script/outcrop web
EOF_WEB
```

### systemd で起動

選んだ方式の `outcrop_units_dir` を設定したシェルで実行します。CPAN 版のサービス定義は `/usr/local/bin/outcrop` を使います。インストール先が異なる場合は `ExecStart` を実際のパスに変更してください。GitHub 版から CPAN 版へ切り替える場合は、先に上記の `source.conf` を両サービスから削除します。

```sh
sudo useradd --system --user-group --home-dir /nonexistent --shell /usr/sbin/nologin outcrop
sudo cp "$outcrop_units_dir/outcrop-worker.service" "$outcrop_units_dir/outcrop-web.service" /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now outcrop-worker.service outcrop-web.service
sudo systemctl --no-pager --full status outcrop-worker.service outcrop-web.service
```

手動で起動する場合は、サービスを停止し、Worker を先に起動します。以下は CPAN 版の例です。GitHub 版は配置先で `outcrop` を `carton exec perl script/outcrop` に置き換えます。

```sh
sudo install -d -o outcrop -g outcrop -m 0750 /run/outcrop-web
sudo outcrop worker
# 別のターミナルで実行
sudo -u outcrop outcrop web
```

## 利用と制約

`http://<実行ホストの IP アドレスまたはホスト名>:8080` を開きます。既定では `0.0.0.0:8080` で待ち受けます。認証機能はないため、ファイアウォールなどで信頼できる端末からの接続に制限してください。待受先は Web の環境変数 `OUTCROP_LISTEN` で指定できます。

自動マウントしない専用 VM に独立した複製を接続し、一覧からディスクを選んでスキャンします。取り外す前にアンマウントを確認してください。実行ホスト自身のスキャンでは、仮想ファイルシステム・別マウント・Outcrop の保存先を除外します。

探査できない場所は、場所と理由を未検査の警告に残して続行します。NFS・EFS、別の `/usr`・`/var` などは追加でマウントしません。「完了」は取得できた範囲の処理完了を表します。ディスクの同一性や読み取り専用状態を確認できない場合、アンマウントに失敗した場合は停止します。

ルート直下の `/var/log`、`/var/crash`、`/var/lib/systemd/coredump` を除外し、パッケージ情報・アプリケーション・ユーザー領域・キャッシュ・一時ファイルは保持します。アプリ内の同名ディレクトリや、別の場所を指すシンボリックリンクにはこの除外を適用しません。

結果・キュー・タグ・メモは `/var/lib/outcrop`、実行時ファイルは `/run/outcrop` と `/run/outcrop-web` に保存します。GitHub 版と CPAN 版で保存形式・保存先は共通です。結果一覧用 SQLite と Grype のデータベースにも保存容量が必要です。

既定の同時スキャン数は 2、設定範囲は 1〜64 です。実行中のスキャンが終わってから変更してください。

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

再起動は実行中のスキャンを中断し、アンマウントを試みます。中断したスキャンは自動再実行せず、待機中の要求は再起動後に処理します。Grype のキャッシュは実行枠ごとに保存します。

## 更新

実行中のスキャンが終わってから両サービスを停止します。

```sh
sudo systemctl stop outcrop-web.service outcrop-worker.service
```

CPAN 版は、インストール節の手順で新しい配布アーカイブまたは CPAN 上のバージョンをインストールし、site ライブラリのディレクトリ権限を再設定します。

GitHub 版は配置先で更新し、所有者・権限を整えます。

```sh
cd /opt/outcrop  # 実際の配置先に合わせる
sudo sh -eu <<'SH'
umask 0022
git pull --ff-only
PERL_CARTON_MIRROR=https://cpan.metacpan.org /usr/bin/carton install --deployment --without develop
chown -R root:root .
chmod -R go-w .
SH
```

サービス定義の変更がある場合は、インストール時と同様にコピーしてから起動します。`Root must own ... and deny group/other writes` が出る場合は、表示されたパスと親ディレクトリの所有者・権限を確認してください。

```sh
sudo systemctl daemon-reload
sudo systemctl start outcrop-worker.service outcrop-web.service
sudo systemctl --no-pager --full status outcrop-worker.service outcrop-web.service

# Web のコード更新だけを反映
sudo systemctl reload outcrop-web.service
```

## 開発と配布

```sh
# mise・build-essential が必要
mise trust
mise install
mise run setup
mise run test
mise run format:check

# 配布アーカイブ（依存モジュールを導入済みの環境で実行）
perl Makefile.PL
make
make test
make disttest
make dist
```

主要な Perl テストは root 権限・実ディスクを必要としません。実際の Syft を使う追加検証は `OUTCROP_TEST_SYFT=/usr/local/bin/syft mise run test` で実行できます。

```sh
# 表示キャッシュのブラウザーテスト（Node.js 22 以降）
npm ci
npx playwright install chromium
mise run test:results

# 大きな結果の測定。生成物は var/results-benchmark/ に保存
carton exec perl script/benchmark-results
```

## ライセンス

[Apache-2.0](LICENSE)
