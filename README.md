# Outcrop

実行ホスト: Ubuntu Server 22.04 / 24.04 LTS / amd64

## インストール

```sh
# パッケージ
sudo apt update
sudo apt install perl carton build-essential git curl ca-certificates util-linux mount xfsprogs
```

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

```sh
# 配置・依存の導入
sudo useradd --system --user-group --home-dir /nonexistent --shell /usr/sbin/nologin outcrop
sudo git clone https://github.com/viasnake/outcrop.git /opt/outcrop
cd /opt/outcrop
sudo env PERL_CARTON_MIRROR=https://cpan.metacpan.org \
  /usr/bin/carton install --deployment --without develop
sudo chown -R root:root /opt/outcrop
sudo chmod -R go-w /opt/outcrop

# サービスの起動
sudo cp /opt/outcrop/systemd/outcrop-worker.service /opt/outcrop/systemd/outcrop-web.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now outcrop-worker.service outcrop-web.service
```

## 利用

```sh
# 別の PC から画面を開く場合（接続先を置き換える）
ssh -N -L 8080:127.0.0.1:8080 admin@scanner-host
```

[http://127.0.0.1:8080](http://127.0.0.1:8080) を開きます。認証機能はないため、ポートは外部に公開しないでください。

クローンディスクは単一ディスクの ext4 / XFS のみ対応します。自動マウントしない専用 VM に独立した複製を接続し、アンマウントを確認してから取り外してください。

対象OSは実行ホストと同じである必要はありません。Ubuntu 18.04以降やCentOSのルートファイルシステムを、対象OSのコードを実行せずに読み取ります。`os-release` などのOS識別ファイルは必須ではなく、CentOS 6.5など、それらがない環境もスキャンします。OSの識別はSyftに任せ、識別できなくてもパッケージ検出を続けます。クローンディスクのLVM構成は対象外です。

探査できない場所は未検査の警告を残し、選択したファイルシステム上で取得できる範囲をスキャンします。`/etc/fstab` に記載されたNFS・EFSや別の `/usr`・`/var` などは追加でマウントせず、場所とファイルシステムの種類を警告に記録します。fstabや主要ディレクトリの欠落、fstabの読み取り・解析ができない場合も警告を残して続行します。警告はスキャン詳細で確認でき、「完了」は取得できた範囲の処理完了を表し、未検査領域を含む全体の検査を保証しません。ディスクの同一性や読み取り専用状態を確認できない場合、アンマウントに失敗した場合は処理を停止します。

読み取り量を減らすため、ルート直下の `/var/log`、`/var/crash`、`/var/lib/systemd/coredump` をスキャンから除外します。別ファイルシステムのログ・クラッシュ領域も対象外とし、シンボリックリンクで別の場所を指す場合はこの除外を適用しません。アプリ内の同名ディレクトリには適用しません。

`/var/lib/dpkg`、`/var/lib/rpm`、`/usr/lib/sysimage/rpm` などのパッケージ情報、`/opt`・`/srv`・ユーザー領域・キャッシュ・一時ファイルは保持します。実行ホスト自身をスキャンする場合は、仮想ファイルシステム、別マウント、Outcropの保存先も対象外です。実際に適用した除外パターンは各スキャンのメタデータに保存されます。除外の指定は[Syftのファイル選択仕様](https://oss.anchore.com/docs/guides/sbom/file-selection/)に従います。

ディスク一覧はスキャン中も約10秒ごとに検知され、画面は5秒ごとに更新されます。新しく接続したディスクを選んで「スキャン開始」を押すと、画面を移動せず追加できます。タグやメモの入力内容は一覧更新後も保持されます。

既定では最大2件を別プロセスで同時に処理し、上限を超えた要求はキューで待機します。並列数は1〜64で設定できます。1なら順次処理になります。CPU・メモリ・ディスクI/Oに合わせて調整してください。

```sh
sudo systemctl edit outcrop-worker.service
```

たとえば最大4件にする場合は、次を保存します。

```ini
[Service]
Environment=OUTCROP_WORKER_JOBS=4
```

```sh
sudo systemctl daemon-reload
sudo systemctl restart outcrop-worker.service
```

再起動は実行中のスキャンを中断し、アンマウントを試みます。中断したスキャンは自動再実行せず、待機中の要求は再起動後に処理します。並列数の変更は実行中の処理が終わってから行ってください。Grypeのデータベースは実行枠ごとのキャッシュに保存するため、初回は各枠でダウンロードが必要となり、並列数に応じて保存容量も増えます。

```sh
# Web のコード更新を反映
sudo systemctl reload outcrop-web.service

# サービスを停止
sudo systemctl stop outcrop-worker.service outcrop-web.service
```

## 開発

```sh
# セットアップ（mise・build-essential が必要）
mise trust
mise install
mise run setup

# テスト・整形チェック
mise run test
mise run format:check

# 実際のSyftでOS識別・除外範囲・パッケージ情報の保持を検証（任意）
OUTCROP_TEST_SYFT=/usr/local/bin/syft mise run test
```

## LICENSE

[Apache-2.0](LICENSE)
