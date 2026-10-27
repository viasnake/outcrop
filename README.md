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

## 更新

実行中のスキャンが終わってから更新してください。以下は標準の `/opt/outcrop` 配置用です。別の場所に配置している場合は、コマンド中のパスとコピーするサービス定義の `WorkingDirectory` を実際の配置先に合わせてください。

```sh
sudo sh -eu <<'SH'
cd /opt/outcrop
umask 0022
systemctl stop outcrop-web.service outcrop-worker.service
git pull --ff-only
env PERL_CARTON_MIRROR=https://cpan.metacpan.org \
  /usr/bin/carton install --deployment --without develop
chown -R root:root /opt/outcrop
chmod -R go-w /opt/outcrop
cp systemd/outcrop-worker.service systemd/outcrop-web.service /etc/systemd/system/
systemctl daemon-reload
systemctl start outcrop-worker.service
systemctl start outcrop-web.service
systemctl --no-pager --full status outcrop-worker.service outcrop-web.service
SH
```

`Root must own ... and deny group/other writes` は、表示されたパスが root 所有でないか、グループ・その他のユーザーに書き込みが許可されている場合に出ます。root での `git pull` でも、`umask 0002` なら更新ファイルが `0664` になり、起動できません。上の手順は `umask 0022` で更新し、既存ファイル・依存ライブラリの所有者と権限も整えます。途中で失敗した場合はサービスを停止したまま終了するため、エラーを解消してから再実行してください。

## 利用

`http://<実行ホストの IP アドレスまたはホスト名>:8080` を開きます。同じホストからは [http://127.0.0.1:8080](http://127.0.0.1:8080) でもアクセスできます。

すべての IPv4 アドレス（`0.0.0.0:8080`）で待ち受けます。認証機能はないため、ファイアウォールなどで信頼できる端末からの接続に制限してください。

クローンディスクは単一ディスクの ext4 / XFS のみ対応します。自動マウントしない専用 VM に独立した複製を接続し、アンマウントを確認してから取り外してください。

GPT ディスク上の BIOS boot partition は、通常のパーティションでファイルシステムが空の場合に同居できます。起動用の領域のため、スキャン対象にはなりません。未対応の構成では、一覧に該当デバイスとパーティションテーブル（PTTYPE）、デバイス種別（TYPE）、パーティション種別（PARTTYPE）、ファイルシステム（FSTYPE）を表示します。`<empty>` は値が空または未検出であることを表します。

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

# 表示キャッシュの実ブラウザーテスト（Node.js 22 以降が必要）
npm ci
npx playwright install chromium
mise run test:results

# 実際のSyftでOS識別・除外範囲・パッケージ情報の保持を検証（任意）
OUTCROP_TEST_SYFT=/usr/local/bin/syft mise run test
```

結果一覧は最大60行ずつ取得します。新規スキャンは終了時にJSONを逐次処理し、スキャン保存先に検索・並べ替え用の `results-syft.sqlite` と `results-grype.sqlite` を作成します。既存結果は「その他の操作」のパッケージ・脆弱性一覧の作成／再作成ボタンから作成でき、再スキャンは不要です。閲覧だけでは作成しません。Webからの再作成は別プロセスで1件ずつ行い、`/var/lib/outcrop/annotations/results/` に保存します。再作成中も旧一覧を閲覧できます。

作成後はSQLiteの整合性と、全行の読み戻しによる件数・内容ハッシュを検証してから置き換えます。元JSONのSHA-256も記録します。失敗時は元JSONと旧一覧を保持し、再作成ボタンから再試行できます。新規スキャンで一覧作成だけが失敗した場合も監査結果は保持され、警告を記録します。JSON全体をメモリに載せず、メモリ使用量は主に1項目の大きさに依存します。元JSONに加えてSQLiteと作成中の一時ファイルの保存容量が必要です。再作成後は一覧の世代が変わり、ブラウザーは旧キャッシュを表示しません。

ブラウザーは表示した範囲をIndexedDBへ圧縮保存します。パッケージと脆弱性は別々に、各512MiBまたはブラウザーが報告する容量の1/4の小さい方を上限とします。同じ種類の最近使われていない項目から削除し、新規保存に失敗した場合は削除も取り消します。旧形式のキャッシュは閲覧した結果から解放します。永続ストレージも要求しますが、許可・容量・保持期間はブラウザーに依存します。保存できなくても一覧は表示でき、再取得も必要な範囲だけです。

1GiB超の合成データによる測定は、リポジトリ直下で `carton exec perl script/benchmark-results` を実行します。生成物は `var/results-benchmark/` に保存されます。出力は初回作成時間、入力・SQLite・応答のサイズ、一覧・検索・並べ替え・末尾取得の各5回の中央値と最大時間です。メモリは `/usr/bin/time -v` で併せて測定できます。

## LICENSE

[Apache-2.0](LICENSE)
