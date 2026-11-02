# OS_IMAGE_BUILD_PLAN.md — MK1Ai Secure Linux ビルド・検証・承認計画書

> **ステータス**: Phase 1（ビルド計画策定完了 / **ビルド未実行・承認待ち**）  
> **絶対ルール**: ユーザーの明示的な承認があるまで、OSイメージのダウンロード、パッケージのインストール、ビルドの実行は一切行いません。

---

## 1. 現状の環境監査とビルド制約（実測確認済み）

2026-10-29 時点のホスト環境の読み取り専用調査結果は以下のとおりである。

| 項目 | ホスト実測値 | ビルドへの影響・判定 |
| :--- | :--- | :--- |
| **ホストOS / カーネル** | Debian GNU/Linux 13 (trixie) / Linux `6.6.147-09648-g97ef00d8a343` `x86_64` | **確認済み** |
| **CPU / メモリ** | Intel N100 (4 vCPU) / 総RAM 2.6 GiB（空き約 565 MiB、Swap 0 B） | **制約大**: 並列ビルド (`-j4`) はOOMの危険があるため `JOBS=1`、メモリ上限 500MB 以内で実行する必要がある。 |
| **ディスク空き容量** | `/dev/vdb` 総容量 28 GiB / 使用 26 GiB / **残り 1.4 GiB (95%使用)** | **重大な制約**: 大型コンテナイメージやフルディストリビューションの展開は不可。ビルド成果物は最大 100 MB 以内に収める必要がある。 |
| **既存ビルドスクリプト** | `/home/harukiy1225/MK1Ai-main/security/usb-scan-guest/{build.sh,sign.sh,Dockerfile}` | **実装済み（参照可能）**: ただし `build.sh` は `docker` コマンドを要求する。 |
| **Docker / QEMU の有無** | `docker`: 未インストール、`qemu-system-x86_64`: 未インストール | **未導入**: 承認なしにパッケージ追加は行わない。 |
| **利用可能なツール** | `python3` (3.13.5), `openssl`, `cpio`, `gzip`, `sha256sum`, `unshare`, `ip` | **確認済み**: 外部パッケージを追加せずローカル資産のみで最小 rootfs / initramfs の検証用パッケージングと署名検証を行う場合はこれらを利用可能。 |

---

## 2. ビルド方式の2段階プラン（承認後に選択実行）

現環境のディスク残量（1.4 GiB）およびツール導入状況を鑑み、以下の2つのビルドプロファイルを設計する。**いずれも現時点では未実行であり、承認後にのみ実行する。**

### Profile A: ローカル・ゼロダウンロード最小 Initramfs / Sandbox イメージ構築（推奨・追加パッケージ不要）
- **概要**: 外部ネットワークからのダウンロードや `apt install` を一切行わず、ホスト上の既存バイナリ（読み取り専用バインドまたは最小構成コピー）と `MK1Ai-main` の検証スクリプト群から、再現可能な `initramfs.cpio.gz` + `manifest.json` + `manifest.sig` + `sbom.spdx.json` を生成する。
- **必要ディスク容量**: 約 15 MB〜30 MB（一時領域含め 60 MB 以下）。
- **必要メモリ**: 128 MB 以下。

### Profile B: フル独立カーネル＋Alpineベース cpio.gz イメージ構築（要承認：ツール導入＆ダウンロード）
- **概要**: `MK1Ai-main/security/usb-scan-guest/build.sh` の方式を拡張し、ピン留めされた `@sha256` ダイジェストのベースイメージから `vmlinuz` と `initramfs.cpio.gz` を生成する。
- **前提となる承認事項**:
  1. ディスク空き容量の確保（最低 3 GiB 以上の空き確保が推奨）
  2. ビルドツールおよび仮想化パッケージ（`qemu-system-x86` 等）のインストール承認
  3. 外部リポジトリからのピン留めイメージ取得の承認

---

## 3. 再現可能ビルド（Reproducible Build）とSBOM・署名の手順

承認後に実行するビルドパイプラインは以下の7ステップで構成される。

1. **Step 1: 事前環境・容量チェック（Preflight Check）**
   - 空きディスク容量 $\ge 1.0\text{ GiB}$、空きメモリ $\ge 300\text{ MiB}$ を確認。満たさない場合はビルドを開始せず即座に中断する。
2. **Step 2: 入力ソースと依存関係の固定検証**
   - すべての取り込み対象ファイルについて、シンボリックリンクでないこと（通常ファイルであること）、パストラバーサルを含まないこと、SHA-256ハッシュが入力ロックファイルと一致することを確認する。
3. **Step 3: 最小構成・権限正規化と決定論的アーカイブ生成**
   - `SOURCE_DATE_EPOCH` を固定し、ファイル一覧を `LC_ALL=C sort -z` で辞書順ソートした上で `cpio --null --reproducible -o -H newc` および `gzip -n -9` によりタイムスタンプに依存しない同一バイナリを生成する。
4. **Step 4: SBOM（Software Bill of Materials）と構成一覧の自動生成**
   - イメージ内に含まれる全実行ファイル・ライブラリ・Pythonモジュール・設定ファイルのパス、バージョン、SHA-256ハッシュ、ライセンス種別を列挙した `sbom.spdx.json` および `config-manifest.json`（有効サービス一覧、sysctl設定、capabilities一覧）を出力する。
5. **Step 5: マニフェスト作成と暗号署名 (`manifest.json` & `manifest.sig`)**
   - `vmlinuz`（使用時）、`initramfs.cpio.gz`、`sbom.spdx.json`、`config-manifest.json` のSHA-256を記録した `manifest.json` を生成し、`openssl pkeyutl -sign -rawin` で署名する。秘密鍵のパーミッションが `0600` 以外の場合は署名を拒否する（`sign.sh` の安全規則を継承）。
6. **Step 6: 起動可能性と互換性の検証計画（Boot & Compatibility Verification）**
   - 生成されたイメージに対し、(a) 署名検証テスト、(b) ハッシュ改ざん時の拒否テスト、(c) 隔離環境での起動・`/etc/mk1ai-release` 読み取り・デフォルト外部通信遮断テストを実施する。
7. **Step 7: 信頼状態の昇格登録**
   - Step 1〜6 のすべてが `PASS` した場合にのみ、イメージステータスを `UNBUILT` → `VERIFIED` に更新する。1項目でも未達の場合は `UNVERIFIED` のままとし、有効化しない。
