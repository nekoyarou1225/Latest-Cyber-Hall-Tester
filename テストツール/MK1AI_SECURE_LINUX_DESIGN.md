# MK1AI_SECURE_LINUX_DESIGN.md — MK1Ai Secure Linux 専用ゲストOS基本設計書

> **ステータス**: Phase 1（設計完了 / イメージ未構築・承認待ち）  
> **重要事項**: 現時点で **MK1Ai Secure Linux イメージは構築済みではありません**。UIおよびAPIの初期状態ではデフォルト選択候補として `MK1Ai Secure Linux (Not Built / Unverified)` と正確に表示し、承認後にのみビルドを実行します。

---

## 1. 実装済み・未実装・推定・未検証の区分

| 区分 | 内容 |
| :--- | :--- |
| **1. 証拠によって確認済み（実装済み）** | `/home/harukiy1225/MK1Ai-main/security/usb-scan-guest/` に Alpine ベースの最小 initramfs ゲスト構築スクリプト (`Dockerfile`, `build.sh`, `sign.sh`, `usb-scan-init`) が存在し、`manifest.json`（SHA-256）と OpenSSL 署名 (`manifest.sig`) の仕組みが実装されている。また `mk1-sandbox-os.sh` に Linux Namespace (`mount, net, uts, ipc, pid`) を用いた隔離環境構築スクリプトが存在する。 |
| **2. 静的解析による候補（未実装）** | AegisLab 用の **MK1Ai Secure Linux**（DPI・XDP/eBPF検証・ゼロトラスト検証用エージェントを統合し、SBOMとビルド来歴を備えた専用ゲストOSイメージ）はまだ構築されていない。 |
| **3. 推定または設計上の懸念** | 現ホストはディスク空き容量が `1.4 GiB`（使用率95%）しかないため、数GB規模の汎用ディストリビューションイメージを生成するとディスク枯渇を起こす。したがって initramfs (`cpio.gz`) または SquashFS による 50MB〜150MB 以下の超軽量イミュータブル構成が必須である。 |
| **4. 未検証** | 現ホストには `docker` および `qemu-system-x86_64` が未インストールであるため、コンテナベースのイメージビルドおよび QEMU/KVM 上での実ブートは**未検証**である。 |

---

## 2. 専用OSとしての設計根拠（単なるリブランドではない理由）

**MK1Ai Secure Linux** は、既存ディストリビューションの `/etc/os-release` を書き換えただけのものではなく、以下の5つの技術的根拠によって専用検証ゲストOSとして定義される。

1. **イミュータブル・読み取り専用ルートファイルシステム (`rootfs.cpio.gz` / `squashfs`)**:
   - ルートファイルシステムはメモリ展開または読み取り専用マウントとし、書き込み可能領域はサイズ上限付き `tmpfs` (`/tmp`, `/run`, `/var/log/mk1-audit`、合計上限 64MB〜256MB) のみに限定する。
2. **専用PID 1 / 最小Init (`mk1-secure-init`) と不要サービスの完全排除**:
   - SSHデーモン、cron、inetd、パッケージマネージャ（実行時 `apk`/`apt`）、コンパイラ、汎用シェル群をランタイムイメージから除去または無効化する。
   - 起動プロセスは (1) `mk1-secure-init`、(2) `mk1-auditd`（監査ログ記録）、(3) `mk1-verify-agent`（隔離検証ハーネス）のみに限定する。
3. **サービス単位の最小権限 (Linux Capabilities / Seccomp / Landlock)**:
   - 各デーモンは専用非特権UID（例: `uid=10001(mk1verify)`）で動作させ、ネットワーク制御が必要なプロセスにのみ `CAP_NET_ADMIN` / `CAP_BPF` を限定付与し、`NoNewPrivileges=yes` を強制する。
4. **デフォルト外部通信遮断 (Default-Deny Egress / Air-Gap)**:
   - ブート直後（ユーザースペース起動前）に `lo` のみを有効化し、外部インターフェースはすべて `DOWN` または `DROP` ポリシーで初期化する。許可されたテスト専用サブネット（例: `10.254.200.0/24`）以外のルーティングエントリを持たない。
5. **暗号学的検証チェーンとSBOMの同梱**:
   - カーネル (`vmlinuz`)、初期RAMディスク (`initramfs.cpio.gz`)、構成一覧 (`config-manifest.json`)、SBOM (`sbom.spdx.json`) の全SHA-256ハッシュを `manifest.json` に記録し、オフライン秘密鍵による署名 `manifest.sig` が検証されない限り `OS Image Manager` は起動を拒否する。

---

## 3. カーネル・ドライバ・XDP/eBPF・DPI 実行経路の要件定義

ソースコードの存在だけで「対応済み」と判定せず、以下の実行経路とカーネル構成を確認対象とする。

| 機能領域 | 必須カーネルConfig / 機能 | 必要な権限 / デバイス | 実行経路の検証方法 |
| :--- | :--- | :--- | :--- |
| **XDP / eBPF** | `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_BPF_JIT=y`, `CONFIG_HAVE_EBPF_JIT=y`, `CONFIG_XDP_SOCKETS=y`, `CONFIG_NET_CLS_BPF=y` | `CAP_BPF`, `CAP_NET_ADMIN`, `RLIMIT_MEMLOCK`（旧カーネル互換）、`/sys/fs/bpf` マウント | `veth` または `virtio_net` に対し `XDP_FLAGS_DRV_MODE` または `XDP_FLAGS_SKB_MODE` でアタッチし、実パケット投入後の `XDP_PASS` / `XDP_DROP` カウンター変化を `bpftool` で実測確認。 |
| **DPI / Netfilter** | `CONFIG_NF_TABLES=y`, `CONFIG_NF_QUEUE=y`, `CONFIG_PACKET=y` | `CAP_NET_RAW`, `CAP_NET_ADMIN` | 隔離 `veth` 上のパケットキャプチャまたはテストハーネス入力から DPI エンジンへ渡し、異常パケット時の Fail-Closed 遮断を確認。 |
| **ハードウェア隔離** | `CONFIG_STRICT_DEVMEM=y`, `CONFIG_MODULE_SIG_FORCE=y` (または `CONFIG_MODULES=n`), `sysctl kernel.kptr_restrict=2`, `kernel.dmesg_restrict=1`, `kernel.unprivileged_bpf_disabled=1` | root でも実行時のカーネルモジュール追加を禁止 (`sysctl kernel.modules_disabled=1`) | ブート後にゲスト内から `insmod` や非特権 `bpf()` システムコールが `EPERM` で拒否されることを実測確認。 |

---

## 4. 監査ログ・バージョン追跡・ロールバック設計

1. **イメージ識別子とバージョン構造**:
   - 形式: `mk1ai-secure-linux-<major>.<minor>.<patch>-<build_date>-<git_or_spec_sha8>`
   - `/etc/mk1ai-release` にビルド日時、構成ハッシュ、SBOMハッシュ、対象アーキテクチャ (`x86_64`) を埋め込む。
2. **監査ログ**:
   - ゲスト内のすべてのポリシー変更、テスト開始・終了、権限エラー、パケット遮断イベントを構造化JSON Lines形式（タイムスタンプ、シーケンス番号、直前ログのSHA-256ハッシュ付き）でシリアルコンソールまたは専用virtio-serial経由でホスト側 `Telemetry & Evidence Manager` へストリーミングする。
3. **安全なロールバック**:
   - イメージはすべて不変（Immutable）であり、更新時は既存イメージを上書きせず新バージョンのディレクトリとして並置登録する。
   - 新イメージの起動チェック・ネットワーク隔離チェック・エージェント応答チェックのいずれか1つでも失敗した場合、直ちに起動を中断し、直前の `VERIFIED` イメージへポインタをロールバックする。
