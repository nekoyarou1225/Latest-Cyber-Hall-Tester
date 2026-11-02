# DEVICE_MONITORING_DESIGN.md — デバイス監視・センサー整合性・リソース保護設計書

> **ステータス**: Phase 1（現ホスト実機センサー監査・設計完了 / 実装未着手・承認待ち）

---

## 1. 現ホスト（Debian 13 / Crostini）における実機センサー監査結果（証拠確認済み）

「OSやハードウェアがデータを提供していない場合、架空の数値を表示しない」「バッテリー残量・電力(W)・電源接続状態を別々に管理する」要件に基づき、現ホストの `/proc` および `/sys` を読み取り専用で実測調査した結果と、AegisLab での表示方針を以下に定義する。

| 取得対象項目 | 現ホストでの取得元パス / API | 現ホストでの実測値（監査時点） | 判定・表示ステータス区分 |
| :--- | :--- | :--- | :--- |
| **CPU使用率** | `/proc/stat`, `os.cpu_count()` | Intel N100 (4 vCPU) 取得可能 | **`[実測可 / AVAILABLE]`** |
| **システムメモリー（使用量・空き・使用率）** | `/proc/meminfo` | Total: `2.6 GiB`, Used: `2.1 GiB`, Available: `565 MiB`, Swap: `0 B` | **`[実測可 / AVAILABLE]`** |
| **テストプロセスのメモリー使用量** | `/proc/self/statm`, `/proc/<pid>/status` (`VmRSS`) | 取得可能 | **`[実測可 / AVAILABLE]`** |
| **GPU使用率とVRAM** | `/sys/class/drm` | `/sys/class/drm/version` のみ存在し、カードデバイスやVRAMカウンタは非公開 | **`[取得不可 / 未対応 (UNSUPPORTED_BY_VIRT_GPU)]`**（架空の0%やダミー値を表示しない） |
| **ストレージ使用量・空き容量** | `os.statvfs("/home/harukiy1225/テストツール")` | `/dev/vdb` Total: `28G`, Used: `26G`, Free: `1.4G` (`95%`) | **`[実測可 / AVAILABLE]`** |
| **ディスク読み書き状況** | `/proc/diskstats` (`vdb`), `/proc/self/io` | 取得可能 | **`[実測可 / AVAILABLE]`** |
| **ネットワーク送受信量・実測レート** | `/proc/net/dev` | インターフェース別累計バイト/パケット数および差分レート算出可能 | **`[実測可 / AVAILABLE]`** |
| **バッテリー残量 (%)** | `/sys/class/power_supply/battery/uevent` (`POWER_SUPPLY_CAPACITY`) | `80` (%) | **`[実測可 / AVAILABLE]`**（電源状態・電力Wとは独立フィールド） |
| **電源接続状態（充電/放電/外部電源）** | `/sys/class/power_supply/battery/uevent` (`STATUS=Discharging`), `/sys/class/power_supply/ac/uevent` (`ONLINE=0`) | バッテリーステータス: `Discharging` / ACオンライン: `0` (未接続) | **`[実測可 / AVAILABLE]`**（残量%・電力Wとは独立フィールド） |
| **消費電力 (W)** | `/sys/class/power_supply/battery/power_now`（不在）、ただし `VOLTAGE_NOW=12878000` ($\mu\text{V}$), `CURRENT_NOW=746000` ($\mu\text{A}$) が存在 | 直接の `power_now` ファイルは未提供。電圧 $12.878\text{ V} \times$ 電流 $0.746\text{ A} \approx 9.61\text{ W}$ | 直接センサー値としては **`[直接取得不可 (DIRECT_SENSOR_UNAVAILABLE)]`**、電圧×電流からの換算値は **`[推定計算値 (DERIVED_V_X_I: 9.61 W)]`** と明示区別して表示する。 |
| **温度** | `/sys/class/thermal/thermal_zone0/{type,temp}` | `type=battery`, `temp=0`（Crostini仮想化によりダミー値 `0` が返る） | `temp=0` は物理温度ではないため **`[取得不可 / 仮想環境未提供 (UNAVAILABLE_VIRTUALIZED)]`** と判定し、`0.0℃` と誤表示しない。 |
| **経過時間・パケット数・仮想ボット数** | 内部タイマー (`monotonic_ns`)・Module 7・Module 8 | 取得可能 | **`[実測可 / AVAILABLE]`** |

---

## 2. ステータスタグ付きテレメトリデータ構造

すべての監視メトリクスは単なる数値型ではなく、必ず `status` メタデータを持つ構造体として表現する。

```json
{
  "battery_capacity_percent": {
    "status": "AVAILABLE",
    "value": 80,
    "unit": "%",
    "source": "/sys/class/power_supply/battery/capacity"
  },
  "power_connection_state": {
    "status": "AVAILABLE",
    "ac_online": false,
    "battery_status": "Discharging",
    "source": "/sys/class/power_supply/{ac,battery}/uevent"
  },
  "power_consumption_watts": {
    "status": "DERIVED_FROM_VOLTAGE_CURRENT",
    "direct_power_now_available": false,
    "derived_value_watts": "9.61",
    "voltage_mv": 12878,
    "current_ma": 746,
    "note": "power_now未提供のため VOLTAGE_NOW * CURRENT_NOW から算出"
  },
  "temperature_celsius": {
    "status": "UNAVAILABLE",
    "value": null,
    "reason": "thermal_zone0 reports constant 0 under Crostini virtualized sysfs"
  },
  "gpu_metrics": {
    "status": "UNSUPPORTED",
    "value": null,
    "reason": "No physical GPU / VRAM counters exposed in /sys/class/drm"
  }
}
```

---

## 3. 初期OFFポリシーと常時有効な必須リソース保護の分離

### 3.1 ユーザー向け監視オプション（初期状態：OFF）
- `device_monitoring_panel_enabled = false`（初期OFF）
- `battery_power_monitoring_panel_enabled = false`（初期OFF）
- `auto_resource_throttling_enabled = false`（初期OFF）
- これらがOFFの間、UI上の監視パネルは「監視パネル：OFF（未計測）」と表示し、不要なUIポーリングを行わない。

### 3.2 必須安全制御（常時有効・スイッチで解除不可）
オプションの監視パネルがOFFであっても、ホストOS（空きRAM 565MiB / 空きDisk 1.4GiB）のクラッシュやフリーズを防ぐため、`Isolation & Safety Controller`（Module 4）は以下のハードリミットを常時強制する。

| 保護項目 | 警告閾値（Warning） | 一時停止閾値（Auto-Pause） | 強制安全停止閾値（Hard Halt） |
| :--- | :--- | :--- | :--- |
| **ホスト空きメモリ (`MemAvailable`)** | `< 350 MiB` | `< 250 MiB` | **`< 180 MiB`** |
| **テストプロセスRSS (`VmRSS`)** | `> 250 MiB` | `> 350 MiB` | **`> 450 MiB`** (`RLIMIT_AS` 併用) |
| **ホスト空きディスク (`/dev/vdb`)** | `< 1.2 GiB` | `< 900 MiB` | **`< 600 MiB`**（ログ・録画即時停止） |
| **バッテリー残量（放電中）** | `< 25 %` | `< 15 %` | **`< 10 %`** |
| **単一テスト最大実行時間** | 設定上限の 80% | - | **設定上限 100% 到達時**（デフォルト最大 300秒） |
