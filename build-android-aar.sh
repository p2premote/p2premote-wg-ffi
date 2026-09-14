#!/usr/bin/env bash
# build-android-aar.sh - 构建 Android WireGuard 数据面 AAR（libwgmobile.aar）
#
# 用 gomobile bind 把 mobile/libwgmobile（wireguard-go userspace 绑定，
# 自 p2premote-punch 仓库迁入）编译为独立 AAR，供 p2premote-android-client
# 使用。打洞层已切换为 Rust 版（punch-native），本 AAR 只含 WG 数据面。
#
# 前置依赖：
#   - Go 1.25+
#   - 已安装并可执行的 gomobile（脚本不会自动安装或切换工具链）
#   - Android NDK（gomobile init 需要），ANDROID_HOME 已配置
#   - goproxy.cn 或其他可用代理（拉取 wireguard-go 等依赖）
#
# 用法：
#   cd p2premote-wg-ffi
#   ./build-android-aar.sh
#
# 产物：
#   p2premote-wg-ffi/libwgmobile.aar  （含目标 ABI libgojni.so）
#
# 然后拷贝到客户端工程：
#   cp libwgmobile.aar ../p2premote-android-client/app/libs/libwgmobile.aar

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

for tool in go gomobile; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "Required tool not found: $tool" >&2
    exit 1
  fi
done
if [[ -z "${ANDROID_HOME:-}" || ! -d "$ANDROID_HOME" ]]; then
  echo "ANDROID_HOME must point to an existing Android SDK directory." >&2
  exit 1
fi

APP_NAME="libwgmobile"
# 对齐 client-android 的 abiFilters：arm64-v8a + x86_64
TARGETS="android/arm64,android/amd64"
ANDROID_API=29   # 对齐 client-android minSdk

if [[ -e "$APP_NAME.aar" ]]; then
  echo "output already exists; remove it before rebuilding: $SCRIPT_DIR/$APP_NAME.aar" >&2
  exit 1
fi

echo "[build-android-aar] 准备 gomobile ..."
export CGO_ENABLED=1
(
  cd mobile/libwgmobile
  go mod download

  # 注意：仓库根目录不是 Go module（Windows 数据面 go.mod 与 Android 绑定的
  # 版本基线不同），gomobile 必须在 mobile/libwgmobile 模块内运行，包路径为 "."。
  echo "[build-android-aar] gomobile bind -> ${APP_NAME}.aar (targets=${TARGETS}, androidapi=${ANDROID_API})"
  gomobile bind \
      -target="${TARGETS}" \
      -androidapi="${ANDROID_API}" \
      -ldflags="-s -w -buildid=" \
      -o "../../${APP_NAME}.aar" \
      .
)

echo "[build-android-aar] 构建完成：${SCRIPT_DIR}/${APP_NAME}.aar"
echo "[build-android-aar] 请拷贝到相邻 p2premote-android-client/app/libs/ 后再 assembleDebug。"
