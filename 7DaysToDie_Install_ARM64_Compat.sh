#!/bin/bash
# 七日杀服务器多功能安装管理脚本 v1.2.4 Oracle Debian12 ARM64超时重试版 爱来自 伶依nekochan 抖音 ACFUN同名主播
# # 本脚本部分代码由kimi生成 有问题请进群告诉我 737331541 记得上传日志

# 颜色输出函数（必须先定义，后面才能使用）
red_echo() {
    echo -e "[31m$1[0m"
}

green_echo() {
    echo -e "[32m$1[0m"
}

yellow_echo() {
    echo -e "[33m$1[0m"
}

blue_echo() {
    echo -e "[34m$1[0m"
}

# 保存当前版本
save_current_version() {
    local version="$1"
    local version_file="$home_dir/.7dtd_version"
    echo "$version" > "$version_file"
    # 兼容root和普通用户
    if [ -n "$REAL_user" ] && [ "$REAL_user" != "root" ]; then
        chown $REAL_user:$REAL_user "$version_file" 2>/dev/null
    fi
}

# 获取当前版本
get_current_version() {
    local version_file="$home_dir/.7dtd_version"
    if [ -f "$version_file" ]; then
        cat "$version_file"
    else
        echo "未记录"
    fi
}

# 获取当前运行用户（支持root和普通用户）
current_user=$(whoami)

if [ "$current_user" = "root" ]; then
    # root 用户使用 /root 目录
    REAL_user="root"
    home_dir="/root"
    yellow_echo "警告：当前以 root 用户运行服务器"
    yellow_echo "建议：为了安全起见，建议创建普通用户运行服务器"
else
    # 普通用户
    REAL_user=$(who am i | awk '{print $1}')
    home_dir=$(getent passwd "$REAL_user" | cut -d: -f6)
fi

seven_days_dir="$home_dir/7DaysToDie"
server_dir="$seven_days_dir/server"
config_file="$home_dir/.7dtd_install_config"
log_dir="$home_dir/7dtd_logs"
log_file="$log_dir/7dtd_install_$(date +%Y%m%d%H%M%S).log"
steamcmd_dir="$home_dir/steamcmd"
manual_stop_flag="$home_dir/.7dtd_manual_stop.flag"
config_backup_dir="$home_dir/7dtd_config_backups"

# 默认配置
DEFAULT_SERVER_PORT="26900"
DEFAULT_SERVER_NAME="七日杀服务器"
DEFAULT_SERVER_DESC="欢迎加入七日杀服务器"
DEFAULT_WORLD_NAME="MyWorld"
DEFAULT_GAME_DIFFICULTY="1"


# ============================================
# 架构检测与 ARM64 兼容层
# 说明：七日杀 Dedicated Server 官方 Linux 程序仍是 x86_64，ARM64 只能通过 Box64 等兼容层运行。
# 下载/更新在 ARM64 上默认使用 DepotDownloader Docker 镜像，避免 SteamCMD 32位 x86 在 ARM 上的兼容问题。
# ============================================
SCRIPT_VERSION="1.2.4-oracle-debian12-arm64-timeout-retry"
ARM64_DEPOT_IMAGE="${ARM64_DEPOT_IMAGE:-ghcr.io/sonroyaalmerol/steam-depot-downloader:debian-bookworm}"
ARM64_STEAMCMD_IMAGE="${ARM64_STEAMCMD_IMAGE:-sonroyaalmerol/steamcmd-arm64:steam-bookworm}"
# ARM64 DepotDownloader 下载保护参数，可在运行脚本前用环境变量覆盖：
#   ARM64_DEPOT_MAX_ATTEMPTS=5 ARM64_DEPOT_IDLE_TIMEOUT=900 sudo ./脚本.sh
ARM64_DEPOT_MAX_ATTEMPTS="${ARM64_DEPOT_MAX_ATTEMPTS:-5}"          # 总重试次数
ARM64_DEPOT_TOTAL_TIMEOUT="${ARM64_DEPOT_TOTAL_TIMEOUT:-3600}"    # 单次总超时，秒
ARM64_DEPOT_IDLE_TIMEOUT="${ARM64_DEPOT_IDLE_TIMEOUT:-600}"       # 单次无输出超时，秒
ARM64_DEPOT_RETRY_SLEEP="${ARM64_DEPOT_RETRY_SLEEP:-20}"          # 重试间隔，秒
ARM64_DEPOT_PULL_TIMEOUT="${ARM64_DEPOT_PULL_TIMEOUT:-600}"       # docker pull 超时，秒
ARM64_DEPOT_MAX_DOWNLOADS="${ARM64_DEPOT_MAX_DOWNLOADS:-8}"       # DepotDownloader 并发下载块
ARM64_DEPOT_MAX_SERVERS="${ARM64_DEPOT_MAX_SERVERS:-8}"           # DepotDownloader 内容服务器数量
ARM64_DEPOT_VALIDATE_MODE="${ARM64_DEPOT_VALIDATE_MODE:-auto}"    # auto/always/never
ARM64_DEPOT_DEBUG="${ARM64_DEPOT_DEBUG:-0}"                       # 1=启用 DepotDownloader -debug
ARM64_DEPOT_CELLID="${ARM64_DEPOT_CELLID:-}"                      # 可选：覆盖 Steam CellID
ARM64_DEPOT_EXTRA_ARGS="${ARM64_DEPOT_EXTRA_ARGS:-}"              # 可选：追加 DepotDownloader 参数
ARM64_SKIP_DOCKER_PULL="${ARM64_SKIP_DOCKER_PULL:-0}"             # 1=优先使用本地镜像，不主动pull
ARM64_DEPOT_LINUX_DEPOT_ID="${ARM64_DEPOT_LINUX_DEPOT_ID:-294422}" # 七日杀Linux专服Depot

get_host_arch_raw() {
    uname -m 2>/dev/null || echo "unknown"
}

detect_host_arch() {
    case "$(get_host_arch_raw)" in
        x86_64|amd64) echo "amd64" ;;
        aarch64|arm64) echo "arm64" ;;
        armv7l|armv6l|armhf) echo "arm32" ;;
        *) echo "unknown" ;;
    esac
}

is_x86_64_host() { [ "$(detect_host_arch)" = "amd64" ]; }
is_arm64_host() { [ "$(detect_host_arch)" = "arm64" ]; }
is_arm32_host() { [ "$(detect_host_arch)" = "arm32" ]; }

print_arch_notice() {
    local arch="$(detect_host_arch)"
    echo "====== 架构信息 ======"
    echo "系统架构: $(get_host_arch_raw) ($arch)"
    if is_arm64_host; then
        yellow_echo "检测到 ARM64：七日杀服务端没有原生 ARM64 Linux 程序，本脚本会使用 Box64 运行 x86_64 服务端。"
        yellow_echo "ARM64 性能和稳定性取决于 CPU、Box64 版本、内存和地图大小；生产服仍优先推荐 x86_64。"
    elif is_arm32_host; then
        red_echo "检测到 ARM32：七日杀 Linux 服务端是 64 位程序，ARM32 无法运行。"
    fi
    echo "======================"
}

get_box64_bin() {
    local candidates=(
        "box64"
        "/usr/bin/box64"
        "/usr/local/bin/box64"
        "/snap/bin/box64-with-gl4es.box64"
        "box64-with-gl4es.box64"
    )
    local b
    for b in "${candidates[@]}"; do
        if command -v "$b" >/dev/null 2>&1; then
            command -v "$b"
            return 0
        fi
        if [ -x "$b" ]; then
            echo "$b"
            return 0
        fi
    done
    return 1
}

export_box64_runtime_env() {
    # 这些是偏保守的 Box64 参数，优先稳定，必要时可以在系统环境里覆盖。
    export BOX64_DYNAREC_BIGBLOCK="${BOX64_DYNAREC_BIGBLOCK:-0}"
    export BOX64_DYNAREC_SAFEFLAGS="${BOX64_DYNAREC_SAFEFLAGS:-2}"
    export BOX64_DYNAREC_STRONGMEM="${BOX64_DYNAREC_STRONGMEM:-3}"
    export BOX64_DYNAREC_FASTROUND="${BOX64_DYNAREC_FASTROUND:-0}"
    export BOX64_DYNAREC_FASTNAN="${BOX64_DYNAREC_FASTNAN:-0}"
    export BOX64_DYNAREC_X87DOUBLE="${BOX64_DYNAREC_X87DOUBLE:-1}"
}

get_server_launch_prefix() {
    if is_arm64_host; then
        get_box64_bin || return 1
    else
        echo ""
    fi
}

ensure_docker_available() {
    if command -v docker >/dev/null 2>&1; then
        return 0
    fi

    yellow_echo "未检测到 Docker。ARM64 下载/更新七日杀服务器推荐使用 DepotDownloader Docker 镜像。"
    if ! ask_yes_no "是否现在安装 docker.io？" "Y"; then
        red_echo "已跳过 Docker 安装，ARM64 下将无法自动下载/更新服务器。"
        return 1
    fi

    sudo apt-get update
    sudo apt-get install -y docker.io
    sudo systemctl enable --now docker 2>/dev/null || true

    if command -v docker >/dev/null 2>&1; then
        green_echo "✓ Docker 已安装"
        return 0
    fi

    red_echo "Docker 安装失败，请手动安装 docker.io 后重试。"
    return 1
}

install_box64_runtime_arm64() {
    if ! is_arm64_host; then
        green_echo "当前不是 ARM64，无需安装 Box64。"
        return 0
    fi

    if get_box64_bin >/dev/null 2>&1; then
        green_echo "✓ 已检测到 Box64: $(get_box64_bin)"
        return 0
    fi

    yellow_echo "未检测到 Box64。ARM64 运行七日杀 x86_64 服务端需要 Box64。"
    yellow_echo "甲骨文 ARM / Debian 12 优先尝试预编译 deb 仓库；失败后可选源码编译。"

    sudo apt-get update
    sudo apt-get install -y ca-certificates wget curl gnupg git build-essential cmake make pkg-config || true

    # 1) 官方文档推荐的 Debian 系预编译仓库（Pi-Apps-Coders）。
    if ask_yes_no "是否尝试安装预编译 Box64 包（推荐）？" "Y"; then
        sudo rm -f /etc/apt/sources.list.d/box64.list /etc/apt/sources.list.d/box64.sources 2>/dev/null || true
        sudo mkdir -p /usr/share/keyrings
        if wget -qO- "https://pi-apps-coders.github.io/box64-debs/KEY.gpg" | sudo gpg --dearmor -o /usr/share/keyrings/box64-archive-keyring.gpg; then
            cat <<'EOF' | sudo tee /etc/apt/sources.list.d/box64.sources >/dev/null
Types: deb
URIs: https://Pi-Apps-Coders.github.io/box64-debs/debian
Suites: ./
Signed-By: /usr/share/keyrings/box64-archive-keyring.gpg
EOF
            sudo apt-get update || true
            sudo apt-get install -y box64-generic-arm || sudo apt-get install -y box64 || true
        fi
    fi

    if get_box64_bin >/dev/null 2>&1; then
        green_echo "✓ Box64 安装/检测成功: $(get_box64_bin)"
        return 0
    fi

    # 2) Debian/Ubuntu 源里如果刚好有 box64，也尝试安装。
    if apt-cache show box64 >/dev/null 2>&1; then
        sudo apt-get install -y box64 || true
    elif apt-cache show box64-arm64 >/dev/null 2>&1; then
        sudo apt-get install -y box64-arm64 || true
    fi

    if get_box64_bin >/dev/null 2>&1; then
        green_echo "✓ Box64 安装/检测成功: $(get_box64_bin)"
        return 0
    fi

    # 3) 源码编译兜底。Oracle Ampere/Neoverse-N1 默认使用 ADLINK 参数，其它 ARM64 使用通用 ARM64 参数。
    if ask_yes_no "预编译包不可用，是否从源码编译 Box64？" "Y"; then
        local build_root="/tmp/box64-build-$(date +%s)"
        local cmake_flags="-D ARM64=1 -D ARM_DYNAREC=ON -D CMAKE_BUILD_TYPE=RelWithDebInfo"
        if lscpu 2>/dev/null | grep -qiE 'Ampere|Altra|Neoverse-N1'; then
            cmake_flags="-D ADLINK=1 -D CMAKE_BUILD_TYPE=RelWithDebInfo"
            yellow_echo "检测到疑似 Oracle Ampere/Neoverse-N1，源码编译将使用 ADLINK 参数。"
        fi
        if [ -n "$BOX64_CMAKE_FLAGS" ]; then
            cmake_flags="$BOX64_CMAKE_FLAGS"
            yellow_echo "使用自定义 BOX64_CMAKE_FLAGS: $cmake_flags"
        fi
        rm -rf "$build_root"
        if git clone --depth 1 https://github.com/ptitSeb/box64.git "$build_root"; then
            mkdir -p "$build_root/build"
            (cd "$build_root/build" && cmake .. $cmake_flags && make -j"$(nproc)" && sudo make install) || true
            sudo systemctl restart systemd-binfmt 2>/dev/null || true
            sudo ldconfig 2>/dev/null || true
        fi
    fi

    if get_box64_bin >/dev/null 2>&1; then
        green_echo "✓ Box64 安装/检测成功: $(get_box64_bin)"
        return 0
    fi

    red_echo "仍未检测到 Box64。请手动安装 Box64 后再启动七日杀服务器。"
    yellow_echo "可参考主菜单 21 或设置 BOX64_CMAKE_FLAGS 后重试。"
    return 1
}

ensure_arm64_download_tool() {
    if ! is_arm64_host; then
        return 0
    fi
    ensure_docker_available || return 1

    local candidates=()
    candidates+=("$ARM64_DEPOT_IMAGE")
    candidates+=("ghcr.io/sonroyaalmerol/steam-depot-downloader:debian-bookworm")
    candidates+=("ghcr.io/sonroyaalmerol/steam-depot-downloader:latest")
    candidates+=("sonroyaalmerol/steam-depot-downloader:debian-bookworm")
    candidates+=("sonroyaalmerol/steam-depot-downloader:latest")

    local img pulled=""
    for img in "${candidates[@]}"; do
        [ -z "$img" ] && continue

        if [ "$ARM64_SKIP_DOCKER_PULL" = "1" ] && sudo docker image inspect "$img" >/dev/null 2>&1; then
            yellow_echo "使用本地 ARM64 下载镜像: $img"
            pulled="$img"
            break
        fi

        yellow_echo "正在拉取/更新 ARM64 下载镜像: $img（最多 ${ARM64_DEPOT_PULL_TIMEOUT}s）"
        if timeout "$ARM64_DEPOT_PULL_TIMEOUT" sudo docker pull "$img"; then
            pulled="$img"
            break
        fi

        local rc=$?
        if [ "$rc" -eq 124 ]; then
            yellow_echo "镜像拉取超时，尝试下一个镜像源..."
        else
            yellow_echo "镜像拉取失败（退出码 $rc），尝试下一个镜像源..."
        fi

        # 如果本地已经有这个镜像，即使 pull 失败也允许使用，避免网络抖动导致完全不可用。
        if sudo docker image inspect "$img" >/dev/null 2>&1; then
            yellow_echo "检测到本地已有镜像，先使用本地版本: $img"
            pulled="$img"
            break
        fi
    done

    if [ -z "$pulled" ]; then
        red_echo "ARM64 下载镜像不可用。请检查 Docker 网络，或设置 ARM64_DEPOT_IMAGE。"
        yellow_echo "可尝试：ARM64_SKIP_DOCKER_PULL=1 sudo ./脚本.sh（前提是本地已有镜像）"
        return 1
    fi

    ARM64_DEPOT_IMAGE="$pulled"
    green_echo "✓ ARM64 下载镜像可用: $ARM64_DEPOT_IMAGE"
    return 0
}

cleanup_arm64_depot_jobs() {
    yellow_echo "正在清理可能卡死的 DepotDownloader Docker 容器/进程..."
    sudo docker ps -a --format '{{.ID}} {{.Names}}' 2>/dev/null | awk '$2 ~ /^7dtd_depot_/ {print $1}' | while read -r cid; do
        [ -n "$cid" ] && sudo docker rm -f "$cid" >/dev/null 2>&1 || true
    done
    sudo pkill -f 'DepotDownloader.*294420' 2>/dev/null || true
    sudo pkill -f 'steam-depot-downloader' 2>/dev/null || true
    green_echo "✓ 清理完成"
}

kill_process_group_safely() {
    local pgid="$1"
    [ -z "$pgid" ] && return 0
    kill -TERM -- "-$pgid" 2>/dev/null || sudo kill -TERM -- "-$pgid" 2>/dev/null || true
    sleep 5
    kill -KILL -- "-$pgid" 2>/dev/null || sudo kill -KILL -- "-$pgid" 2>/dev/null || true
}

run_command_with_watchdog() {
    local label="$1"
    local log_file="$2"
    local total_timeout="$3"
    local idle_timeout="$4"
    shift 4

    [[ "$total_timeout" =~ ^[0-9]+$ ]] || total_timeout=3600
    [[ "$idle_timeout" =~ ^[0-9]+$ ]] || idle_timeout=600

    mkdir -p "$(dirname "$log_file")"
    : > "$log_file"

    local wrapper
    wrapper=$(mktemp "/tmp/7dtd_watchdog_${label//[^a-zA-Z0-9]/_}_XXXXXX.sh") || return 1
    cat > "$wrapper" <<'EOF'
#!/bin/bash
set -o pipefail
"$@" 2>&1 | tee -a "$RUN_LOG_FILE"
exit ${PIPESTATUS[0]}
EOF
    chmod +x "$wrapper"

    echo "[$(date '+%F %T')] START $label" >> "$log_file"
    echo "[$(date '+%F %T')] CMD: $*" >> "$log_file"

    RUN_LOG_FILE="$log_file" setsid "$wrapper" "$@" &
    local pid=$!
    local started now last_progress current_size last_size rc
    started=$(date +%s)
    last_progress=$started
    last_size=0

    while kill -0 "$pid" 2>/dev/null; do
        sleep 5
        now=$(date +%s)
        current_size=0
        [ -f "$log_file" ] && current_size=$(stat -c '%s' "$log_file" 2>/dev/null || echo 0)

        if [ "$current_size" != "$last_size" ]; then
            last_size="$current_size"
            last_progress="$now"
        fi

        if [ $((now - started)) -ge "$total_timeout" ]; then
            yellow_echo "[$label] 单次总超时 ${total_timeout}s，终止本次下载..."
            echo "[$(date '+%F %T')] WATCHDOG_TOTAL_TIMEOUT ${total_timeout}s" >> "$log_file"
            kill_process_group_safely "$pid"
            wait "$pid" 2>/dev/null || true
            rm -f "$wrapper"
            return 124
        fi

        if [ $((now - last_progress)) -ge "$idle_timeout" ]; then
            yellow_echo "[$label] 无输出 ${idle_timeout}s，疑似卡住，终止本次下载..."
            echo "[$(date '+%F %T')] WATCHDOG_IDLE_TIMEOUT ${idle_timeout}s" >> "$log_file"
            kill_process_group_safely "$pid"
            wait "$pid" 2>/dev/null || true
            rm -f "$wrapper"
            return 125
        fi
    done

    wait "$pid"
    rc=$?
    echo "[$(date '+%F %T')] EXIT $label rc=$rc" >> "$log_file"
    rm -f "$wrapper"
    return "$rc"
}

build_depotdownloader_args_arm64() {
    local beta_branch="$1"
    local mode="$2"
    local include_validate="$3"

    local args=(DepotDownloader -app 294420 -os linux -osarch 64 -dir "$server_dir")

    # 模式：app 下载整个应用；depot 只拉 Linux depot。depot 模式用于 app 模式卡在 Got AppInfo 后的兜底。
    if [ "$mode" = "depot" ]; then
        args+=(-depot "$ARM64_DEPOT_LINUX_DEPOT_ID")
    fi

    if [ "$beta_branch" != "public" ] && [ "$beta_branch" != "Public" ]; then
        args+=(-branch "$beta_branch")
    fi

    if [ "$include_validate" = "1" ]; then
        args+=(-validate)
    fi

    if [[ "$ARM64_DEPOT_MAX_DOWNLOADS" =~ ^[0-9]+$ ]] && [ "$ARM64_DEPOT_MAX_DOWNLOADS" -gt 0 ]; then
        args+=(-max-downloads "$ARM64_DEPOT_MAX_DOWNLOADS")
    fi
    if [[ "$ARM64_DEPOT_MAX_SERVERS" =~ ^[0-9]+$ ]] && [ "$ARM64_DEPOT_MAX_SERVERS" -gt 0 ]; then
        args+=(-max-servers "$ARM64_DEPOT_MAX_SERVERS")
    fi
    if [ -n "$ARM64_DEPOT_CELLID" ]; then
        args+=(-cellid "$ARM64_DEPOT_CELLID")
    fi
    if [ "$ARM64_DEPOT_DEBUG" = "1" ]; then
        args+=(-debug)
    fi
    if [ -n "$ARM64_DEPOT_EXTRA_ARGS" ]; then
        # shellcheck disable=SC2206
        local extra=( $ARM64_DEPOT_EXTRA_ARGS )
        args+=("${extra[@]}")
    fi

    printf '%s\n' "${args[@]}"
}

steam_depot_update_7dtd_arm64() {
    local beta_branch="$1"
    [ -z "$beta_branch" ] && beta_branch="public"

    if ! is_arm64_host; then
        return 1
    fi

    if is_arm32_host; then
        red_echo "ARM32 不支持运行七日杀 64位 Linux 服务端。"
        return 1
    fi

    ensure_arm64_download_tool || return 1
    mkdir -p "$server_dir" "$log_dir/arm64_depot"

    local max_attempts="$ARM64_DEPOT_MAX_ATTEMPTS"
    [[ "$max_attempts" =~ ^[0-9]+$ ]] || max_attempts=5
    [ "$max_attempts" -lt 1 ] && max_attempts=1

    echo "============================================="
    echo "ARM64 下载/更新七日杀服务器"
    echo "方式: DepotDownloader Docker + 超时看门狗"
    echo "版本分支: $beta_branch"
    echo "目标目录: $server_dir"
    echo "镜像: $ARM64_DEPOT_IMAGE"
    echo "单次总超时: ${ARM64_DEPOT_TOTAL_TIMEOUT}s"
    echo "单次无输出超时: ${ARM64_DEPOT_IDLE_TIMEOUT}s"
    echo "最大尝试次数: ${max_attempts}"
    echo "============================================="

    local attempt mode include_validate log_file container_name rc sleep_seconds
    local success=0

    for attempt in $(seq 1 "$max_attempts"); do
        # 尝试策略：先完整 app+validate；再 app 不 validate；再只拉 Linux depot；后续交替重试。
        mode="app"
        include_validate=1
        case "$attempt" in
            1)
                mode="app"
                [ "$ARM64_DEPOT_VALIDATE_MODE" = "never" ] && include_validate=0
                ;;
            2)
                mode="app"
                [ "$ARM64_DEPOT_VALIDATE_MODE" = "always" ] && include_validate=1 || include_validate=0
                ;;
            3)
                mode="depot"
                [ "$ARM64_DEPOT_VALIDATE_MODE" = "always" ] && include_validate=1 || include_validate=0
                ;;
            *)
                if [ $((attempt % 2)) -eq 0 ]; then mode="app"; else mode="depot"; fi
                [ "$ARM64_DEPOT_VALIDATE_MODE" = "always" ] && include_validate=1 || include_validate=0
                ;;
        esac

        container_name="7dtd_depot_$$_${attempt}"
        log_file="$log_dir/arm64_depot/depot_${beta_branch}_${mode}_attempt${attempt}_$(date +%Y%m%d_%H%M%S).log"
        sudo docker rm -f "$container_name" >/dev/null 2>&1 || true

        mapfile -t dd_args < <(build_depotdownloader_args_arm64 "$beta_branch" "$mode" "$include_validate")

        local docker_args=(run --rm --init --network host --name "$container_name" --user 0:0)
        docker_args+=(-v "$server_dir:$server_dir")
        docker_args+=("$ARM64_DEPOT_IMAGE")

        echo ""
        echo "============================================="
        echo "DepotDownloader 尝试 ($attempt/$max_attempts)"
        echo "模式: $mode | validate: $include_validate | 日志: $log_file"
        echo "============================================="

        run_command_with_watchdog "depot_${attempt}_${mode}" "$log_file" "$ARM64_DEPOT_TOTAL_TIMEOUT" "$ARM64_DEPOT_IDLE_TIMEOUT" \
            sudo docker "${docker_args[@]}" "${dd_args[@]}"
        rc=$?

        # 确保超时后不会残留容器。
        sudo docker rm -f "$container_name" >/dev/null 2>&1 || true

        if [ "$rc" -eq 0 ] && [ -f "$server_dir/7DaysToDieServer.x86_64" ]; then
            success=1
            break
        fi

        if [ "$rc" -eq 0 ] && [ ! -f "$server_dir/7DaysToDieServer.x86_64" ]; then
            red_echo "DepotDownloader 返回成功，但未找到 7DaysToDieServer.x86_64，继续重试。"
        elif [ "$rc" -eq 124 ]; then
            yellow_echo "本次下载达到总超时。"
        elif [ "$rc" -eq 125 ]; then
            yellow_echo "本次下载因长时间无输出被判定卡住。"
            if grep -q "Got AppInfo for 294420" "$log_file" 2>/dev/null && ! grep -q "Processing depot\|Downloading depot" "$log_file" 2>/dev/null; then
                yellow_echo "日志显示卡在 Got AppInfo 附近；下一次会尝试切换下载模式/跳过validate。"
            fi
        else
            yellow_echo "DepotDownloader 失败，退出码: $rc"
        fi

        yellow_echo "失败日志保留在: $log_file"
        if [ "$attempt" -lt "$max_attempts" ]; then
            sleep_seconds="$ARM64_DEPOT_RETRY_SLEEP"
            [[ "$sleep_seconds" =~ ^[0-9]+$ ]] || sleep_seconds=20
            yellow_echo "${sleep_seconds}s 后重试..."
            sleep "$sleep_seconds"
        fi
    done

    if [ "$success" -eq 1 ]; then
        chmod +x "$server_dir/7DaysToDieServer.x86_64" 2>/dev/null || true
        if [ -n "$REAL_user" ] && [ "$REAL_user" != "root" ]; then
            sudo chown -R "$REAL_user:$REAL_user" "$server_dir" 2>/dev/null || true
        fi
        green_echo "✓ ARM64 模式下载/更新完成"
        return 0
    fi

    red_echo "ARM64 模式下载/更新失败。"
    yellow_echo "你可以查看日志目录: $log_dir/arm64_depot"
    yellow_echo "如一直卡在 Got AppInfo，可尝试：ARM64_DEPOT_IDLE_TIMEOUT=900 ARM64_DEPOT_VALIDATE_MODE=never sudo ./脚本.sh"
    return 1
}
extract_steamclient_so_arm64() {
    if ! is_arm64_host; then
        return 1
    fi

    mkdir -p "$steamcmd_dir" "$server_dir" "$home_dir/.steam/sdk64"

    # 如果本地已有，就直接用。
    if [ -f "$steamcmd_dir/linux64/steamclient.so" ]; then
        cp -f "$steamcmd_dir/linux64/steamclient.so" "$server_dir/steamclient.so" 2>/dev/null || true
        ln -sf "$steamcmd_dir/linux64/steamclient.so" "$home_dir/.steam/sdk64/steamclient.so" 2>/dev/null || true
        return 0
    fi
    if [ -f "$steamcmd_dir/steamclient.so" ]; then
        cp -f "$steamcmd_dir/steamclient.so" "$server_dir/steamclient.so" 2>/dev/null || true
        ln -sf "$steamcmd_dir/steamclient.so" "$home_dir/.steam/sdk64/steamclient.so" 2>/dev/null || true
        return 0
    fi

    if ! command -v docker >/dev/null 2>&1; then
        yellow_echo "[Steam修复] ARM64 下未安装 Docker，跳过 steamclient.so 提取。"
        return 1
    fi

    yellow_echo "[Steam修复] 尝试从 ARM64 SteamCMD 镜像提取 steamclient.so ..."
    local steamcmd_images=("$ARM64_STEAMCMD_IMAGE" "sonroyaalmerol/steamcmd-arm64:steam-bookworm" "sonroyaalmerol/steamcmd-arm64:latest")
    local img
    for img in "${steamcmd_images[@]}"; do
        [ -z "$img" ] && continue
        sudo docker pull "$img" >/dev/null 2>&1 || continue
        sudo docker run --rm --user 0:0 -v "$steamcmd_dir:/host_steamcmd" "$img" \
            bash -lc 'cp -f /home/steam/steamcmd/linux64/steamclient.so /host_steamcmd/steamclient.so 2>/dev/null || cp -f /root/Steam/linux64/steamclient.so /host_steamcmd/steamclient.so 2>/dev/null || true' || true
        [ -f "$steamcmd_dir/steamclient.so" ] && break
    done

    if [ -f "$steamcmd_dir/steamclient.so" ]; then
        cp -f "$steamcmd_dir/steamclient.so" "$server_dir/steamclient.so" 2>/dev/null || true
        ln -sf "$steamcmd_dir/steamclient.so" "$home_dir/.steam/sdk64/steamclient.so" 2>/dev/null || true
        green_echo "[Steam修复] ✓ ARM64 模式已准备 steamclient.so"
        return 0
    fi

    yellow_echo "[Steam修复] 未能提取 steamclient.so。如服务器可正常启动可忽略；否则请手动补充。"
    return 1
}

arm64_compat_menu() {
    while true; do
        echo "============================================="
        echo "          ARM64兼容环境"
        echo "============================================="
        print_arch_notice
        echo "1. 检查 ARM64 运行环境"
        echo "2. 安装/修复 Box64"
        echo "3. 安装/修复 Docker 下载环境"
        echo "4. 拉取 ARM64 下载镜像"
        echo "5. 提取/修复 steamclient.so"
        echo "6. 清理卡死的 DepotDownloader 容器/进程"
        echo "7. 显示 ARM64 下载超时/重试参数"
        echo "0. 返回主菜单"
        echo "============================================="
        read -p "请输入操作编号: " arm_choice
        case "$arm_choice" in
            1)
                echo "Box64: $(get_box64_bin 2>/dev/null || echo '未安装')"
                echo "Docker: $(command -v docker 2>/dev/null || echo '未安装')"
                echo "Depot镜像: $ARM64_DEPOT_IMAGE"
                echo "SteamCMD镜像: $ARM64_STEAMCMD_IMAGE"
                read -p "按回车键继续..." ;;
            2) install_box64_runtime_arm64; read -p "按回车键继续..." ;;
            3) ensure_docker_available; read -p "按回车键继续..." ;;
            4) ensure_arm64_download_tool; read -p "按回车键继续..." ;;
            5) extract_steamclient_so_arm64; read -p "按回车键继续..." ;;
            6) cleanup_arm64_depot_jobs; read -p "按回车键继续..." ;;
            7)
                echo "ARM64_DEPOT_MAX_ATTEMPTS=$ARM64_DEPOT_MAX_ATTEMPTS"
                echo "ARM64_DEPOT_TOTAL_TIMEOUT=$ARM64_DEPOT_TOTAL_TIMEOUT"
                echo "ARM64_DEPOT_IDLE_TIMEOUT=$ARM64_DEPOT_IDLE_TIMEOUT"
                echo "ARM64_DEPOT_RETRY_SLEEP=$ARM64_DEPOT_RETRY_SLEEP"
                echo "ARM64_DEPOT_PULL_TIMEOUT=$ARM64_DEPOT_PULL_TIMEOUT"
                echo "ARM64_DEPOT_MAX_DOWNLOADS=$ARM64_DEPOT_MAX_DOWNLOADS"
                echo "ARM64_DEPOT_MAX_SERVERS=$ARM64_DEPOT_MAX_SERVERS"
                echo "ARM64_DEPOT_VALIDATE_MODE=$ARM64_DEPOT_VALIDATE_MODE"
                echo "ARM64_DEPOT_LINUX_DEPOT_ID=$ARM64_DEPOT_LINUX_DEPOT_ID"
                echo "ARM64_DEPOT_CELLID=${ARM64_DEPOT_CELLID:-未设置}"
                echo "ARM64_DEPOT_EXTRA_ARGS=${ARM64_DEPOT_EXTRA_ARGS:-未设置}"
                read -p "按回车键继续..." ;;
            0) return 0 ;;
            *) red_echo "无效选项" ;;
        esac
    done
}

# 询问函数
ask_yes_no() {
    local prompt="$1"
    local default="$2"
    local reply

    while true; do
        if [ "$default" = "Y" ]; then
            read -p "$prompt [Y/n]: " reply
        else
            read -p "$prompt [y/N]: " reply
        fi

        if [ -z "$reply" ]; then
            reply="$default"
        fi

        case "$reply" in
            [Yy]* ) return 0 ;;
            [Nn]* ) return 1 ;;
            * ) echo "请输入 y 或 n." ;;
        esac
    done
}

# Auto backup serverconfig.xml before risky operations
backup_server_config_auto() {
    local op_name="$1"
    local src="$server_dir/serverconfig.xml"
    local ts="$(date +%Y%m%d_%H%M%S)"

    if [ ! -f "$src" ]; then
        yellow_echo "[配置备份] 未找到配置文件，跳过: $src"
        return 0
    fi

    mkdir -p "$config_backup_dir"
    local dst="$config_backup_dir/serverconfig_${op_name}_${ts}.xml"
    if cp -a "$src" "$dst" 2>/dev/null; then
        green_echo "[配置备份] ✓ 已备份: $dst"
    else
        red_echo "[配置备份] ✗ 备份失败: $src"
        return 1
    fi
}

# --- 人工停服标记（用于避免宕机自动恢复误拉起） ---
set_manual_stop_flag() {
    local reason="${1:-manual}"
    echo "$(date +%s) $reason" > "$manual_stop_flag"
    chown $REAL_user:$REAL_user "$manual_stop_flag" 2>/dev/null
}

clear_manual_stop_flag() {
    rm -f "$manual_stop_flag" 2>/dev/null
}

# 初始化日志系统
init_logging() {
    mkdir -p "$log_dir"
    touch "$log_file"
    # 兼容root和普通用户
    if [ -n "$REAL_user" ] && [ "$REAL_user" != "root" ]; then
        chown $REAL_user:$REAL_user "$log_file"
    fi
    exec > >(tee -a "$log_file") 2>&1
    echo "=== 七日杀服务器安装日志 $(date) ==="
}

# 调试信息
debug_info() {
    echo "====== 系统信息 ====="
    echo "当前运行用户: $(whoami)"
    echo "系统架构: $(get_host_arch_raw) ($(detect_host_arch))"
    echo "实际用户: ${REAL_user:-root}"
    echo "用户目录: $home_dir"
    echo "服务器目录: $server_dir"
    echo "SteamCMD目录: $steamcmd_dir"
    echo "日志文件: $log_file"
    echo "内存信息:"
    free -m
    echo "存储信息:"
    df -h
    echo "====================="
}

# 读取安装配置
read_install_config() {
    if [ -f "$config_file" ]; then
        echo "读取安装配置文件: $config_file"
        source "$config_file"
        if [ -n "$SAVED_BASE_DIR" ] && [ -d "$SAVED_BASE_DIR" ]; then
            home_dir="$SAVED_BASE_DIR"
            seven_days_dir="$home_dir/7DaysToDie"
            server_dir="$seven_days_dir/server"
            steamcmd_dir="$home_dir/steamcmd"
            echo "检测到历史安装配置，使用已配置的安装目录: $home_dir"
            return 0
        fi
    fi
    return 1
}

# 保存安装配置
save_install_config() {
    local new_base_dir="$1"
    echo "保存安装配置到: $config_file"
    cat > "$config_file" << EOF
# 七日杀服务器安装配置
# 生成时间: $(date)
# 不要手动修改此文件
SAVED_BASE_DIR="$new_base_dir"
EOF
    chmod 600 "$config_file"
    # 兼容root和普通用户
    if [ -n "$REAL_user" ] && [ "$REAL_user" != "root" ]; then
        chown $REAL_user:$REAL_user "$config_file"
    fi
}

# 检测路径
detect_paths() {
    if [ -z "$home_dir" ]; then
        # 兼容root和普通用户
        if [ "$(whoami)" = "root" ]; then
            home_dir="/root"
        else
            REAL_user=$(who am i | awk '{print $1}')
            home_dir=$(getent passwd "$REAL_user" | cut -d: -f6)
        fi
    fi

    if [ -f "$home_dir/.7dtd_install_config" ]; then
        source "$home_dir/.7dtd_install_config"
        if [ -n "$SAVED_BASE_DIR" ] && [ -d "$SAVED_BASE_DIR" ]; then
            home_dir="$SAVED_BASE_DIR"
        fi
    fi

    seven_days_dir="${seven_days_dir:-$home_dir/7DaysToDie}"
    server_dir="${server_dir:-$seven_days_dir/server}"
    steamcmd_dir="${steamcmd_dir:-$home_dir/steamcmd}"
    config_file="${config_file:-$home_dir/.7dtd_install_config}"
}

# --- 更换 APT 软件源 ---
change_apt_source() {
    if ! grep -q "Ubuntu" /etc/issue 2>/dev/null; then
        yellow_echo "非 Ubuntu 系统，跳过更换软件源步骤。"
        return 0
    fi

    yellow_echo "----------------------------------------------------------------"
    yellow_echo "为了提升后续软件包的下载速度，可选择更换为国内镜像源。"
    yellow_echo "此操作将备份当前的源列表，支持多种国内镜像选择。"
    yellow_echo "----------------------------------------------------------------"

    ubuntu_sources_file="/etc/apt/sources.list.d/ubuntu.sources"
    if [ -f "$ubuntu_sources_file" ]; then
        yellow_echo "检测到 Ubuntu 新格式源文件: $ubuntu_sources_file"
        yellow_echo "为避免与旧格式源文件重复配置，将备份并禁用新格式源文件..."

        backup_time=$(date +%Y%m%d%H%M%S)
        sudo cp "$ubuntu_sources_file" "${ubuntu_sources_file}.bak_${backup_time}" &&             green_echo "已备份: ${ubuntu_sources_file}.bak_${backup_time}"

        sudo truncate -s 0 "$ubuntu_sources_file" &&             green_echo "已清空新格式源文件，避免与旧格式源重复"
    fi

    echo "请选择要使用的软件源（默认：中科大源）："
    echo "1) 中科大源 (mirrors.ustc.edu.cn)"
    echo "2) 腾讯云源 (mirrors.cloud.tencent.com)"
    echo "3) 阿里云源 (mirrors.aliyun.com)"
    echo "4) 南京大学源 (mirror.nju.edu.cn)"
    echo "5) CERNET教育网源 (mirrors.cernet.edu.cn)"
    echo "6) 跳过更换源"
    read -p "请输入选项 (1-6，默认1): " source_choice
    source_choice=${source_choice:-1}

    if [ "$source_choice" -eq 6 ]; then
        green_echo "已选择跳过更换软件源。"
        return 0
    fi

    if ! [[ "$source_choice" =~ ^[1-5]$ ]]; then
        red_echo "无效选择，默认使用中科大源"
        source_choice=1
    fi

    case $source_choice in
        1) mirror="https://mirrors.ustc.edu.cn/ubuntu/"; mirror_name="中科大" ;;
        2) mirror="https://mirrors.cloud.tencent.com/ubuntu/"; mirror_name="腾讯云" ;;
        3) mirror="https://mirrors.aliyun.com/ubuntu/"; mirror_name="阿里云" ;;
        4) mirror="https://mirror.nju.edu.cn/ubuntu/"; mirror_name="南京大学" ;;
        5) mirror="https://mirrors.cernet.edu.cn/ubuntu/"; mirror_name="CERNET教育网" ;;
    esac

    codename=$(lsb_release -cs)
    if [ -z "$codename" ]; then
        red_echo "无法自动检测到系统代号，更换源失败！"
        return 1
    fi
    green_echo "检测到系统代号为: $codename，将更换为$mirror_name源"

    green_echo "正在备份当前源文件 /etc/apt/sources.list ..."
    sudo cp /etc/apt/sources.list "/etc/apt/sources.list.bak_$(date +%F-%T)"

    green_echo "正在写入新的$mirror_name源配置..."

    if [ "$source_choice" -eq 5 ]; then
        sudo tee /etc/apt/sources.list > /dev/null <<EOF
# 默认注释了源码镜像以提高 apt update 速度
deb ${mirror} ${codename} main restricted universe multiverse
# deb-src ${mirror} ${codename} main restricted universe multiverse
deb ${mirror} ${codename}-updates main restricted universe multiverse
# deb-src ${mirror} ${codename}-updates main restricted universe multiverse
deb ${mirror} ${codename}-backports main restricted universe multiverse
# deb-src ${mirror} ${codename}-backports main restricted universe multiverse

# 以下安全更新软件源包含了官方源与镜像站配置
deb http://security.ubuntu.com/ubuntu/ ${codename}-security main restricted universe multiverse
# deb-src http://security.ubuntu.com/ubuntu/ ${codename}-security main restricted universe multiverse
EOF
    else
        sudo tee /etc/apt/sources.list > /dev/null <<EOF
deb $mirror ${codename} main restricted universe multiverse
deb $mirror ${codename}-updates main restricted universe multiverse
deb $mirror ${codename}-backports main restricted universe multiverse
deb $mirror ${codename}-security main restricted universe multiverse
deb-src $mirror ${codename} main restricted universe multiverse
deb-src $mirror ${codename}-updates main restricted universe multiverse
deb-src $mirror ${codename}-backports main restricted universe multiverse
deb-src $mirror ${codename}-security main restricted universe multiverse
EOF
    fi

    green_echo "源文件已更新，正在刷新软件列表 (apt-get update)..."
    sudo apt-get clean
    sudo apt-get update 2>&1 | grep -v "被配置了多次" || true
    green_echo "$mirror_name软件源更换并刷新完成！"
}

# --- 设置系统虚拟内存 ---
set_swap_memory() {
    echo "====== 设置系统虚拟内存 ======"

    swap_flag="$home_dir/.7dtd_swap_set"

    if [ -f /swapfile ] || [ -f "$swap_flag" ]; then
        echo "检测到系统已设置虚拟内存，请选择操作："
        echo "1) 重新设置虚拟内存"
        echo "2) 卸载虚拟内存"
        echo "3) 跳过操作"
        read -p "请输入选项 (1-3): " operation_choice

        case $operation_choice in
            1) echo "您选择了重新设置虚拟内存" ;;
            2)
                echo "开始卸载虚拟内存..."
                if [ -f /swapfile ]; then
                    sudo swapoff /swapfile 2>/dev/null
                    sudo rm -f /swapfile
                fi
                sudo sed -i '/swapfile/d' /etc/fstab
                rm -f "$swap_flag" 2>/dev/null
                green_echo "虚拟内存已成功卸载！"
                free -h
                return 0
                ;;
            3) echo "已跳过虚拟内存操作"; return 0 ;;
            *) red_echo "无效选择，使用默认操作：重新设置" ;;
        esac
    fi

    total_memory=$(free -m | awk '/Mem:/ {print $2}')
    echo "检测到物理内存: $total_memory MB"

    echo "请选择虚拟内存大小设置："
    echo "1) 物理内存的一半 (${total_memory}/2 = $((total_memory / 2)) MB)"
    echo "2) 与物理内存相同 (${total_memory} MB)"
    echo "3) 物理内存的两倍 (${total_memory}*2 = $((total_memory * 2)) MB)"
    echo "4) 自定义大小"
    echo "5) 取消设置"
    read -p "请输入选项 (1-5): " choice

    case $choice in
        1) swap_size=$((total_memory / 2)) ;;
        2) swap_size=$total_memory ;;
        3) swap_size=$((total_memory * 2)) ;;
        4)
            while true; do
                read -p "请输入虚拟内存大小 (MB，建议不小于 ${total_memory}): " custom_swap
                if [[ $custom_swap =~ ^[0-9]+$ ]] && [ $custom_swap -ge 512 ]; then
                    swap_size=$custom_swap
                    break
                else
                    red_echo "请输入有效的数字（至少512MB）"
                fi
            done
            ;;
        5) echo "已取消虚拟内存设置"; return 0 ;;
        *) red_echo "无效选择，使用默认值：物理内存的一半"; swap_size=$((total_memory / 2)) ;;
    esac

    echo "设置虚拟内存大小为: ${swap_size}MB"

    if [ -f /swapfile ]; then
        echo "检测到已存在交换文件，删除旧文件..."
        sudo swapoff /swapfile
        sudo rm -f /swapfile
    fi

    echo "创建 ${swap_size}MB 的交换文件..."
    if ! sudo dd if=/dev/zero of=/swapfile bs=1M count=$swap_size status=progress; then
        red_echo "创建交换文件失败！"
        return 1
    fi

    sudo chmod 600 /swapfile

    echo "格式化交换文件..."
    if ! sudo mkswap /swapfile; then
        red_echo "格式化交换文件失败！"
        sudo rm -f /swapfile
        return 1
    fi

    echo "启用交换文件..."
    if ! sudo swapon /swapfile; then
        red_echo "启用交换文件失败！"
        sudo rm -f /swapfile
        return 1
    fi

    echo "设置开机自动挂载交换文件..."
    if ! grep -q "/swapfile" /etc/fstab; then
        echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
    fi

    touch "$swap_flag"

    echo "虚拟内存设置完成！"
    free -h
}

# --- 系统依赖检查 ---
check_system_dependencies() {
    echo "====== 系统依赖检查（Ubuntu/Debian，含ARM64适配）======"
    print_arch_notice

    local missing_packages=()
    local fix_needed=0
    local arch="$(detect_host_arch)"

    echo "【检查基础命令/软件包】"
    local packages=(wget ca-certificates screen procps sudo tar gzip curl lsof jq unzip bc file libsdl2-2.0-0)
    local pkg
    for pkg in "${packages[@]}"; do
        if dpkg -l 2>/dev/null | grep -q "^ii  $pkg" || command -v "$pkg" >/dev/null 2>&1; then
            green_echo "✓ $pkg 已安装"
        else
            red_echo "✗ 缺少 $pkg"
            missing_packages+=("$pkg")
            fix_needed=1
        fi
    done

    if is_x86_64_host; then
        echo ""
        echo "【检查 x86_64 / SteamCMD 32位运行库】"
        if dpkg --print-foreign-architectures 2>/dev/null | grep -q "i386"; then
            green_echo "✓ i386 架构已启用"
        else
            red_echo "✗ i386 架构未启用"
            missing_packages+=("dpkg --add-architecture i386")
            fix_needed=1
        fi

        local x86_packages=(libc6:i386 libstdc++6:i386 libcurl4-gnutls-dev:i386 lib32gcc-s1)
        for pkg in "${x86_packages[@]}"; do
            if dpkg -l 2>/dev/null | grep -q "^ii  $pkg"; then
                green_echo "✓ $pkg 已安装"
            else
                red_echo "✗ 缺少 $pkg"
                missing_packages+=("$pkg")
                fix_needed=1
            fi
        done
    elif is_arm64_host; then
        echo ""
        echo "【检查 ARM64 兼容层】"
        if get_box64_bin >/dev/null 2>&1; then
            green_echo "✓ Box64 已安装: $(get_box64_bin)"
        else
            red_echo "✗ 缺少 Box64（启动 x86_64 七日杀服务端需要）"
            fix_needed=1
        fi

        if command -v docker >/dev/null 2>&1; then
            green_echo "✓ Docker 已安装"
        else
            red_echo "✗ 缺少 Docker（ARM64 下载/更新服务器推荐使用 DepotDownloader 镜像）"
            fix_needed=1
        fi
    elif is_arm32_host; then
        red_echo "ARM32 无法运行七日杀 64位 Linux 服务端。"
        return 1
    else
        yellow_echo "未知架构：$arch。脚本将只安装基础依赖。"
    fi

    echo ""
    echo "========================================"
    if [ $fix_needed -eq 0 ]; then
        green_echo "✓ 依赖检查通过。"
    else
        red_echo "✗ 检测到缺失依赖或兼容层。"
        echo "需要修复的项目："
        for pkg in "${missing_packages[@]}"; do
            echo "  - $pkg"
        done
        echo ""
        if ask_yes_no "是否立即自动修复？" "Y"; then
            install_dependencies
        fi
    fi
    echo "========================================"
}

# --- 安装系统依赖 ---
install_dependencies() {
    echo "====== 安装系统依赖 ======"
    print_arch_notice

    local base_packages=(
        wget ca-certificates screen procps sudo tar gzip curl lsof jq unzip bc file libsdl2-2.0-0
        nano vim net-tools cron
    )

    sudo apt-get update
    sudo apt-get install -y "${base_packages[@]}"

    if is_x86_64_host; then
        echo "添加32位架构支持（SteamCMD必需）..."
        sudo dpkg --add-architecture i386
        sudo apt-get update

        echo "安装 x86_64 SteamCMD/七日杀运行库..."
        sudo apt-get install -y \
            libc6:i386 \
            libstdc++6:i386 \
            libcurl4-gnutls-dev:i386 \
            lib32gcc-s1 \
            libcurl4-gnutls-dev \
            libgcc-s1 \
            libstdc++6
    elif is_arm64_host; then
        yellow_echo "ARM64 模式：跳过 i386 依赖，改用 Docker + DepotDownloader 下载，Box64 运行 x86_64 服务端。"
        if ask_yes_no "是否安装/修复 ARM64 兼容环境（Docker + Box64）？" "Y"; then
            ensure_docker_available || true
            install_box64_runtime_arm64 || true
        else
            yellow_echo "已跳过 ARM64 兼容环境安装。后续可在主菜单 21 中单独安装。"
        fi
    elif is_arm32_host; then
        red_echo "ARM32 不支持七日杀 64位服务端。"
        return 1
    fi

    green_echo "系统依赖处理完成！"
}

# --- SteamCMD 检查和更新 ---
check_and_update_steamcmd() {
    echo "====== 检查并更新 SteamCMD / 下载工具 ======" 
    detect_paths

    if is_arm64_host; then
        yellow_echo "ARM64 模式不使用本机 SteamCMD，改用 Docker DepotDownloader。"
        ensure_arm64_download_tool
        return $?
    fi

    if [ ! -f "$steamcmd_dir/steamcmd.sh" ]; then
        red_echo "SteamCMD 未安装，开始自动重装..."
        reinstall_steamcmd_now
        return $?
    fi

    echo "运行 SteamCMD 自我更新（300秒超时）..."
    cd "$steamcmd_dir" || return 1
    if timeout 300 ./steamcmd.sh +quit 2>/dev/null; then
        green_echo "✓ SteamCMD 自我更新成功"
        return 0
    else
        local exit_code=$?
        [ $exit_code -eq 124 ] && red_echo "✗ 更新超时（超过300秒）" || red_echo "✗ 更新失败（退出码: $exit_code）"
        red_echo "无人值守模式：立即删除并重新安装 SteamCMD..."
        reinstall_steamcmd_now
        return $?
    fi
}

# --- 重装 SteamCMD ---
reinstall_steamcmd_now() {
    if is_arm64_host; then
        yellow_echo "ARM64 模式：不安装传统 SteamCMD，准备 Docker DepotDownloader。"
        mkdir -p "$steamcmd_dir"
        cat > "$steamcmd_dir/README_ARM64.txt" << EOF
ARM64兼容模式说明：
本机不运行 Valve SteamCMD；安装/更新七日杀使用 Docker 镜像：$ARM64_DEPOT_IMAGE
启动七日杀 x86_64 服务端需要 Box64。
EOF
        ensure_arm64_download_tool
        return $?
    fi

    rm -rf "$steamcmd_dir"
    mkdir -p "$steamcmd_dir"
    cd "$steamcmd_dir" || return 1

    steamcmd_file="steamcmd_latest_bytuluo.tar.gz"
    local download_ok=0
    for url in \
        "http://182.92.78.139:5244/d/alist/DST/steamcmd/${steamcmd_file}?sign=613RJGb_4PXpML8MuloHhLtmPmFM32eK9LAVC4EJI7s=:0" \
        "https://mirrors.aliyun.com/steamcmd/linux/$steamcmd_file" \
        "https://mirrors.cloud.tencent.com/steamcmd/linux/$steamcmd_file" \
        "https://steamcdn-a.akamaihd.net/client/installer/$steamcmd_file"; do
        echo "尝试下载 $url ..."
        rm -f "$steamcmd_file"
        if wget --tries=3 --timeout=30 --progress=bar:force -O "$steamcmd_file" "$url"; then
            if tar -tzf "$steamcmd_file" >/dev/null 2>&1; then
                download_ok=1
                break
            else
                yellow_echo "下载包校验失败，尝试下一个源..."
            fi
        fi
    done

    if [ "$download_ok" -ne 1 ]; then
        red_echo "✗ 所有源下载失败"
        return 1
    fi

    tar -zxf "$steamcmd_file" && rm -f "$steamcmd_file"
    if [ -f "./steamcmd.sh" ]; then
        chmod +x ./steamcmd.sh ./linux32/steamcmd 2>/dev/null
        green_echo "✓ SteamCMD 已自动重装完成"
        return 0
    else
        red_echo "✗ 重装后验证失败"
        return 1
    fi
}

# --- 带重试的七日杀更新（处理 Missing configuration） ---
steamcmd_update_7dtd_with_retry() {
    local beta_branch="$1"
    local max_attempts=3
    local attempt=1
    local update_log=""

    [ -z "$beta_branch" ] && beta_branch="public"

    if is_arm64_host; then
        steam_depot_update_7dtd_arm64 "$beta_branch"
        return $?
    fi

    while [ "$attempt" -le "$max_attempts" ]; do
        echo "============================================="
        echo "SteamCMD 更新尝试 ($attempt/$max_attempts)"
        echo "============================================="
        cd "$steamcmd_dir" || return 1

        echo "[阶段 1/2] 初始化 SteamCMD 客户端..."
        timeout 300 ./steamcmd.sh +quit >/dev/null 2>&1 || true

        echo "[阶段 2/2] 下载/更新七日杀服务器文件（实时日志）..."
        update_log="/tmp/7dtd_steamcmd_update_$$_${attempt}.log"
        timeout 1800 ./steamcmd.sh \
            +@ShutdownOnFailedCommand 1 \
            +@NoPromptForPassword 1 \
            +app_info_update 1 \
            +force_install_dir "$server_dir" \
            +login anonymous \
            +app_update 294420 -beta "$beta_branch" validate \
            +quit 2>&1 | tee "$update_log"
        local rc=${PIPESTATUS[0]}

        if [ "$rc" -eq 0 ]; then
            green_echo "✓ 下载/更新完成"
            rm -f "$update_log"
            return 0
        fi

        if grep -qi "Missing configuration" "$update_log"; then
            yellow_echo "检测到 Missing configuration，正在修复 SteamCMD 后重试..."
            check_and_update_steamcmd || reinstall_steamcmd_now || true
        else
            yellow_echo "SteamCMD 更新失败（退出码: $rc），准备重试..."
            yellow_echo "失败日志: $update_log"
        fi

        rm -f "$update_log"
        attempt=$((attempt + 1))
        [ "$attempt" -le "$max_attempts" ] && sleep 5
    done

    return 1
}

# --- 安装 SteamCMD（已安装则跳过，同步饥荒脚本的超时重装功能） ---
install_steamcmd() {
    echo "====== 安装 SteamCMD / ARM64下载工具 ======"

    if is_arm64_host; then
        yellow_echo "ARM64 模式：准备 Docker DepotDownloader，不安装传统 SteamCMD。"
        mkdir -p "$steamcmd_dir"
        cat > "$steamcmd_dir/README_ARM64.txt" << EOF
ARM64兼容模式：
- 下载/更新：Docker + DepotDownloader ($ARM64_DEPOT_IMAGE)
- 运行服务端：Box64 + 7DaysToDieServer.x86_64
EOF
        ensure_arm64_download_tool
        return $?
    fi

    if [ -f "$steamcmd_dir/steamcmd.sh" ]; then
        green_echo "✓ SteamCMD 已安装在: $steamcmd_dir"
        yellow_echo "如需重新安装，请先删除目录: rm -rf $steamcmd_dir"
        echo "运行 SteamCMD 自我更新（300秒超时）..."
        cd "$steamcmd_dir" || return 1
        if timeout 300 ./steamcmd.sh +quit 2>/dev/null; then
            green_echo "✓ SteamCMD 自我更新成功"
            return 0
        else
            local exit_code=$?
            [ $exit_code -eq 124 ] && red_echo "✗ 更新超时（超过300秒）" || red_echo "✗ 更新失败（退出码: $exit_code）"
            red_echo "无人值守模式：立即删除并重新安装 SteamCMD..."
            reinstall_steamcmd_now
            return $?
        fi
    fi

    reinstall_steamcmd_now
}

# --- 安装/更新七日杀服务器 ---
install_7dtd_server() {
    backup_server_config_auto "install_update"
    echo "====== 安装/更新七日杀服务器 ======"

    if is_arm64_host; then
        ensure_arm64_download_tool || return 1
    elif [ ! -f "$steamcmd_dir/steamcmd.sh" ]; then
        red_echo "SteamCMD 未安装，请先安装 SteamCMD"
        return 1
    fi

    # 初始化备份变量（修复变量作用域问题）
    local backup_dir="$home_dir/7dtd_backups"
    local backup_file=""
    
    # 备份现有配置文件
    if [ -f "$server_dir/serverconfig.xml" ]; then
        backup_file="serverconfig_$(date +%Y%m%d_%H%M%S).xml"
        mkdir -p "$backup_dir"
        cp "$server_dir/serverconfig.xml" "$backup_dir/$backup_file"
        green_echo "✓ 已备份配置文件到: $backup_dir/$backup_file"
    fi

    mkdir -p "$server_dir"

    # 更新前自动备份存档
    auto_backup_current_save "更新前"

    # 读取当前版本，如果不存在则默认为 public
    local current_version=$(get_current_version)
    if [ "$current_version" = "未记录" ] || [ -z "$current_version" ]; then
        current_version="public"
        yellow_echo "未检测到版本记录，默认使用 public 版本"
    else
        green_echo "当前版本: $current_version"
    fi

    echo "正在安装/更新七日杀服务器..."
    echo "版本分支: $current_version"
    # 使用当前版本进行更新
    steamcmd_update_7dtd_with_retry "$current_version"

    if [ $? -eq 0 ]; then
        green_echo "✓ 七日杀服务器安装/更新完成"
        green_echo "  安装目录: $server_dir"
        green_echo "  版本: $current_version"
        
        # 确保版本记录正确
        save_current_version "$current_version"
        
        # 询问是否恢复旧配置（修复：检查backup_file是否非空）
        if [ -n "$backup_file" ] && [ -f "$backup_dir/$backup_file" ]; then
            echo ""
            echo "============================================="
            echo "  服务器更新可能覆盖了配置文件"
            echo "============================================="
            echo ""
            echo "请选择操作："
            echo "y) 使用更新前备份的旧配置文件"
            echo "n) 使用默认新的配置文件"
            echo ""
            read -p "请输入选择 (y/n): " config_choice
            
            if [[ "$config_choice" =~ ^[Yy]$ ]]; then
                echo "正在恢复旧的配置文件..."
                cp "$backup_dir/$backup_file" "$server_dir/serverconfig.xml"
                green_echo "✓ 已恢复旧配置文件"
            else
                yellow_echo "使用新的默认配置文件"
            fi
        fi
        
        # 创建存档目录结构
        ensure_saves_directory
        
        # 如果serveradmin.xml不存在，生成默认的
        local admin_file=$(get_serveradmin_path)
        if [ ! -f "$admin_file" ]; then
            generate_default_serveradmin
        fi
        
        # 修复 Steam 客户端库
        fix_steamclient_so
        
    else
        red_echo "✗ 安装/更新失败"
        return 1
    fi
}
# --- 切换服务器版本 ---
switch_server_version() {
    backup_server_config_auto "switch_version"
    echo "====== 切换服务器版本 ======"

    if is_arm64_host; then
        ensure_arm64_download_tool || return 1
    elif [ ! -f "$steamcmd_dir/steamcmd.sh" ]; then
        red_echo "SteamCMD 未安装"
        return 1
    fi

    local backup_dir="$home_dir/7dtd_backups"
    local backup_file=""

    # 备份现有配置文件
    if [ -f "$server_dir/serverconfig.xml" ]; then
        backup_file="serverconfig_$(date +%Y%m%d_%H%M%S).xml"
        mkdir -p "$backup_dir"
        cp "$server_dir/serverconfig.xml" "$backup_dir/$backup_file"
        green_echo "✓ 已备份配置文件到: $backup_dir/$backup_file"
    fi

    echo "请选择要切换的版本："
    echo ""
    echo "【推荐版本】"
    echo "1) 默认公开版本 (public) - 当前最新稳定版"
    echo "2) latest_experimental - 最新实验版 (不稳定)"
    echo ""
    echo "【2.x 稳定版】"
    echo "3) v2.6 - Version 2.6 Stable"
    echo "4) v2.5 - Version 2.5 Stable"
    echo "5) v2.4 - Version 2.4 Stable"
    echo "6) v2.3 - Version 2.3 Stable"
    echo "7) v2.2 - Version 2.2 Stable"
    echo "8) v2.0 - Version 2.0 Stable"
    echo ""
    echo "【1.x 稳定版】"
    echo "9) v1.4 - Version 1.4 Stable"
    echo ""
    echo "【Alpha 21.x】"
    echo "10) alpha21.2 - Alpha 21.2 Stable"
    echo ""
    echo "【Alpha 20.x】"
    echo "11) alpha20.7 - Alpha 20.7 Stable"
    echo ""
    echo "【Alpha 19.x】"
    echo "12) alpha19.6 - Alpha 19.6 Stable"
    echo ""
    echo "【Alpha 18.x】"
    echo "13) alpha18.4 - Alpha 18.4 Stable"
    echo ""
    echo "【Alpha 17.x】"
    echo "14) alpha17.4 - Alpha 17.4 Stable"
    echo ""
    echo "【更早版本】"
    echo "15) alpha16.4 - Alpha 16.4 Stable"
    echo "16) alpha15.2 - Alpha 15.2 Stable"
    echo "17) alpha14.7 - Alpha 14.7 Stable"
    echo "18) alpha13.8 - Alpha 13.8 Stable"
    echo "19) alpha12.5 - Alpha 12.5 Stable"
    echo "20) alpha11.6 - Alpha 11.6 Stable"
    echo "21) alpha10.4 - Alpha 10.4 Stable"
    echo "22) alpha9.3 - Alpha 9.3 Stable"
    echo "23) alpha8.8 - Alpha 8.8 Stable"
    echo ""
    echo "【自定义】"
    echo "99) 手动输入版本号"
    echo ""
    echo "0) 取消"
    echo ""
    read -p "请输入选项: " version_choice

    local beta_branch=""
    local version_name=""

    case $version_choice in
        1) beta_branch="public"; version_name="默认公开版本 (public)" ;;
        2) beta_branch="latest_experimental"; version_name="最新实验版 (latest_experimental)" ;;
        3) beta_branch="v2.6"; version_name="v2.6 Stable" ;;
        4) beta_branch="v2.5"; version_name="v2.5 Stable" ;;
        5) beta_branch="v2.4"; version_name="v2.4 Stable" ;;
        6) beta_branch="v2.3"; version_name="v2.3 Stable" ;;
        7) beta_branch="v2.2"; version_name="v2.2 Stable" ;;
        8) beta_branch="v2.0"; version_name="v2.0 Stable" ;;
        9) beta_branch="v1.4"; version_name="v1.4 Stable" ;;
        10) beta_branch="alpha21.2"; version_name="Alpha 21.2 Stable" ;;
        11) beta_branch="alpha20.7"; version_name="Alpha 20.7 Stable" ;;
        12) beta_branch="alpha19.6"; version_name="Alpha 19.6 Stable" ;;
        13) beta_branch="alpha18.4"; version_name="Alpha 18.4 Stable" ;;
        14) beta_branch="alpha17.4"; version_name="Alpha 17.4 Stable" ;;
        15) beta_branch="alpha16.4"; version_name="Alpha 16.4 Stable" ;;
        16) beta_branch="alpha15.2"; version_name="Alpha 15.2 Stable" ;;
        17) beta_branch="alpha14.7"; version_name="Alpha 14.7 Stable" ;;
        18) beta_branch="alpha13.8"; version_name="Alpha 13.8 Stable" ;;
        19) beta_branch="alpha12.5"; version_name="Alpha 12.5 Stable" ;;
        20) beta_branch="alpha11.6"; version_name="Alpha 11.6 Stable" ;;
        21) beta_branch="alpha10.4"; version_name="Alpha 10.4 Stable" ;;
        22) beta_branch="alpha9.3"; version_name="Alpha 9.3 Stable" ;;
        23) beta_branch="alpha8.8"; version_name="Alpha 8.8 Stable" ;;
        99)
            echo ""
            echo "请输入要切换的版本号 (例如: v2.5, alpha21.2, experimental 等):"
            read -p "版本号: " custom_version
            if [ -z "$custom_version" ]; then
                red_echo "版本号不能为空"
                return 1
            fi
            beta_branch="$custom_version"
            version_name="自定义版本 ($custom_version)"
            ;;
        0) echo "已取消"; return 0 ;;
        *) red_echo "无效选项"; return 1 ;;
    esac

    # 实验版和旧版本警告
    if [ "$beta_branch" = "latest_experimental" ] || [ "$beta_branch" = "experimental" ]; then
        yellow_echo "警告：实验版可能包含未完成的特性和bug"
        if ! ask_yes_no "确定要切换到实验版吗？" "N"; then
            echo "已取消切换"
            return 0
        fi
    elif [[ "$beta_branch" == alpha* ]] || [[ "$beta_branch" == v1.* ]]; then
        yellow_echo "警告：您选择的版本较旧，可能不兼容新版存档"
        if ! ask_yes_no "确定要切换到 $version_name 吗？" "N"; then
            echo "已取消切换"
            return 0
        fi
    fi

    # 切换版本前自动备份存档
    auto_backup_current_save "切换版本前"
    
    # 备份官方Mod
    backup_official_mods
    
    echo ""
    echo "正在切换到 $version_name ..."
    echo "分支参数: -beta $beta_branch"
    echo ""
    
    # 修复：始终使用 -beta 参数，确保能正确切换版本
    steamcmd_update_7dtd_with_retry "$beta_branch"

    if [ $? -eq 0 ]; then
        green_echo "✓ 已成功切换到 $version_name"
        echo "当前版本: $beta_branch"
        # 保存当前版本到文件
        save_current_version "$beta_branch"

        # 切换版本后可选择恢复旧配置（防止更新覆盖 serverconfig.xml）
        if [ -n "$backup_file" ] && [ -f "$backup_dir/$backup_file" ]; then
            echo ""
            echo "============================================="
            echo "  服务器更新可能覆盖了配置文件"
            echo "============================================="
            echo ""
            echo "请选择操作："
            echo "y) 使用更新前备份的旧配置文件"
            echo "n) 使用默认新的配置文件"
            echo ""
            read -p "请输入选择 (y/n): " config_choice

            if [[ "$config_choice" =~ ^[Yy]$ ]]; then
                echo "正在恢复旧的配置文件..."
                cp "$backup_dir/$backup_file" "$server_dir/serverconfig.xml"
                green_echo "✓ 已恢复旧配置文件"
            else
                yellow_echo "使用新的默认配置文件"
            fi
        fi
    else
        red_echo "✗ 版本切换失败"
        yellow_echo "提示: 请检查版本号是否正确，或查看 SteamCMD 输出了解详情"
        return 1
    fi
}

# --- 备份官方Mod文件夹 ---
backup_official_mods() {
    local mods_dir="$server_dir/Mods"
    local backup_base="$home_dir/7dtd_mods_backup"
    
    # 官方Mod列表
    local official_mods=("0_TFP_Harmony" "TFP_CommandExtensions" "TFP_MapRendering" "TFP_WebServer")
    
    if [ ! -d "$mods_dir" ]; then
        return 0
    fi
    
    # 检查是否有官方mod需要备份
    local has_official=false
    for mod in "${official_mods[@]}"; do
        if [ -d "$mods_dir/$mod" ]; then
            has_official=true
            break
        fi
    done
    
    if [ "$has_official" = false ]; then
        return 0
    fi
    
    # 创建带时间戳的备份目录
    local backup_dir="$backup_base/official_mods_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$backup_dir"
    
    echo "[Mod备份] 正在备份官方Mod..."
    local backed_count=0
    
    for mod in "${official_mods[@]}"; do
        if [ -d "$mods_dir/$mod" ]; then
            if cp -r "$mods_dir/$mod" "$backup_dir/" 2>/dev/null; then
                ((backed_count++))
                echo "  ✓ $mod"
            fi
        fi
    done
    
    if [ $backed_count -gt 0 ]; then
        green_echo "[Mod备份] ✓ 已备份 $backed_count 个官方Mod到: $backup_dir"
        
        # 清理旧备份，只保留最近5个
        local backup_count=$(ls -1d "$backup_base"/official_mods_* 2>/dev/null | wc -l)
        if [ "$backup_count" -gt 5 ]; then
            ls -1td "$backup_base"/official_mods_* | tail -n +6 | xargs rm -rf
            yellow_echo "[Mod备份] 已清理旧备份，保留最近5个"
        fi
    fi
}

# --- 获取官方Mod备份列表 ---
list_official_mod_backups() {
    local backup_base="$home_dir/7dtd_mods_backup"
    ls -1td "$backup_base"/official_mods_* 2>/dev/null
}

# --- 还原官方Mod ---
restore_official_mods() {
    local mods_dir="$server_dir/Mods"
    local backup_base="$home_dir/7dtd_mods_backup"
    
    # 获取最新的备份
    local latest_backup=$(ls -1td "$backup_base"/official_mods_* 2>/dev/null | head -n 1)
    
    if [ -z "$latest_backup" ]; then
        red_echo "未找到官方Mod备份"
        return 1
    fi
    
    if [ ! -d "$mods_dir" ]; then
        mkdir -p "$mods_dir"
    fi
    
    echo "正在从备份还原官方Mod: $(basename "$latest_backup")"
    local restored_count=0
    
    for mod in "0_TFP_Harmony" "TFP_CommandExtensions" "TFP_MapRendering" "TFP_WebServer"; do
        if [ -d "$latest_backup/$mod" ]; then
            # 如果已存在则先删除
            if [ -d "$mods_dir/$mod" ]; then
                rm -rf "$mods_dir/$mod"
            fi
            if cp -r "$latest_backup/$mod" "$mods_dir/" 2>/dev/null; then
                ((restored_count++))
                green_echo "  ✓ 还原 $mod"
            fi
        fi
    done
    
    if [ $restored_count -gt 0 ]; then
        green_echo "✓ 成功还原 $restored_count 个官方Mod"
    else
        yellow_echo "备份中没有找到官方Mod文件"
    fi
}

# --- Mod管理菜单 ---
manage_mods_menu() {
    local mods_dir="$server_dir/Mods"
    
    while true; do
        echo "============================================="
        echo "          Mod管理"
        echo "============================================="
        
        # 显示当前Mod列表
        if [ -d "$mods_dir" ]; then
            echo "当前Mods文件夹内容:"
            local idx=0
            declare -A mod_map
            
            for item in "$mods_dir"/*; do
                if [ -d "$item" ]; then
                    ((idx++))
                    local mod_name=$(basename "$item")
                    mod_map[$idx]="$mod_name"
                    
                    # 标记官方mod
                    if [[ "$mod_name" == "0_TFP_Harmony" || "$mod_name" == "TFP_CommandExtensions" || "$mod_name" == "TFP_MapRendering" || "$mod_name" == "TFP_WebServer" ]]; then
                        echo "  [$idx] $mod_name (官方)"
                    else
                        echo "  [$idx] $mod_name"
                    fi
                fi
            done
            
            if [ $idx -eq 0 ]; then
                echo "  (Mods文件夹为空)"
            fi
            echo ""
        else
            echo "Mods文件夹不存在"
            echo ""
        fi
        
        echo "提示: 如需添加Mod，请直接上传到: $server_dir/Mods"
        echo ""
        echo "操作选项:"
        echo "1. 删除单个Mod"
        echo "2. 清空Mods文件夹并还原官方Mod"
        echo "3. 手动还原官方Mod备份"
        echo "4. 查看官方Mod备份列表"
        echo "0. 返回主菜单"
        echo "============================================="
        read -p "请输入操作编号: " choice
        
        case $choice in
            1)
                echo "====== 删除Mod ======"
                if [ ! -d "$mods_dir" ] || [ -z "$(ls -A "$mods_dir" 2>/dev/null)" ]; then
                    yellow_echo "Mods文件夹为空"
                    break
                fi
                
                echo "选择要删除的Mod:"
                local del_idx=0
                declare -A del_map
                
                for item in "$mods_dir"/*; do
                    if [ -d "$item" ]; then
                        ((del_idx++))
                        local mod_name=$(basename "$item")
                        del_map[$del_idx]="$mod_name"
                        echo "  $del_idx) $mod_name"
                    fi
                done
                
                echo "  0) 取消"
                read -p "请选择: " del_choice
                
                if [[ "$del_choice" =~ ^[0-9]+$ ]] && [ "$del_choice" -ge 1 ] && [ "$del_choice" -le $del_idx ]; then
                    local target_mod="${del_map[$del_choice]}"
                    
                    # 警告官方mod
                    if [[ "$target_mod" == "0_TFP_Harmony" || "$target_mod" == "TFP_CommandExtensions" || "$target_mod" == "TFP_MapRendering" || "$target_mod" == "TFP_WebServer" ]]; then
                        red_echo "警告: '$target_mod' 是官方Mod，删除可能导致服务器报错！"
                        if ! ask_yes_no "确定要删除吗？" "N"; then
                            echo "已取消"
                            break
                        fi
                    else
                        if ! ask_yes_no "确定要删除 '$target_mod' 吗？" "N"; then
                            echo "已取消"
                            break
                        fi
                    fi
                    
                    if rm -rf "$mods_dir/$target_mod"; then
                        green_echo "✓ 已删除 '$target_mod'"
                    else
                        red_echo "✗ 删除失败"
                    fi
                fi
                ;;
            2)
                echo "====== 清空Mods并还原官方Mod ======"
                red_echo "警告: 此操作将删除Mods文件夹中的所有内容！"
                
                # 先备份官方mod
                backup_official_mods
                
                if ask_yes_no "确定要清空Mods文件夹并还原官方Mod吗？" "N"; then
                    if [ -d "$mods_dir" ]; then
                        echo "正在清空Mods文件夹..."
                        rm -rf "$mods_dir"/*
                    fi
                    
                    mkdir -p "$mods_dir"
                    
                    # 还原官方mod
                    restore_official_mods
                    green_echo "✓ Mods文件夹已清空并还原官方Mod"
                else
                    echo "已取消"
                fi
                ;;
            3)
                echo "====== 手动还原官方Mod ======"
                restore_official_mods
                ;;
            4)
                echo "====== 官方Mod备份列表 ======"
                local backups=($(list_official_mod_backups))
                if [ ${#backups[@]} -eq 0 ]; then
                    yellow_echo "没有找到备份"
                else
                    echo "可用的官方Mod备份:"
                    local bidx=0
                    for backup in "${backups[@]}"; do
                        ((bidx++))
                        local bname=$(basename "$backup")
                        local btime=$(stat -c %y "$backup" 2>/dev/null | cut -d'.' -f1)
                        local bsize=$(du -sh "$backup" 2>/dev/null | cut -f1)
                        echo "  $bidx) $bname ($bsize) - $btime"
                    done
                fi
                read -p "按回车键继续..."
                ;;
            0)
                return 0
                ;;
            *)
                red_echo "无效选项"
                ;;
        esac
        echo ""
    done
}

# --- 重装游戏服务器 ---
reinstall_server() {
    backup_server_config_auto "reinstall"
    echo "====== 重装游戏服务器 ======"

    # 读取当前版本，重装后需要恢复
    local current_version=$(get_current_version)
    if [ "$current_version" = "未记录" ] || [ -z "$current_version" ]; then
        current_version="public"
        yellow_echo "未检测到版本记录，重装后将使用 public 版本"
    else
        green_echo "检测到当前版本: $current_version，重装后将保持此版本"
    fi

    yellow_echo "警告：此操作将删除服务器文件但保留存档和配置！"
    if ! ask_yes_no "确定要重装七日杀服务器吗？" "N"; then
        echo "已取消重装"
        return 0
    fi

    # 备份官方Mod
    backup_official_mods

    # 备份存档和配置
    backup_dir="$home_dir/7dtd_backup_$(date +%Y%m%d%H%M%S)"
    mkdir -p "$backup_dir"

    if [ -d "$server_dir/Saves" ]; then
        echo "备份存档..."
        cp -r "$server_dir/Saves" "$backup_dir/"
    fi

    if [ -f "$server_dir/serverconfig.xml" ]; then
        echo "备份配置文件..."
        cp "$server_dir/serverconfig.xml" "$backup_dir/"
    fi

    # 删除服务器目录
    echo "删除服务器目录..."
    rm -rf "$server_dir"

    # 确保版本记录在重装前保存（虽然上面读取了，但以防万一）
    save_current_version "$current_version"

    # 重新安装（使用当前版本）
    echo "开始重新安装服务器（版本: $current_version）..."
    
    mkdir -p "$server_dir"
    
    if is_arm64_host; then
        ensure_arm64_download_tool || return 1
    elif [ ! -f "$steamcmd_dir/steamcmd.sh" ]; then
        red_echo "SteamCMD 未安装，请先安装 SteamCMD"
        return 1
    fi

    steamcmd_update_7dtd_with_retry "$current_version"

    if [ $? -ne 0 ]; then
        red_echo "✗ 服务器下载失败"
        return 1
    fi

    # 恢复版本记录（确保正确）
    save_current_version "$current_version"

    # 恢复存档和配置
    if [ -d "$backup_dir/Saves" ]; then
        echo "恢复存档..."
        mkdir -p "$server_dir/Saves"
        cp -r "$backup_dir/Saves/"* "$server_dir/Saves/"
    fi

    if [ -f "$backup_dir/serverconfig.xml" ]; then
        echo "恢复配置文件..."
        cp "$backup_dir/serverconfig.xml" "$server_dir/"
    fi

    # 恢复官方Mod
    restore_official_mods

    # 创建存档目录结构
    ensure_saves_directory
    
    # 如果serveradmin.xml不存在，生成默认的
    local admin_file=$(get_serveradmin_path)
    if [ ! -f "$admin_file" ]; then
        generate_default_serveradmin
    fi
    
    # 修复 Steam 客户端库
    fix_steamclient_so

    green_echo "✓ 重装完成（版本: $current_version）"
    echo "备份保存在: $backup_dir"
}

# --- 修改配置文件 ---
modify_server_config() {
    echo "====== 修改服务器配置文件 ======"

    config_path="$server_dir/serverconfig.xml"

    if [ ! -f "$config_path" ]; then
        yellow_echo "未找到现有配置文件，将创建新配置..."
        mkdir -p "$server_dir"
    fi

    echo "请选择配置方式："
    echo "1) 交互式修改（基础+高级，推荐）"
    echo "2) 使用默认配置模板"
    echo "3) 手动修改配置文件"
    echo "0) 取消"
    read -p "请输入选项: " config_choice

    case $config_choice in
        1) interactive_config ;;
        2) generate_default_config ;;
        3) edit_existing_config ;;
        0) return 0 ;;
        *) red_echo "无效选项" ;;
    esac
}

# 获取可用的游戏世界列表
get_available_worlds() {
    local worlds_dir="$server_dir/Data/Worlds"
    local worlds=()
    
    if [ -d "$worlds_dir" ]; then
        while IFS= read -r dir; do
            local world_name=$(basename "$dir")
            # 排除 Empty 和 Playtesting 文件夹
            if [[ "$world_name" != "Empty" && "$world_name" != "Playtesting" ]]; then
                worlds+=("$world_name")
            fi
        done < <(find "$worlds_dir" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort)
    fi
    
    echo "${worlds[@]}"
}

# --- 交互式配置 ---
interactive_config() {
    echo "====== 交互式配置服务器 ======"
    echo "[调试] 地图扫描路径: $server_dir/Data/Worlds"

    config_path="$server_dir/serverconfig.xml"

    # 读取当前配置或设置默认值
    if [ -f "$config_path" ]; then
        current_name=$(get_config_value "$config_path" "ServerName")
        current_desc=$(get_config_value "$config_path" "ServerDescription")
        current_port=$(get_config_value "$config_path" "ServerPort")
        current_world=$(get_config_value "$config_path" "GameWorld")
        current_diff=$(get_config_value "$config_path" "GameDifficulty")
        current_maxplayers=$(get_config_value "$config_path" "ServerMaxPlayerCount")
        current_password=$(get_config_value "$config_path" "ServerPassword")
        current_admin_pass=$(get_config_value "$config_path" "TelnetPassword")

        [ -z "$current_name" ] && current_name="$DEFAULT_SERVER_NAME"
        [ -z "$current_desc" ] && current_desc="$DEFAULT_SERVER_DESC"
        [ -z "$current_port" ] && current_port="$DEFAULT_SERVER_PORT"
        [ -z "$current_world" ] && current_world="Navezgane"
        [ -z "$current_diff" ] && current_diff="$DEFAULT_GAME_DIFFICULTY"
        [ -z "$current_maxplayers" ] && current_maxplayers="8"
        [ -z "$current_password" ] && current_password=""
        [ -z "$current_admin_pass" ] && current_admin_pass="admin123"
    else
        current_name="$DEFAULT_SERVER_NAME"
        current_desc="$DEFAULT_SERVER_DESC"
        current_port="$DEFAULT_SERVER_PORT"
        current_world="Navezgane"
        current_diff="$DEFAULT_GAME_DIFFICULTY"
        current_maxplayers="8"
        current_password=""
        current_admin_pass="admin123"
    fi

    echo "请按提示输入配置（直接回车保留当前值）："
    echo ""

    read -p "服务器名称 [$current_name]: " input_name
    server_name="${input_name:-$current_name}"

    read -p "服务器描述 [$current_desc]: " input_desc
    server_desc="${input_desc:-$current_desc}"

    read -p "服务器端口 [$current_port]: " input_port
    server_port="${input_port:-$current_port}"

    # 获取可用的游戏世界列表
    echo "正在扫描可用的游戏世界..."
    available_worlds=($(get_available_worlds))
    
    echo ""
    echo "选择游戏世界："
    echo "1) RWG (随机生成世界)"
    
    local idx=1
    declare -A world_map
    world_map[1]="RWG"
    
    for world in "${available_worlds[@]}"; do
        ((idx++))
        world_map[$idx]="$world"
        # 显示世界名称，如果是 Navezgane 添加说明
        if [ "$world" = "Navezgane" ]; then
            echo "$idx) $world (默认地图)"
        else
            echo "$idx) $world"
        fi
    done
    
    read -p "选择 [$current_world]: " world_choice
    
    if [[ "$world_choice" =~ ^[0-9]+$ ]] && [ "$world_choice" -ge 1 ] && [ "$world_choice" -le $idx ]; then
        server_world="${world_map[$world_choice]}"
    else
        # 检查输入是否匹配某个世界名称
        local found=false
        for world in "${available_worlds[@]}"; do
            if [[ "${world,,}" == "${world_choice,,}" ]]; then
                server_world="$world"
                found=true
                break
            fi
        done
        if [ "$found" = false ]; then
            server_world="$current_world"
        fi
    fi

    if [ "$server_world" = "RWG" ]; then
        read -p "世界生成种子 [MySeed]: " world_seed
        world_seed="${world_seed:-MySeed}"
        
        # 世界大小验证循环
        while true; do
            read -p "世界大小 [6144，必须为1024的倍数]: " world_size
            world_size="${world_size:-6144}"
            
            # 检查是否为数字
            if ! [[ "$world_size" =~ ^[0-9]+$ ]]; then
                red_echo "错误：请输入数字"
                continue
            fi
            
            # 检查是否为1024的倍数
            if [ $((world_size % 1024)) -ne 0 ]; then
                red_echo "错误：世界大小必须是1024的倍数 (如 1024, 2048, 4096, 6144, 8192, 10240等)"
                continue
            fi
            
            # 检查最小值
            if [ "$world_size" -lt 1024 ]; then
                red_echo "错误：世界大小至少为1024"
                continue
            fi
            
            break
        done
    fi

    echo "选择游戏难度："
    echo "0) 冒险 (最简单)"
    echo "1) 普通"
    echo "2) 困难"
    echo "3) 疯狂"
    echo "4) 噩梦"
    echo "5) 极限"
    read -p "选择 [$current_diff]: " diff_choice

    case $diff_choice in
        0|1|2|3|4|5) game_difficulty="$diff_choice" ;;
        *) game_difficulty="$current_diff" ;;
    esac

    read -p "最大玩家数 [$current_maxplayers]: " input_max
    max_players="${input_max:-$current_maxplayers}"

    read -p "服务器密码（留空表示无密码） [$current_password]: " input_pass
    server_password="${input_pass:-$current_password}"

    # 管理员密码验证循环
    while true; do
        read -p "管理员密码（用于游戏内管理，必须英文+数字8位以上） [$current_admin_pass]: " admin_pass
        
        # 如果为空，使用默认密码
        if [ -z "$admin_pass" ]; then
            admin_pass="$current_admin_pass"
            yellow_echo "使用当前管理员密码: $admin_pass"
            break
        fi
        
        # 检查密码长度
        if [ ${#admin_pass} -lt 8 ]; then
            red_echo "错误：密码长度必须至少8位"
            continue
        fi
        
        # 检查是否包含字母
        if ! [[ "$admin_pass" =~ [a-zA-Z] ]]; then
            red_echo "错误：密码必须包含英文字母"
            continue
        fi
        
        # 检查是否包含数字
        if ! [[ "$admin_pass" =~ [0-9] ]]; then
            red_echo "错误：密码必须包含数字"
            continue
        fi
        
        # 密码符合要求
        break
    done

    # 生成配置文件
    generate_config_file

    green_echo "✓ 配置文件已生成: $config_path"
    
    # 提示是否修改高级设置
    echo ""
    if ask_yes_no "是否继续进入高级设置（地区/死亡惩罚/视距等）？" "Y"; then
        modify_advanced_settings
    fi
}

# --- 生成配置文件 ---
generate_config_file() {
    cat > "$config_path" << 'XMLEOF'
<?xml version="1.0"?>
<ServerSettings>
    <!-- ==================== 通用服务器设置 ==================== -->

    <!-- 服务器基本信息 -->
    <property name="ServerName" value="SERVER_NAME_PLACEHOLDER"/> <!-- 服务器名称（大厅显示） -->
    <property name="ServerDescription" value="SERVER_DESC_PLACEHOLDER"/> <!-- 服务器描述 -->
    <property name="ServerWebsiteURL" value=""/> <!-- 服务器网站链接（可留空） -->
    <property name="ServerPassword" value="SERVER_PASS_PLACEHOLDER"/> <!-- 服务器加入密码（空=无密码） -->
    <property name="ServerLoginConfirmationText" value=""/> <!-- 玩家加入确认文本（可留空） -->
    <property name="Region" value="Asia"/> <!-- 大洲（建议 Asia） -->
    <property name="Language" value="Chinese"/> <!-- 语言（建议 Chinese） -->

    <!-- 网络设置 -->
    <property name="ServerPort" value="SERVER_PORT_PLACEHOLDER"/> <!-- 游戏端口 -->
    <property name="ServerVisibility" value="2"/> <!-- 2公开 1好友 0隐藏 -->
    <property name="ServerDisabledNetworkProtocols" value="SteamNetworking"/> <!-- 禁用SteamNetworking，减少网络兼容问题 -->
    <property name="ServerMaxWorldTransferSpeedKiBs" value="1000"/> <!-- 新玩家下载地图速度上限(KiB/s) -->

    <!-- 玩家槽位设置 -->
    <property name="ServerMaxPlayerCount" value="MAX_PLAYERS_PLACEHOLDER"/> <!-- 最大在线人数 -->
    <property name="ServerReservedSlots" value="1"/> <!-- 预留槽位 -->
    <property name="ServerReservedSlotsPermission" value="100"/> <!-- 使用预留槽位所需权限 -->
    <property name="ServerAdminSlots" value="1"/> <!-- 管理员保留槽位 -->
    <property name="ServerAdminSlotsPermission" value="0"/> <!-- 管理员槽位权限，0为最高 -->

    <!-- 管理界面 -->
    <property name="WebDashboardEnabled" value="false"/> <!-- Web控制台开关 -->
    <property name="WebDashboardPort" value="8080"/> <!-- Web控制台端口 -->
    <property name="WebDashboardUrl" value=""/> <!-- 反代URL（可留空） -->
    <property name="EnableMapRendering" value="false"/> <!-- Web地图渲染（耗性能） -->

    <!-- Telnet远程管理 -->
    <property name="TelnetEnabled" value="false"/> <!-- Telnet远程控制开关 -->
    <property name="TelnetPort" value="8081"/> <!-- Telnet端口 -->
    <property name="TelnetPassword" value="TELNET_PASS_PLACEHOLDER"/> <!-- Telnet密码 -->
    <property name="TelnetFailedLoginLimit" value="10"/> <!-- Telnet连续输错次数 -->
    <property name="TelnetFailedLoginsBlocktime" value="10"/> <!-- Telnet输错封禁秒数 -->

    <!-- 终端窗口 -->
    <property name="TerminalWindowEnabled" value="false"/> <!-- 终端窗口（Windows专用） -->

    <!-- 文件夹和文件位置 -->
    <property name="AdminFileName" value="serveradmin.xml"/> <!-- 管理员配置文件名 -->

    <!-- 其他技术设置 -->
    <property name="ServerAllowCrossplay" value="false"/> <!-- 跨平台联机 -->
    <property name="EACEnabled" value="false"/> <!-- EAC反作弊 -->
    <property name="IgnoreEOSSanctions" value="false"/> <!-- 忽略EOS制裁 -->
    <property name="HideCommandExecutionLog" value="0"/> <!-- 命令日志隐藏级别 -->
    <property name="MaxUncoveredMapChunksPerPlayer" value="131072"/> <!-- 玩家地图揭示上限 -->
    <property name="PersistentPlayerProfiles" value="true"/> <!-- 玩家档案绑定（建议开启） -->
    <property name="MaxChunkAge" value="-1"/> <!-- 区块重置天数（-1关闭） -->
    <property name="SaveDataLimit" value="-1"/> <!-- 存档容量限制MB（-1关闭） -->

    <!-- ==================== 游戏玩法设置 ==================== -->

    <!-- 世界设置 -->
    <property name="GameWorld" value="WORLD_NAME_PLACEHOLDER"/> <!-- 地图名（Navezgane/RWG/预制图） -->
    <property name="WorldGenSeed" value="WORLD_SEED_PLACEHOLDER"/> <!-- RWG地图种子 -->
    <property name="WorldGenSize" value="WORLD_SIZE_PLACEHOLDER"/> <!-- RWG地图尺寸 -->
    <property name="GameName" value="MyGame"/> <!-- 存档名 -->
    <property name="GameMode" value="GameModeSurvival"/> <!-- 游戏模式 -->

    <!-- 难度设置 -->
    <property name="GameDifficulty" value="DIFFICULTY_PLACEHOLDER"/> <!-- 难度 0-5 -->
    <property name="BlockDamagePlayer" value="100"/>
    <property name="BlockDamageAI" value="100"/>
    <property name="BlockDamageAIBM" value="100"/>
    <property name="XPMultiplier" value="100"/>
    <property name="PlayerSafeZoneLevel" value="5"/>
    <property name="PlayerSafeZoneHours" value="5"/>

    <!-- 游戏规则 -->
    <property name="BuildCreate" value="false"/> <!-- 创造模式 -->
    <property name="DayNightLength" value="60"/> <!-- 一天总时长（分钟） -->
    <property name="DayLightLength" value="18"/> <!-- 白天时长（小时） -->
    <property name="BiomeProgression" value="true"/>
    <property name="StormFreq" value="50"/>
    <property name="DeathPenalty" value="1"/> <!-- 死亡惩罚 -->
    <property name="DropOnDeath" value="1"/> <!-- 死亡掉落规则 -->
    <property name="DropOnQuit" value="0"/>
    <property name="BedrollDeadZoneSize" value="15"/>
    <property name="BedrollExpiryTime" value="45"/>
    <property name="AllowSpawnNearFriend" value="2"/>
    <property name="CameraRestrictionMode" value="0"/>
    <property name="JarRefund" value="60"/>

    <!-- 性能相关 -->
    <property name="MaxSpawnedZombies" value="48"/> <!-- 全图最大僵尸数（高=更吃性能） -->
    <property name="MaxSpawnedAnimals" value="50"/> <!-- 全图最大动物数 -->
    <property name="ServerMaxAllowedViewDistance" value="6"/> <!-- 客户端可申请最大视距 -->
    <property name="MaxQueuedMeshLayers" value="500"/> <!-- 网格队列上限（高=更吃内存） -->

    <!-- 僵尸设置 -->
    <property name="EnemySpawnMode" value="true"/>
    <property name="EnemyDifficulty" value="0"/>
    <property name="ZombieFeralSense" value="2"/>
    <property name="ZombieMove" value="1"/>
    <property name="ZombieMoveNight" value="2"/>
    <property name="ZombieFeralMove" value="3"/>
    <property name="ZombieBMMove" value="3"/>
    <property name="AISmellMode" value="3"/>
    <property name="BloodMoonFrequency" value="7"/> <!-- 血月周期（天） -->
    <property name="BloodMoonRange" value="0"/>
    <property name="BloodMoonWarning" value="8"/>
    <property name="BloodMoonEnemyCount" value="48"/>

    <!-- 战利品设置 -->
    <property name="LootAbundance" value="100"/> <!-- 物资丰度百分比 -->
    <property name="LootRespawnDays" value="28"/> <!-- 容器重生天数 -->
    <property name="AirDropFrequency" value="72"/>
    <property name="AirDropMarker" value="true"/>

    <!-- 多人游戏设置 -->
    <property name="PartySharedKillRange" value="500"/>
    <property name="PlayerKillingMode" value="0"/> <!-- PVP模式 0禁用 3全开 -->

    <!-- 领地声明选项 -->
    <property name="LandClaimCount" value="3"/>
    <property name="LandClaimSize" value="41"/>
    <property name="LandClaimDeadZone" value="30"/>
    <property name="LandClaimExpiryTime" value="7"/>
    <property name="LandClaimDecayMode" value="2"/>
    <property name="LandClaimOnlineDurabilityModifier" value="4"/>
    <property name="LandClaimOfflineDurabilityModifier" value="4"/>
    <property name="LandClaimOfflineDelay" value="0"/>

    <!-- 动态网格系统 -->
    <property name="DynamicMeshEnabled" value="true"/>
    <property name="DynamicMeshLandClaimOnly" value="true"/>
    <property name="DynamicMeshLandClaimBuffer" value="3"/>
    <property name="DynamicMeshMaxItemCache" value="3"/>

    <!-- Twitch直播集成 -->
    <property name="TwitchServerPermission" value="90"/>
    <property name="TwitchBloodMoonAllowed" value="false"/>

    <!-- 任务进度每日限制 -->
    <property name="QuestProgressionDailyLimit" value="3"/>
</ServerSettings>
XMLEOF

    # 替换占位符
    sed -i "s/SERVER_NAME_PLACEHOLDER/$server_name/g" "$config_path"
    sed -i "s/SERVER_DESC_PLACEHOLDER/$server_desc/g" "$config_path"
    sed -i "s/SERVER_PORT_PLACEHOLDER/$server_port/g" "$config_path"
    sed -i "s/SERVER_PASS_PLACEHOLDER/$server_password/g" "$config_path"
    sed -i "s/MAX_PLAYERS_PLACEHOLDER/$max_players/g" "$config_path"
    sed -i "s/TELNET_PASS_PLACEHOLDER/$admin_pass/g" "$config_path"
    sed -i "s/WORLD_NAME_PLACEHOLDER/$server_world/g" "$config_path"
    sed -i "s/DIFFICULTY_PLACEHOLDER/$game_difficulty/g" "$config_path"

    if [ "$server_world" = "RWG" ]; then
        sed -i "s/WORLD_SEED_PLACEHOLDER/$world_seed/g" "$config_path"
        sed -i "s/WORLD_SIZE_PLACEHOLDER/$world_size/g" "$config_path"
    else
        sed -i "s/WORLD_SEED_PLACEHOLDER/MySeed/g" "$config_path"
        sed -i "s/WORLD_SIZE_PLACEHOLDER/6144/g" "$config_path"
    fi
}

# --- 使用默认配置 ---
generate_default_config() {
    config_path="$server_dir/serverconfig.xml"

    server_name="$DEFAULT_SERVER_NAME"
    server_desc="$DEFAULT_SERVER_DESC"
    server_port="$DEFAULT_SERVER_PORT"
    server_password=""
    max_players="8"
    admin_pass="admin123"
    server_world="Navezgane"
    game_difficulty="1"

    generate_config_file

    green_echo "✓ 默认配置文件已生成: $config_path"
    yellow_echo "提示：您可以在主菜单使用选项1进行交互式修改，或选项3手动修改配置文件"
}

# --- 编辑现有配置 ---
edit_existing_config() {
    config_path="$server_dir/serverconfig.xml"

    if [ ! -f "$config_path" ]; then
        red_echo "未找到现有配置文件"
        return 1
    fi

    echo "请选择编辑方式："
    echo "1) 使用 nano 编辑"
    echo "2) 使用 vim 编辑"
    echo "3) 显示配置文件路径，手动编辑"
    read -p "请选择: " edit_choice

    case $edit_choice in
        1) nano "$config_path" ;;
        2) vim "$config_path" ;;
        3) 
            echo "配置文件路径: $config_path"
            echo "您可以使用SFTP或SSH下载编辑后上传"
            ;;
        *) red_echo "无效选项" ;;
    esac
}

# --- 修改服务器高级设置 ---
# --- 获取配置值（如果存在）---
get_config_value() {
    local file="$1"
    local key="$2"
    awk -v key="$key" '
        $0 ~ /<property/ && $0 ~ ("name=\"" key "\"") {
            if (match($0, /value="[^"]*"/)) {
                print substr($0, RSTART + 7, RLENGTH - 8)
                exit
            }
        }
    ' "$file" 2>/dev/null || echo ""
}

# --- 检查配置是否存在 ---
config_exists() {
    local file="$1"
    local key="$2"
    grep -q "name=\"$key\"" "$file" 2>/dev/null
}

# --- 修改配置值（只修改已有配置）---
update_config_value() {
    local file="$1"
    local key="$2"
    local newval="$3"
    
    if config_exists "$file" "$key"; then
        sed -i "s|<property name=\"$key\" value=\"[^\"]*\"|<property name=\"$key\" value=\"$newval\"|g" "$file"
        return 0
    else
        return 1
    fi
}

# --- 启动参数说明 ---
show_startup_flags_help() {
    echo "====== 启动参数说明 ======"
    echo "-dedicated  : 专用服务器模式（建议始终启用）"
    echo "-batchmode  : 后台批处理模式，减少交互依赖"
    echo "-nographics : 禁用图形渲染，通常更省资源"
    echo "-quit       : 当启动失败或异常时尽快退出，便于守护脚本拉起"
    echo ""
    echo "内置预设说明："
    echo "标准模式(standard)      : 稳定推荐，兼顾资源占用与运行稳定"
    echo "性能模式(performance)   : 偏性能，强制无图形与批处理"
    echo "兼容模式(compatible)    : 兼容排障，关闭 -nographics"
    echo "最小模式(minimal)       : 最小参数，仅保留必要启动参数"
    echo "调试模式(debug)         : 调试排障，保留更多运行上下文"
    echo "自定义模式(custom)      : 仅使用你手动输入的参数"
}

# --- 启动相关配置（serverconfig 联动） ---
setup_startup_related_config() {
    local config_path="$server_dir/serverconfig.xml"
    if [ ! -f "$config_path" ]; then
        red_echo "未找到 serverconfig.xml"
        return 1
    fi

    local telnet_enabled terminal_enabled
    telnet_enabled=$(get_config_value "$config_path" "TelnetEnabled")
    terminal_enabled=$(get_config_value "$config_path" "TerminalWindowEnabled")

    echo "====== 启动相关配置（serverconfig）======"
    echo "1) Telnet远程控制开关（TelnetEnabled）            : ${telnet_enabled:-未设置}"
    echo "2) 终端窗口开关（TerminalWindowEnabled）         : ${terminal_enabled:-未设置}"
    echo "0) 返回"
    read -p "请选择要切换的项: " cfg_choice

    case "$cfg_choice" in
        1)
            if [ "${telnet_enabled,,}" = "true" ]; then
                update_config_value "$config_path" "TelnetEnabled" "false" && green_echo "✓ TelnetEnabled 已改为 false"
            else
                update_config_value "$config_path" "TelnetEnabled" "true" && green_echo "✓ TelnetEnabled 已改为 true"
            fi
            ;;
        2)
            if [ "${terminal_enabled,,}" = "true" ]; then
                update_config_value "$config_path" "TerminalWindowEnabled" "false" && green_echo "✓ TerminalWindowEnabled 已改为 false"
            else
                update_config_value "$config_path" "TerminalWindowEnabled" "true" && green_echo "✓ TerminalWindowEnabled 已改为 true"
            fi
            ;;
        0) return 0 ;;
        *) red_echo "无效选项" ;;
    esac
}

# --- 获取启动参数预设 ---
get_server_startup_flags() {
    local preset_file="$home_dir/.7dtd_startup_preset.conf"
    local STARTUP_PRESET="standard"
    local CUSTOM_ARGS=""
    local EXTRA_ARGS=""
    local FORCE_DEDICATED="1"
    local FORCE_BATCHMODE="1"
    local FORCE_NOGRAPHICS="1"
    local FORCE_QUIT="1"
    local flags=""

    if [ -f "$preset_file" ]; then
        source "$preset_file" 2>/dev/null
    fi

    case "$STARTUP_PRESET" in
        standard)    flags="-quit -batchmode -nographics -dedicated" ;;
        performance) flags="-quit -batchmode -nographics -dedicated" ;;
        compatible)  flags="-quit -batchmode -dedicated" ;;
        minimal)     flags="-batchmode -dedicated" ;;
        debug)       flags="-batchmode -dedicated" ;;
        custom)
            if [ -n "$CUSTOM_ARGS" ]; then
                flags="$CUSTOM_ARGS"
            else
                flags="-quit -batchmode -nographics -dedicated"
            fi
            ;;
        *) flags="-quit -batchmode -nographics -dedicated" ;;
    esac

    # 开关覆盖：可在预设基础上启用/禁用关键参数
    if [ "$FORCE_DEDICATED" = "1" ]; then
        flags="$flags -dedicated"
    else
        flags=$(echo " $flags " | sed 's/ -dedicated / /g')
    fi

    if [ "$FORCE_BATCHMODE" = "1" ]; then
        flags="$flags -batchmode"
    else
        flags=$(echo " $flags " | sed 's/ -batchmode / /g')
    fi

    if [ "$FORCE_NOGRAPHICS" = "1" ]; then
        flags="$flags -nographics"
    else
        flags=$(echo " $flags " | sed 's/ -nographics / /g')
    fi

    if [ "$FORCE_QUIT" = "1" ]; then
        flags="$flags -quit"
    else
        flags=$(echo " $flags " | sed 's/ -quit / /g')
    fi

    # 附加参数：用于自定义扩展（例如调试标记）
    if [ -n "$EXTRA_ARGS" ]; then
        flags="$flags $EXTRA_ARGS"
    fi

    # 去重
    local out=""
    local token=""
    for token in $flags; do
        case " $out " in
            *" $token "*) ;;
            *) out="$out $token" ;;
        esac
    done
    echo "$out" | xargs
}

# --- 启动参数预设管理 ---
setup_startup_preset() {
    local preset_file="$home_dir/.7dtd_startup_preset.conf"
    local STARTUP_PRESET="standard"
    local CUSTOM_ARGS=""
    local EXTRA_ARGS=""
    local FORCE_DEDICATED="1"
    local FORCE_BATCHMODE="1"
    local FORCE_NOGRAPHICS="1"
    local FORCE_QUIT="1"

    if [ -f "$preset_file" ]; then
        source "$preset_file" 2>/dev/null
    fi

    while true; do
        echo "====== 启动参数预设管理 ======"
        echo "当前预设: ${STARTUP_PRESET}"
        echo "参数开关: 专用模式(dedicated)=$FORCE_DEDICATED 批处理(batchmode)=$FORCE_BATCHMODE 无图形(nographics)=$FORCE_NOGRAPHICS 失败退出(quit)=$FORCE_QUIT"
        [ -n "$EXTRA_ARGS" ] && echo "附加参数: $EXTRA_ARGS"
        [ "$STARTUP_PRESET" = "custom" ] && [ -n "$CUSTOM_ARGS" ] && echo "自定义参数: $CUSTOM_ARGS"
        echo "当前生效参数: $(get_server_startup_flags) -configfile=serverconfig.xml"
        echo ""
        echo "1) 选择预设（标准/性能/兼容/最小/调试/自定义）"
        echo "2) 调整关键参数开关（专用模式/批处理/无图形/失败退出）"
        echo "3) 设置附加参数（在预设后追加）"
        echo "4) 设置完整自定义参数（仅 custom 预设生效）"
        echo "5) 查看参数说明"
        echo "6) 启动相关功能设置（Telnet远程控制/终端窗口）"
        echo "0) 保存并返回"
        read -p "请选择: " preset_choice

        case "$preset_choice" in
            1)
                echo "可选预设:"
                echo "1) 标准模式（standard，推荐）"
                echo "2) 性能模式（performance，无图形）"
                echo "3) 兼容模式（compatible，排障）"
                echo "4) 最小模式（minimal）"
                echo "5) 调试模式（debug）"
                echo "6) 自定义模式（custom）"
                read -p "请选择预设 [默认1]: " profile_choice
                case "${profile_choice:-1}" in
                    1) STARTUP_PRESET="standard" ;;
                    2) STARTUP_PRESET="performance" ;;
                    3) STARTUP_PRESET="compatible" ;;
                    4) STARTUP_PRESET="minimal" ;;
                    5) STARTUP_PRESET="debug" ;;
                    6) STARTUP_PRESET="custom" ;;
                    *) red_echo "无效选择" ;;
                esac
                ;;
            2)
                echo "当前开关:"
                echo "1) 专用模式（dedicated）   : $FORCE_DEDICATED"
                echo "2) 批处理模式（batchmode） : $FORCE_BATCHMODE"
                echo "3) 无图形模式（nographics）: $FORCE_NOGRAPHICS"
                echo "4) 失败退出（quit）        : $FORCE_QUIT"
                read -p "输入要切换的编号(1-4): " toggle_choice
                case "$toggle_choice" in
                    1) [ "$FORCE_DEDICATED" = "1" ] && FORCE_DEDICATED="0" || FORCE_DEDICATED="1" ;;
                    2) [ "$FORCE_BATCHMODE" = "1" ] && FORCE_BATCHMODE="0" || FORCE_BATCHMODE="1" ;;
                    3) [ "$FORCE_NOGRAPHICS" = "1" ] && FORCE_NOGRAPHICS="0" || FORCE_NOGRAPHICS="1" ;;
                    4) [ "$FORCE_QUIT" = "1" ] && FORCE_QUIT="0" || FORCE_QUIT="1" ;;
                    *) red_echo "无效选择" ;;
                esac
                ;;
            3)
                echo "示例附加参数: -someflag -anotherflag=value"
                read -p "请输入附加参数（留空清除）: " EXTRA_ARGS
                if [ -n "$EXTRA_ARGS" ] && ! echo "$EXTRA_ARGS" | grep -Eq '^[a-zA-Z0-9_./=:+ -]+$'; then
                    red_echo "附加参数包含非法字符，已忽略本次输入"
                    EXTRA_ARGS=""
                fi
                ;;
            4)
                echo "示例: -quit -batchmode -nographics -dedicated"
                read -p "请输入完整自定义参数: " CUSTOM_ARGS
                if [ -n "$CUSTOM_ARGS" ] && ! echo "$CUSTOM_ARGS" | grep -Eq '^[a-zA-Z0-9_./=:+ -]+$'; then
                    red_echo "自定义参数包含非法字符，已忽略本次输入"
                    CUSTOM_ARGS=""
                fi
                ;;
            5)
                show_startup_flags_help
                read -p "按回车键继续..."
                ;;
            6)
                setup_startup_related_config
                read -p "按回车键继续..."
                ;;
            0)
                break
                ;;
            *)
                red_echo "无效选项"
                ;;
        esac
    done

    cat > "$preset_file" << EOF
# 七日杀启动参数预设配置
# STARTUP_PRESET: standard/performance/compatible/minimal/debug/custom
# FORCE_* 开关: 1=启用该参数, 0=禁用该参数
# EXTRA_ARGS: 在预设参数后追加
# CUSTOM_ARGS: 当 STARTUP_PRESET=custom 时使用
STARTUP_PRESET="$STARTUP_PRESET"
CUSTOM_ARGS="$CUSTOM_ARGS"
EXTRA_ARGS="$EXTRA_ARGS"
FORCE_DEDICATED="$FORCE_DEDICATED"
FORCE_BATCHMODE="$FORCE_BATCHMODE"
FORCE_NOGRAPHICS="$FORCE_NOGRAPHICS"
FORCE_QUIT="$FORCE_QUIT"
EOF
    chmod 600 "$preset_file"
    chown $REAL_user:$REAL_user "$preset_file" 2>/dev/null

    green_echo "✓ 启动参数预设已保存"
    echo "当前生效参数: $(get_server_startup_flags) -configfile=serverconfig.xml"
}

# --- 管理员操作审计 ---
audit_admin_action() {
    local action="$1"
    local details="$2"
    local audit_file="$home_dir/7dtd_admin_audit.log"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] user=$(whoami) action=${action} details=${details}" >> "$audit_file"
}

# --- Telnet会话模式 ---
open_telnet_console_session() {
    local config_path="$server_dir/serverconfig.xml"
    if [ ! -f "$config_path" ]; then
        red_echo "未找到 serverconfig.xml"
        return 1
    fi

    local telnet_enabled telnet_port
    telnet_enabled=$(get_config_value "$config_path" "TelnetEnabled")
    telnet_port=$(get_config_value "$config_path" "TelnetPort")
    telnet_port=${telnet_port:-8081}

    if [ "${telnet_enabled,,}" != "true" ]; then
        yellow_echo "7DTD 原生不提供标准 RCON，会话控制使用 Telnet。"
        if ask_yes_no "检测到 Telnet 未启用，是否现在自动启用并写入配置" "Y"; then
            update_config_value "$config_path" "TelnetEnabled" "true" >/dev/null 2>&1
            [ -z "$telnet_port" ] && update_config_value "$config_path" "TelnetPort" "8081" >/dev/null 2>&1
            green_echo "✓ 已启用 Telnet（配置已写入）"
            yellow_echo "请重启服务器后再进入会话模式。"
        else
            yellow_echo "已取消启用 Telnet"
        fi
        return 1
    fi

    if ! command -v telnet >/dev/null 2>&1; then
        red_echo "系统未安装 telnet 客户端，请安装后重试 (apt install telnet)"
        return 1
    fi

    echo "====== 游戏服务器控制台会话（Telnet） ======"
    yellow_echo "即将连接 127.0.0.1:$telnet_port"
    yellow_echo "连接后按提示输入 TelnetPassword，即可连续输入控制台命令。"
    yellow_echo "退出会话: 输入 exit 或按 Ctrl+] 后输入 quit"
    read -p "按回车开始连接..."
    telnet 127.0.0.1 "$telnet_port"
}

# --- 日志与备份自动清理 ---
setup_cleanup_policy() {
    local config_file="$home_dir/.7dtd_cleanup.conf"
    local cleanup_script="$home_dir/7dtd_cleanup.sh"
    local cron_file="/etc/cron.d/7dtd_cleanup"

    local enabled=0
    local log_keep_days=7
    local backup_keep_days=14
    local output_log_keep_count=30

    if [ -f "$config_file" ]; then
        source "$config_file" 2>/dev/null
    fi

    echo "====== 自动清理日志与备份 ======"
    echo "当前状态: $([ "$enabled" = "1" ] && echo '已启用' || echo '未启用')"
    echo "日志保留天数: $log_keep_days 天"
    echo "备份保留天数: $backup_keep_days 天"
    echo "output_log 保留数量: $output_log_keep_count 个"
    echo ""
    echo "1) 启用/更新清理策略"
    echo "2) 关闭清理策略"
    echo "3) 立即执行一次清理"
    echo "4) 查看清理日志"
    echo "0) 返回"
    read -p "请选择: " choice

    case "$choice" in
        1)
            read -p "日志保留天数 [默认7]: " input_log_days
            read -p "备份保留天数 [默认14]: " input_backup_days
            read -p "output_log 保留数量 [默认30]: " input_log_count
            log_keep_days=${input_log_days:-7}
            backup_keep_days=${input_backup_days:-14}
            output_log_keep_count=${input_log_count:-30}

            cat > "$config_file" << EOF
enabled=1
log_keep_days=$log_keep_days
backup_keep_days=$backup_keep_days
output_log_keep_count=$output_log_keep_count
EOF
            chmod 600 "$config_file"
            chown $REAL_user:$REAL_user "$config_file" 2>/dev/null

            cat > "$cleanup_script" << 'EOF'
#!/bin/bash
CONFIG_FILE="CONFIG_FILE_PLACEHOLDER"
source "$CONFIG_FILE" 2>/dev/null
enabled=${enabled:-0}
log_keep_days=${log_keep_days:-7}
backup_keep_days=${backup_keep_days:-14}
output_log_keep_count=${output_log_keep_count:-30}

if [ "$enabled" != "1" ]; then
    exit 0
fi

current_user=$(whoami)
if [ "$current_user" = "root" ]; then
    home_dir="/root"
else
    home_dir="$HOME"
fi

server_dir="$home_dir/7DaysToDie/server"
backup_dir="$home_dir/7dtd_save_backups"
log_file="$home_dir/7dtd_cleanup.log"

echo "[$(date '+%Y-%m-%d %H:%M:%S')] 开始清理" >> "$log_file"

find "$server_dir" -maxdepth 1 -type f -name "output_log*.txt" -mtime +"$log_keep_days" -delete 2>/dev/null
find "$backup_dir" -type f -name "*.tar.gz" -mtime +"$backup_keep_days" -delete 2>/dev/null

ls -1t "$server_dir"/output_log*.txt 2>/dev/null | tail -n +$((output_log_keep_count + 1)) | xargs -r rm -f

echo "[$(date '+%Y-%m-%d %H:%M:%S')] 清理完成" >> "$log_file"
EOF
            sed -i "s|CONFIG_FILE_PLACEHOLDER|$config_file|g" "$cleanup_script"
            chmod +x "$cleanup_script"
            chown $REAL_user:$REAL_user "$cleanup_script" 2>/dev/null

            sudo tee "$cron_file" > /dev/null << EOF
# 七日杀日志与备份清理 (每天凌晨4点)
0 4 * * * root $cleanup_script
EOF
            green_echo "✓ 自动清理策略已启用"
            ;;
        2)
            sudo rm -f "$cron_file"
            rm -f "$config_file" "$cleanup_script"
            green_echo "✓ 自动清理策略已关闭（配置/脚本/计划任务已删除）"
            ;;
        3)
            if [ -f "$cleanup_script" ]; then
                bash "$cleanup_script"
                green_echo "✓ 已执行清理"
            else
                yellow_echo "未找到清理脚本，请先启用策略"
            fi
            ;;
        4)
            local cleanup_log="$home_dir/7dtd_cleanup.log"
            if [ -f "$cleanup_log" ]; then
                tail -20 "$cleanup_log"
            else
                yellow_echo "暂无清理日志"
            fi
            ;;
        0) return 0 ;;
        *) red_echo "无效选项" ;;
    esac
}

# --- 修改服务器高级设置（可选配置）---
modify_advanced_settings() {
    local config_path="$server_dir/serverconfig.xml"
    
    if [ ! -f "$config_path" ]; then
        red_echo "未找到服务器配置文件，请先安装服务器"
        return 1
    fi
    
    while true; do
        local menu_items=()
        local item_keys=()
        local idx=0
        
        echo "============================================="
        echo "          修改服务器配置"
        echo "============================================="
        
        # 常规设置
        echo ""
        echo "--- 常规设置 ---"
        if config_exists "$config_path" "ServerName"; then
            ((idx++))
            local val=$(get_config_value "$config_path" "ServerName")
            echo "$idx. 服务器名称              [$val]"
            menu_items[$idx]="服务器名称"
            item_keys[$idx]="ServerName"
        fi
        if config_exists "$config_path" "ServerDescription"; then
            ((idx++))
            local val=$(get_config_value "$config_path" "ServerDescription")
            echo "$idx. 服务器描述              [$val]"
            menu_items[$idx]="服务器描述"
            item_keys[$idx]="ServerDescription"
        fi
        if config_exists "$config_path" "ServerPassword"; then
            ((idx++))
            local val=$(get_config_value "$config_path" "ServerPassword")
            [ -z "$val" ] && val="(无)"
            echo "$idx. 服务器密码              [$val]"
            menu_items[$idx]="服务器密码"
            item_keys[$idx]="ServerPassword"
        fi
        if config_exists "$config_path" "ServerPort"; then
            ((idx++))
            local val=$(get_config_value "$config_path" "ServerPort")
            echo "$idx. 服务器端口              [$val]"
            menu_items[$idx]="服务器端口"
            item_keys[$idx]="ServerPort"
        fi
        if config_exists "$config_path" "ServerVisibility"; then
            ((idx++))
            local val=$(get_config_value "$config_path" "ServerVisibility")
            local desc=""
            case "$val" in
                0) desc="不列出" ;;
                1) desc="仅好友" ;;
                2) desc="公开" ;;
            esac
            echo "$idx. 服务器可见性            [$val=$desc]"
            menu_items[$idx]="服务器可见性"
            item_keys[$idx]="ServerVisibility"
        fi
        if config_exists "$config_path" "ServerMaxPlayerCount"; then
            ((idx++))
            local val=$(get_config_value "$config_path" "ServerMaxPlayerCount")
            echo "$idx. 最大玩家数量            [$val]"
            menu_items[$idx]="最大玩家数量"
            item_keys[$idx]="ServerMaxPlayerCount"
        fi
        if config_exists "$config_path" "EACEnabled"; then
            ((idx++))
            local val=$(get_config_value "$config_path" "EACEnabled")
            echo "$idx. EAC反作弊               [$val]"
            menu_items[$idx]="EAC反作弊"
            item_keys[$idx]="EACEnabled"
        fi
        
        # 世界设置
        echo ""
        echo "--- 世界设置 ---"
        if config_exists "$config_path" "GameWorld"; then
            ((idx++))
            local val=$(get_config_value "$config_path" "GameWorld")
            echo "$idx. 游戏世界                [$val]"
            menu_items[$idx]="游戏世界"
            item_keys[$idx]="GameWorld"
        fi
        if config_exists "$config_path" "WorldGenSeed"; then
            ((idx++))
            local val=$(get_config_value "$config_path" "WorldGenSeed")
            echo "$idx. 世界生成种子            [$val]"
            menu_items[$idx]="世界生成种子"
            item_keys[$idx]="WorldGenSeed"
        fi
        if config_exists "$config_path" "WorldGenSize"; then
            ((idx++))
            local val=$(get_config_value "$config_path" "WorldGenSize")
            echo "$idx. 世界大小                [$val]"
            menu_items[$idx]="世界大小"
            item_keys[$idx]="WorldGenSize"
        fi
        if config_exists "$config_path" "GameName"; then
            ((idx++))
            local val=$(get_config_value "$config_path" "GameName")
            echo "$idx. 游戏名称(存档名)        [$val]"
            menu_items[$idx]="游戏名称"
            item_keys[$idx]="GameName"
        fi
        if config_exists "$config_path" "GameMode"; then
            ((idx++))
            local val=$(get_config_value "$config_path" "GameMode")
            echo "$idx. 游戏模式                [$val]"
            menu_items[$idx]="游戏模式"
            item_keys[$idx]="GameMode"
        fi
        
        # 游戏玩法设置
        echo ""
        echo "--- 游戏玩法 ---"
        if config_exists "$config_path" "GameDifficulty"; then
            ((idx++))
            local val=$(get_config_value "$config_path" "GameDifficulty")
            echo "$idx. 游戏难度                [$val]"
            menu_items[$idx]="游戏难度"
            item_keys[$idx]="GameDifficulty"
        fi
        if config_exists "$config_path" "BlockDamagePlayer"; then
            ((idx++))
            local val=$(get_config_value "$config_path" "BlockDamagePlayer")
            echo "$idx. 玩家方块伤害            [$val%]"
            menu_items[$idx]="玩家方块伤害"
            item_keys[$idx]="BlockDamagePlayer"
        fi
        if config_exists "$config_path" "BlockDamageAI"; then
            ((idx++))
            local val=$(get_config_value "$config_path" "BlockDamageAI")
            echo "$idx. AI方块伤害             [$val%]"
            menu_items[$idx]="AI方块伤害"
            item_keys[$idx]="BlockDamageAI"
        fi
        if config_exists "$config_path" "BlockDamageAIBM"; then
            ((idx++))
            local val=$(get_config_value "$config_path" "BlockDamageAIBM")
            echo "$idx. 血月AI方块伤害         [$val%]"
            menu_items[$idx]="血月AI方块伤害"
            item_keys[$idx]="BlockDamageAIBM"
        fi
        if config_exists "$config_path" "XPMultiplier"; then
            ((idx++))
            local val=$(get_config_value "$config_path" "XPMultiplier")
            echo "$idx. 经验倍率                [$val%]"
            menu_items[$idx]="经验倍率"
            item_keys[$idx]="XPMultiplier"
        fi
        if config_exists "$config_path" "DayNightLength"; then
            ((idx++))
            local val=$(get_config_value "$config_path" "DayNightLength")
            echo "$idx. 昼夜长度(分钟)          [$val]"
            menu_items[$idx]="昼夜长度"
            item_keys[$idx]="DayNightLength"
        fi
        if config_exists "$config_path" "DayLightLength"; then
            ((idx++))
            local val=$(get_config_value "$config_path" "DayLightLength")
            echo "$idx. 白天长度(小时)          [$val]"
            menu_items[$idx]="白天长度"
            item_keys[$idx]="DayLightLength"
        fi
        if config_exists "$config_path" "DeathPenalty"; then
            ((idx++))
            local val=$(get_config_value "$config_path" "DeathPenalty")
            local desc=""
            case "$val" in
                0) desc="无" ;;
                1) desc="经验惩罚" ;;
                2) desc="受伤" ;;
                3) desc="永久死亡" ;;
            esac
            echo "$idx. 死亡惩罚                [$val=$desc]"
            menu_items[$idx]="死亡惩罚"
            item_keys[$idx]="DeathPenalty"
        fi
        if config_exists "$config_path" "DropOnDeath"; then
            ((idx++))
            local val=$(get_config_value "$config_path" "DropOnDeath")
            local desc=""
            case "$val" in
                0) desc="无" ;;
                1) desc="所有" ;;
                2) desc="工具带" ;;
                3) desc="背包" ;;
                4) desc="删除所有" ;;
            esac
            echo "$idx. 死亡掉落                [$val=$desc]"
            menu_items[$idx]="死亡掉落"
            item_keys[$idx]="DropOnDeath"
        fi
        if config_exists "$config_path" "DropOnQuit"; then
            ((idx++))
            local val=$(get_config_value "$config_path" "DropOnQuit")
            local desc=""
            case "$val" in
                0) desc="无" ;;
                1) desc="所有" ;;
                2) desc="工具带" ;;
                3) desc="背包" ;;
            esac
            echo "$idx. 退出掉落                [$val=$desc]"
            menu_items[$idx]="退出掉落"
            item_keys[$idx]="DropOnQuit"
        fi
        
        # 僵尸设置
        echo ""
        echo "--- 僵尸设置 ---"
        if config_exists "$config_path" "MaxSpawnedZombies"; then
            ((idx++))
            local val=$(get_config_value "$config_path" "MaxSpawnedZombies")
            echo "$idx. 最大刷新僵尸数          [$val]"
            menu_items[$idx]="最大刷新僵尸数"
            item_keys[$idx]="MaxSpawnedZombies"
        fi
        if config_exists "$config_path" "MaxSpawnedAnimals"; then
            ((idx++))
            local val=$(get_config_value "$config_path" "MaxSpawnedAnimals")
            echo "$idx. 最大刷新动物数          [$val]"
            menu_items[$idx]="最大刷新动物数"
            item_keys[$idx]="MaxSpawnedAnimals"
        fi
        if config_exists "$config_path" "BloodMoonFrequency"; then
            ((idx++))
            local val=$(get_config_value "$config_path" "BloodMoonFrequency")
            [ "$val" = "0" ] && val="无血月"
            echo "$idx. 血月频率(天)            [$val]"
            menu_items[$idx]="血月频率"
            item_keys[$idx]="BloodMoonFrequency"
        fi
        if config_exists "$config_path" "BloodMoonEnemyCount"; then
            ((idx++))
            local val=$(get_config_value "$config_path" "BloodMoonEnemyCount")
            echo "$idx. 血月敌人数量            [$val]"
            menu_items[$idx]="血月敌人数量"
            item_keys[$idx]="BloodMoonEnemyCount"
        fi
        if config_exists "$config_path" "ZombieMove"; then
            ((idx++))
            local val=$(get_config_value "$config_path" "ZombieMove")
            local desc=""
            case "$val" in
                0) desc="行走" ;;
                1) desc="慢跑" ;;
                2) desc="跑步" ;;
                3) desc="冲刺" ;;
                4) desc="噩梦" ;;
            esac
            echo "$idx. 僵尸移动速度            [$val=$desc]"
            menu_items[$idx]="僵尸移动速度"
            item_keys[$idx]="ZombieMove"
        fi
        if config_exists "$config_path" "ZombieMoveNight"; then
            ((idx++))
            local val=$(get_config_value "$config_path" "ZombieMoveNight")
            local desc=""
            case "$val" in
                0) desc="行走" ;;
                1) desc="慢跑" ;;
                2) desc="跑步" ;;
                3) desc="冲刺" ;;
                4) desc="噩梦" ;;
            esac
            echo "$idx. 夜间僵尸速度            [$val=$desc]"
            menu_items[$idx]="夜间僵尸速度"
            item_keys[$idx]="ZombieMoveNight"
        fi
        
        # 性能设置
        echo ""
        echo "--- 性能设置 ---"
        if config_exists "$config_path" "MaxChunkAge"; then
            ((idx++))
            local val=$(get_config_value "$config_path" "MaxChunkAge")
            [ "$val" = "-1" ] && val="永不重置"
            echo "$idx. 区块最大年龄            [$val]"
            menu_items[$idx]="区块最大年龄"
            item_keys[$idx]="MaxChunkAge"
        fi
        if config_exists "$config_path" "ServerMaxAllowedViewDistance"; then
            ((idx++))
            local val=$(get_config_value "$config_path" "ServerMaxAllowedViewDistance")
            echo "$idx. 最大视距                [$val]"
            menu_items[$idx]="最大视距"
            item_keys[$idx]="ServerMaxAllowedViewDistance"
        fi
        if config_exists "$config_path" "MaxQueuedMeshLayers"; then
            ((idx++))
            local val=$(get_config_value "$config_path" "MaxQueuedMeshLayers")
            echo "$idx. 排队网格层数            [$val]"
            menu_items[$idx]="排队网格层数"
            item_keys[$idx]="MaxQueuedMeshLayers"
        fi
        if config_exists "$config_path" "DynamicMeshMaxItemCache"; then
            ((idx++))
            local val=$(get_config_value "$config_path" "DynamicMeshMaxItemCache")
            echo "$idx. 动态网格缓存            [$val]"
            menu_items[$idx]="动态网格缓存"
            item_keys[$idx]="DynamicMeshMaxItemCache"
        fi
        if config_exists "$config_path" "ServerMaxWorldTransferSpeedKiBs"; then
            ((idx++))
            local val=$(get_config_value "$config_path" "ServerMaxWorldTransferSpeedKiBs")
            echo "$idx. 世界传输速度(kiB/s)     [$val]"
            menu_items[$idx]="世界传输速度"
            item_keys[$idx]="ServerMaxWorldTransferSpeedKiBs"
        fi
        
        # 功能设置
        echo ""
        echo "--- 功能设置 ---"
        if config_exists "$config_path" "Region"; then
            ((idx++))
            local val=$(get_config_value "$config_path" "Region")
            echo "$idx. 服务器地区              [$val]"
            menu_items[$idx]="服务器地区"
            item_keys[$idx]="Region"
        fi
        if config_exists "$config_path" "Language"; then
            ((idx++))
            local val=$(get_config_value "$config_path" "Language")
            echo "$idx. 服务器语言              [$val]"
            menu_items[$idx]="服务器语言"
            item_keys[$idx]="Language"
        fi
        if config_exists "$config_path" "ServerReservedSlots"; then
            ((idx++))
            local val=$(get_config_value "$config_path" "ServerReservedSlots")
            echo "$idx. 预留槽位                [$val]"
            menu_items[$idx]="预留槽位"
            item_keys[$idx]="ServerReservedSlots"
        fi
        if config_exists "$config_path" "ServerAdminSlots"; then
            ((idx++))
            local val=$(get_config_value "$config_path" "ServerAdminSlots")
            echo "$idx. 管理员槽位              [$val]"
            menu_items[$idx]="管理员槽位"
            item_keys[$idx]="ServerAdminSlots"
        fi
        if config_exists "$config_path" "ServerAllowCrossplay"; then
            ((idx++))
            local val=$(get_config_value "$config_path" "ServerAllowCrossplay")
            echo "$idx. 跨平台游戏              [$val]"
            menu_items[$idx]="跨平台游戏"
            item_keys[$idx]="ServerAllowCrossplay"
        fi
        if config_exists "$config_path" "IgnoreEOSSanctions"; then
            ((idx++))
            local val=$(get_config_value "$config_path" "IgnoreEOSSanctions")
            echo "$idx. 忽略EOS制裁            [$val]"
            menu_items[$idx]="忽略EOS制裁"
            item_keys[$idx]="IgnoreEOSSanctions"
        fi
        
        # 其他设置
        echo ""
        echo "--- 其他设置 ---"
        if config_exists "$config_path" "LootAbundance"; then
            ((idx++))
            local val=$(get_config_value "$config_path" "LootAbundance")
            echo "$idx. 战利品丰富度            [$val%]"
            menu_items[$idx]="战利品丰富度"
            item_keys[$idx]="LootAbundance"
        fi
        if config_exists "$config_path" "LootRespawnDays"; then
            ((idx++))
            local val=$(get_config_value "$config_path" "LootRespawnDays")
            echo "$idx. 战利品重生天数          [$val]"
            menu_items[$idx]="战利品重生天数"
            item_keys[$idx]="LootRespawnDays"
        fi
        if config_exists "$config_path" "AirDropFrequency"; then
            ((idx++))
            local val=$(get_config_value "$config_path" "AirDropFrequency")
            [ "$val" = "0" ] && val="无空投"
            echo "$idx. 空投频率(小时)          [$val]"
            menu_items[$idx]="空投频率"
            item_keys[$idx]="AirDropFrequency"
        fi
        if config_exists "$config_path" "LandClaimCount"; then
            ((idx++))
            local val=$(get_config_value "$config_path" "LandClaimCount")
            echo "$idx. 领地声明数量            [$val]"
            menu_items[$idx]="领地声明数量"
            item_keys[$idx]="LandClaimCount"
        fi
        if config_exists "$config_path" "LandClaimSize"; then
            ((idx++))
            local val=$(get_config_value "$config_path" "LandClaimSize")
            echo "$idx. 领地大小                [$val]"
            menu_items[$idx]="领地大小"
            item_keys[$idx]="LandClaimSize"
        fi
        
        echo ""
        echo "0. 返回主菜单"
        echo "============================================="
        read -p "请输入操作编号: " choice
        
        if [ "$choice" = "0" ]; then
            return 0
        fi
        
        if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le $idx ]; then
            local key="${item_keys[$choice]}"
            local name="${menu_items[$choice]}"
            local current=$(get_config_value "$config_path" "$key")
            
            echo ""
            echo "=== 修改 $name ==="
            echo "当前值: $current"
            
            # 根据配置项类型提供不同提示
            case "$key" in
                "ServerVisibility")
                    echo "0 = 不列出(需手动输入IP), 1 = 仅好友可见, 2 = 公开"
                    ;;
                "GameDifficulty")
                    echo "0 = 冒险(最简单), 1 = 普通, 2 = 困难, 3 = 疯狂, 4 = 噩梦, 5 = 极限"
                    ;;
                "DeathPenalty")
                    echo "0 = 无, 1 = 经验惩罚, 2 = 受伤, 3 = 永久死亡"
                    ;;
                "DropOnDeath")
                    echo "0 = 无, 1 = 所有物品, 2 = 仅工具带, 3 = 仅背包, 4 = 删除所有"
                    ;;
                "DropOnQuit")
                    echo "0 = 无, 1 = 所有物品, 2 = 仅工具带, 3 = 仅背包"
                    ;;
                "ZombieMove"|"ZombieMoveNight"|"ZombieFeralMove"|"ZombieBMMove")
                    echo "0 = 行走, 1 = 慢跑, 2 = 跑步, 3 = 冲刺, 4 = 噩梦"
                    ;;
                "MaxChunkAge")
                    echo "-1 = 永不重置, 0 = 立即重置, 正数 = 游戏天数"
                    ;;
                "Region")
                    echo "可选: Asia, Europe, NorthAmericaEast, NorthAmericaWest, Russia, SouthAmerica, etc."
                    ;;
                "WorldGenSize")
                    echo "必须是2048的倍数: 6144, 8192, 10240"
                    ;;
                "GameWorld")
                    echo "RWG = 随机生成, 或选择已有世界名称"
                    available_worlds=($(get_available_worlds))
                    echo ""
                    echo "可用世界:"
                    local widx=0
                    for world in "${available_worlds[@]}"; do
                        ((widx++))
                        echo "  $widx) $world"
                    done
                    ;;
            esac
            
            read -p "请输入新值: " newval
            
            if [ -n "$newval" ]; then
                if update_config_value "$config_path" "$key" "$newval"; then
                    green_echo "✓ $name 已更新为: $newval"
                else
                    red_echo "✗ 更新失败: $key 不存在于配置文件中"
                fi
            else
                yellow_echo "未输入新值，取消修改"
            fi
        else
            red_echo "无效选项"
        fi
        
        echo ""
    done
}

# --- 自动备份当前存档（根据serverconfig.xml配置） ---
auto_backup_current_save() {
    local operation="$1"  # 操作类型：启动/关闭/切换版本/更新
    local config_path="$server_dir/serverconfig.xml"
    
    if [ ! -f "$config_path" ]; then
        yellow_echo "[自动备份] 未找到配置文件，跳过存档备份"
        return 0
    fi
    
    # 读取配置中的游戏世界和存档名称（宽松解析，兼容不同空格/属性顺序）
    local game_world
    local game_name
    game_world=$(get_config_value "$config_path" "GameWorld")
    game_name=$(get_config_value "$config_path" "GameName")
    [ -z "$game_name" ] && game_name="MyGame"
    
    local saves_dir="$home_dir/.local/share/7DaysToDie/Saves"
    local save_path="$saves_dir/$game_world/$game_name"

    # 回退：当配置缺失或目录不匹配时，从现有存档目录自动推断
    if [ -z "$game_world" ] || [ ! -d "$save_path" ]; then
        if [ -z "$game_world" ] || [ ! -d "$saves_dir/$game_world" ]; then
            game_world=$(find "$saves_dir" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' 2>/dev/null | head -1)
        fi
        if [ -n "$game_world" ] && [ -d "$saves_dir/$game_world" ]; then
            if [ -z "$game_name" ] || [ ! -d "$saves_dir/$game_world/$game_name" ]; then
                game_name=$(find "$saves_dir/$game_world" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' 2>/dev/null | head -1)
            fi
            save_path="$saves_dir/$game_world/$game_name"
        fi
    fi
    
    if [ ! -d "$save_path" ]; then
        yellow_echo "[自动备份] 存档目录不存在: ${game_world:-未知世界}/${game_name:-未知存档}"
        return 0
    fi
    
    # 创建自动备份目录
    local auto_backup_dir="$home_dir/7dtd_save_backups/auto_${operation}"
    mkdir -p "$auto_backup_dir"
    
    local backup_name="${game_world}_${game_name}_$(date +%Y%m%d_%H%M%S).tar.gz"
    local backup_path="$auto_backup_dir/$backup_name"
    
    echo "[自动备份] 正在备份存档: $game_world/$game_name ..."
    echo "[自动备份] 操作类型: $operation"
    
    if tar -czf "$backup_path" -C "$saves_dir/$game_world" "$game_name" 2>/dev/null; then
        local backup_size=$(ls -lh "$backup_path" | awk '{print $5}')
        green_echo "[自动备份] ✓ 备份成功: $backup_name (${backup_size})"
        
        # 只保留最近5个自动备份
        local backup_count=$(ls -1 "$auto_backup_dir"/*.tar.gz 2>/dev/null | wc -l)
        if [ "$backup_count" -gt 5 ]; then
            ls -1t "$auto_backup_dir"/*.tar.gz | tail -n +6 | xargs rm -f
            yellow_echo "[自动备份] 已清理旧备份，保留最近5个"
        fi
        
        return 0
    else
        red_echo "[自动备份] ✗ 备份失败"
        return 1
    fi
}

# --- 修复 Steam 客户端库 ---
fix_steamclient_so() {
    if is_arm64_host; then
        extract_steamclient_so_arm64 || true
        return 0
    fi

    local steamclient_src="$steamcmd_dir/linux64/steamclient.so"
    local steamclient_dst="$server_dir/steamclient.so"
    local sdk64_dir="$home_dir/.steam/sdk64"
    
    if [ ! -f "$steamclient_src" ]; then
        yellow_echo "[Steam修复] 未找到steamcmd中的steamclient.so"
        return 1
    fi
    
    if [ ! -f "$steamclient_dst" ]; then
        echo "[Steam修复] 复制steamclient.so到服务器目录..."
        cp "$steamclient_src" "$steamclient_dst"
    fi
    
    if [ ! -d "$sdk64_dir" ]; then
        echo "[Steam修复] 创建Steam SDK目录..."
        mkdir -p "$sdk64_dir"
    fi
    
    if [ ! -f "$sdk64_dir/steamclient.so" ]; then
        echo "[Steam修复] 创建steamclient.so符号链接..."
        ln -sf "$steamclient_src" "$sdk64_dir/steamclient.so"
    fi
    
    return 0
}

# --- 启动服务器 ---
start_server() {
    echo "====== 启动七日杀服务器 ======"

    if [ ! -f "$server_dir/serverconfig.xml" ]; then
        red_echo "未找到配置文件，请先配置服务器"
        return 1
    fi

    if [ ! -f "$server_dir/7DaysToDieServer.x86_64" ]; then
        red_echo "未找到服务器程序，请先安装服务器"
        return 1
    fi

    if is_arm32_host; then
        red_echo "ARM32 无法运行七日杀 64位 Linux 服务端。"
        return 1
    fi

    local launch_prefix=""
    if is_arm64_host; then
        launch_prefix=$(get_server_launch_prefix)
        if [ -z "$launch_prefix" ]; then
            red_echo "ARM64 启动需要 Box64，但未检测到。请先在主菜单 21 安装/修复 Box64。"
            return 1
        fi
        export_box64_runtime_env
        yellow_echo "ARM64兼容启动：$launch_prefix ./7DaysToDieServer.x86_64"
    fi

    if pgrep -f "7DaysToDieServer" > /dev/null; then
        yellow_echo "警告：服务器似乎已在运行"
        read -p "是否强制重启? (y/N): " restart
        if [[ $restart =~ ^[Yy]$ ]]; then
            stop_server
        else
            return 0
        fi
    fi

    clear_manual_stop_flag
    fix_steamclient_so
    auto_backup_current_save "启动前"
    
    echo "正在启动服务器..."
    cd "$server_dir" || return 1

    export LD_LIBRARY_PATH=".:$server_dir:$steamcmd_dir/linux64:$LD_LIBRARY_PATH"
    local logfile="output_log__$(date +%Y-%m-%d__%H-%M-%S).txt"
    local startup_flags
    startup_flags=$(get_server_startup_flags)
    local server_launch_cmd="./7DaysToDieServer.x86_64"
    if [ -n "$launch_prefix" ]; then
        server_launch_cmd="$launch_prefix ./7DaysToDieServer.x86_64"
    fi

    screen -dmS 7DaysToDie bash -c "cd '$server_dir' && export LD_LIBRARY_PATH='.':'$server_dir':'$steamcmd_dir/linux64':\$LD_LIBRARY_PATH && export BOX64_DYNAREC_BIGBLOCK='${BOX64_DYNAREC_BIGBLOCK:-0}' BOX64_DYNAREC_SAFEFLAGS='${BOX64_DYNAREC_SAFEFLAGS:-2}' BOX64_DYNAREC_STRONGMEM='${BOX64_DYNAREC_STRONGMEM:-3}' BOX64_DYNAREC_FASTROUND='${BOX64_DYNAREC_FASTROUND:-0}' BOX64_DYNAREC_FASTNAN='${BOX64_DYNAREC_FASTNAN:-0}' BOX64_DYNAREC_X87DOUBLE='${BOX64_DYNAREC_X87DOUBLE:-1}' && $server_launch_cmd -logfile '$logfile' $startup_flags -configfile=serverconfig.xml"

    sleep 5

    if pgrep -f "7DaysToDieServer" > /dev/null; then
        green_echo "✓ 服务器启动成功"
        echo ""
        echo "查看方式："
        echo "  脚本内查看日志: 主菜单 -> 6. 查看服务器状态和查看日志 -> 2. 查看实时日志"
        echo "  查看服务器状态: 主菜单 -> 6. 查看服务器状态和查看日志 -> 1. 查看服务器状态"
        echo "  当前日志文件: $server_dir/$logfile"
    else
        red_echo "✗ 服务器启动失败"
        yellow_echo "提示: 检查日志文件 $server_dir/$logfile 了解详情"
        return 1
    fi
}

# ============================================
# 闲时重启功能
# ============================================

# 获取当前在线玩家数量
get_online_player_count() {
    local count=0
    local latest_log=""
    latest_log=$(get_active_server_log_file 2>/dev/null)

    # 方法1: 从日志事件推算在线人数（连接+1，断开-1）
    if [ -n "$latest_log" ] && [ -f "$latest_log" ]; then
        count=$(tail -n 6000 "$latest_log" 2>/dev/null | awk '
            /PlayerLogin:|Player connected:|\[NET\] PlayerConnected/ { c++ }
            /Player disconnected:|\[NET\] PlayerDisconnected|Client disconnect/ { if (c>0) c-- }
            END { print c+0 }
        ')
    fi

    # 方法2: 网络连接兜底（防止日志不完整）
    if ! [[ "$count" =~ ^[0-9]+$ ]]; then
        count=0
    fi
    if [ "$count" -eq 0 ]; then
        local conn_count=0
        if command -v ss >/dev/null 2>&1; then
            conn_count=$(ss -tn 2>/dev/null | grep -E ":26900|:26901|:26902" | grep ESTAB | wc -l)
        else
            conn_count=$(netstat -tn 2>/dev/null | grep -E ":26900|:26901|:26902" | grep ESTABLISHED | wc -l)
        fi
        if [[ "$conn_count" =~ ^[0-9]+$ ]] && [ "$conn_count" -gt 0 ]; then
            # 粗略换算：通常每个玩家会有多个连接，最少按1计
            count=$((conn_count / 2))
            [ "$count" -lt 1 ] && count=1
        fi
    fi

    echo "${count:-0}"
}

# 获取服务器内存使用(MB)
get_server_memory_mb() {
    local mem_mb=0
    
    # 只匹配真实游戏进程，避免匹配到 screen/bash 包装进程
    local pid=$(get_runtime_server_pid)
    if [ -n "$pid" ]; then
        # 读取/proc/[pid]/status中的VmRSS
        if [ -f "/proc/$pid/status" ]; then
            mem_mb=$(grep "VmRSS:" "/proc/$pid/status" 2>/dev/null | awk '{print int($2/1024)}')
        fi
        
        # 如果上面的方法失败，使用ps
        if [ -z "$mem_mb" ] || [ "$mem_mb" -eq 0 ]; then
            mem_mb=$(ps -o rss= -p "$pid" 2>/dev/null | awk '{print int($1/1024)}')
        fi
    fi
    
    echo "${mem_mb:-0}"
}

# 检查最近是否有玩家登录(分钟)
check_last_player_login() {
    local minutes=${1:-30}
    local latest_log=""
    latest_log=$(get_active_server_log_file 2>/dev/null)
    if [ -z "$latest_log" ] || [ ! -f "$latest_log" ]; then
        latest_log=$(ls -t "$server_dir"/output_log*.txt 2>/dev/null | head -1)
    fi
    
    if [ -z "$latest_log" ] || [ ! -f "$latest_log" ]; then
        echo "9999"  # 返回一个大数字表示没有日志
        return
    fi
    
    # 查找最近一次玩家连接的时间
    local last_login_line=$(grep -E "Player.*connected|Player.*joined|\[Auth\].*PlayerName" "$latest_log" 2>/dev/null | tail -1)
    
    if [ -z "$last_login_line" ]; then
        echo "9999"  # 很久没有玩家登录
        return
    fi
    
    # 提取日志时间戳，优先完整日期格式
    local log_ts=""
    log_ts=$(echo "$last_login_line" | grep -oE '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}' | head -1)
    if [ -z "$log_ts" ]; then
        local log_time=$(echo "$last_login_line" | grep -oE '^[0-9]{2}:[0-9]{2}:[0-9]{2}' | head -1)
        if [ -n "$log_time" ]; then
            log_ts="$(date +%Y-%m-%d)T$log_time"
        fi
    fi

    if [ -z "$log_ts" ]; then
        echo "9999"
        return
    fi

    local now_epoch log_epoch
    now_epoch=$(date +%s 2>/dev/null || echo 0)
    log_epoch=$(date -d "${log_ts/T/ }" +%s 2>/dev/null || echo 0)
    if [ "$now_epoch" -le 0 ] || [ "$log_epoch" -le 0 ]; then
        echo "9999"
        return
    fi

    local diff=$(((now_epoch - log_epoch) / 60))
    [ "$diff" -lt 0 ] && diff=9999
    echo "$diff"
}

# 闲时重启检测脚本
create_idle_restart_script() {
    local script_path="$home_dir/7dtd_idle_restart.sh"
    
    cat > "$script_path" << 'EOF'
#!/bin/bash
# 七日杀闲时自动重启脚本
# 检测条件：内存超阈值 && 当前无玩家在线 && 空闲时间超过阈值

CONFIG_FILE="CONFIG_FILE_PLACEHOLDER"
LOG_FILE="LOG_FILE_PLACEHOLDER"
LOCK_FILE="LOCK_FILE_PLACEHOLDER"
PRESET_FILE="PRESET_FILE_PLACEHOLDER"
MARKER_FILE="MARKER_FILE_PLACEHOLDER"
MANUAL_STOP_FILE="MANUAL_STOP_FILE_PLACEHOLDER"

# 防并发：避免多次触发重启流程
if command -v flock >/dev/null 2>&1; then
    exec 9>"$LOCK_FILE"
    if ! flock -n 9; then
        exit 0
    fi
fi

# 读取配置
MEMORY_THRESHOLD=4096
IDLE_MINUTES=30
ENABLED=0
BROADCAST_BEFORE_RESTART=1

if [ -f "$CONFIG_FILE" ]; then
    source "$CONFIG_FILE"
fi

# 兼容旧配置的小写字段
[ -n "$memory_threshold" ] && MEMORY_THRESHOLD="$memory_threshold"
[ -n "$idle_minutes" ] && IDLE_MINUTES="$idle_minutes"
[ -n "$enabled" ] && ENABLED="$enabled"
[ -n "$broadcast_before_restart" ] && BROADCAST_BEFORE_RESTART="$broadcast_before_restart"

if [ "$ENABLED" != "1" ]; then
    exit 0
fi

# 记录日志
log_msg() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

set_restart_marker() {
    echo "$(date +%s) idle_restart" > "$MARKER_FILE"
}

clear_restart_marker() {
    rm -f "$MARKER_FILE" 2>/dev/null
}

set_manual_stop_flag() {
    local reason="${1:-idle_restart}"
    echo "$(date +%s) $reason" > "$MANUAL_STOP_FILE"
}

clear_manual_stop_flag() {
    rm -f "$MANUAL_STOP_FILE" 2>/dev/null
}

# 运行时读取启动参数预设，避免启用时写死参数
get_runtime_startup_flags() {
    local STARTUP_PRESET="standard"
    local CUSTOM_ARGS=""
    local EXTRA_ARGS=""
    local FORCE_DEDICATED="1"
    local FORCE_BATCHMODE="1"
    local FORCE_NOGRAPHICS="1"
    local FORCE_QUIT="1"
    local flags=""

    if [ -f "$PRESET_FILE" ]; then
        source "$PRESET_FILE" 2>/dev/null
    fi

    case "$STARTUP_PRESET" in
        standard)    flags="-quit -batchmode -nographics -dedicated" ;;
        performance) flags="-quit -batchmode -nographics -dedicated" ;;
        compatible)  flags="-quit -batchmode -dedicated" ;;
        minimal)     flags="-batchmode -dedicated" ;;
        debug)       flags="-batchmode -dedicated" ;;
        custom)      flags="${CUSTOM_ARGS:--quit -batchmode -nographics -dedicated}" ;;
        *)           flags="-quit -batchmode -nographics -dedicated" ;;
    esac

    if [ "$FORCE_DEDICATED" = "1" ]; then flags="$flags -dedicated"; else flags=$(echo " $flags " | sed 's/ -dedicated / /g'); fi
    if [ "$FORCE_BATCHMODE" = "1" ]; then flags="$flags -batchmode"; else flags=$(echo " $flags " | sed 's/ -batchmode / /g'); fi
    if [ "$FORCE_NOGRAPHICS" = "1" ]; then flags="$flags -nographics"; else flags=$(echo " $flags " | sed 's/ -nographics / /g'); fi
    if [ "$FORCE_QUIT" = "1" ]; then flags="$flags -quit"; else flags=$(echo " $flags " | sed 's/ -quit / /g'); fi
    [ -n "$EXTRA_ARGS" ] && flags="$flags $EXTRA_ARGS"
    echo "$flags" | xargs
}

# ARM64运行时启动命令准备
get_box64_cmd_runtime() {
    for b in box64 /usr/bin/box64 /usr/local/bin/box64 /snap/bin/box64-with-gl4es.box64 box64-with-gl4es.box64; do
        if command -v "$b" >/dev/null 2>&1; then command -v "$b"; return 0; fi
        if [ -x "$b" ]; then echo "$b"; return 0; fi
    done
    return 1
}
prepare_server_launch_cmd() {
    SERVER_LAUNCH_CMD="./7DaysToDieServer.x86_64"
    case "$(uname -m 2>/dev/null)" in
        aarch64|arm64)
            local b
            b=$(get_box64_cmd_runtime)
            if [ -z "$b" ]; then
                echo "[$(date '+%Y-%m-%d %H:%M:%S')] ARM64缺少Box64，无法自动重启七日杀" >> "${LOG_FILE:-${log_file:-/tmp/7dtd_arm64_compat.log}}"
                exit 1
            fi
            export BOX64_DYNAREC_BIGBLOCK="${BOX64_DYNAREC_BIGBLOCK:-0}"
            export BOX64_DYNAREC_SAFEFLAGS="${BOX64_DYNAREC_SAFEFLAGS:-2}"
            export BOX64_DYNAREC_STRONGMEM="${BOX64_DYNAREC_STRONGMEM:-3}"
            export BOX64_DYNAREC_FASTROUND="${BOX64_DYNAREC_FASTROUND:-0}"
            export BOX64_DYNAREC_FASTNAN="${BOX64_DYNAREC_FASTNAN:-0}"
            export BOX64_DYNAREC_X87DOUBLE="${BOX64_DYNAREC_X87DOUBLE:-1}"
            SERVER_LAUNCH_CMD="$b ./7DaysToDieServer.x86_64"
            ;;
    esac
}

# 检查服务器是否运行
if ! pgrep -f "7DaysToDieServer" > /dev/null; then
    exit 0
fi

# 获取真实服务器进程PID（排除screen/bash包装进程）
get_runtime_server_pid() {
    ps -eo pid,args --no-headers 2>/dev/null | awk '
        /7DaysToDieServer\.x86_64/ &&
        $0 !~ /SCREEN -dmS/ &&
        $0 !~ /screen -dmS/ &&
        $0 !~ /bash -c/ {
            print $1
            exit
        }
    '
}

# 获取内存使用
get_memory_mb() {
    local pid=$(get_runtime_server_pid)
    if [ -n "$pid" ] && [ -f "/proc/$pid/status" ]; then
        local rss_mb
        rss_mb=$(grep "VmRSS:" "/proc/$pid/status" 2>/dev/null | awk '{print int($2/1024)}')
        if [ -n "$rss_mb" ] && [ "$rss_mb" -ge 0 ] 2>/dev/null; then
            echo "$rss_mb"
            return
        fi
        ps -o rss= -p "$pid" 2>/dev/null | awk '{print int($1/1024)}'
    else
        echo "0"
    fi
}

# 获取在线玩家数
get_player_count() {
    local server_dir="SERVER_DIR_PLACEHOLDER"
    local latest_log=""
    local count=0
    local pid=$(get_runtime_server_pid)

    if [ -n "$pid" ] && [ -r "/proc/$pid/cmdline" ]; then
        latest_log=$(tr '\0' '\n' < "/proc/$pid/cmdline" | awk '
            prev=="-logfile" { print; exit }
            { prev=$0 }
        ')
        if [ -n "$latest_log" ] && [[ "$latest_log" != /* ]]; then
            latest_log="$server_dir/$latest_log"
        fi
    fi
    if [ -z "$latest_log" ] || [ ! -f "$latest_log" ]; then
        latest_log=$(ls -t "$server_dir"/output_log*.txt 2>/dev/null | head -1)
    fi

    if [ -n "$latest_log" ] && [ -f "$latest_log" ]; then
        count=$(tail -n 6000 "$latest_log" 2>/dev/null | awk '
            /PlayerLogin:|Player connected:|\[NET\] PlayerConnected/ { c++ }
            /Player disconnected:|\[NET\] PlayerDisconnected|Client disconnect/ { if (c>0) c-- }
            END { print c+0 }
        ')
    fi

    if ! [[ "$count" =~ ^[0-9]+$ ]]; then
        count=0
    fi

    if [ "$count" -eq 0 ]; then
        local conn_count=0
        if command -v ss >/dev/null 2>&1; then
            conn_count=$(ss -tn 2>/dev/null | grep -E ":26900|:26901|:26902" | grep ESTAB | wc -l)
        else
            conn_count=$(netstat -tn 2>/dev/null | grep -E ":26900|:26901|:26902" | grep ESTABLISHED | wc -l)
        fi
        if [[ "$conn_count" =~ ^[0-9]+$ ]] && [ "$conn_count" -gt 0 ]; then
            count=$((conn_count / 2))
            [ "$count" -lt 1 ] && count=1
        fi
    fi
    echo "${count:-0}"
}

# 检查最后登录时间(分钟)
check_last_login() {
    local server_dir="SERVER_DIR_PLACEHOLDER"
    local latest_log=""
    local pid=$(get_runtime_server_pid)
    if [ -n "$pid" ] && [ -r "/proc/$pid/cmdline" ]; then
        latest_log=$(tr '\0' '\n' < "/proc/$pid/cmdline" | awk '
            prev=="-logfile" { print; exit }
            { prev=$0 }
        ')
        if [ -n "$latest_log" ] && [[ "$latest_log" != /* ]]; then
            latest_log="$server_dir/$latest_log"
        fi
    fi
    if [ -z "$latest_log" ] || [ ! -f "$latest_log" ]; then
        latest_log=$(ls -t "$server_dir"/output_log*.txt 2>/dev/null | head -1)
    fi
    
    if [ -z "$latest_log" ] || [ ! -f "$latest_log" ]; then
        echo "9999"
        return
    fi
    
    local last_login=$(grep -E "Player.*connected|Player.*joined|\[Auth\].*PlayerName" "$latest_log" 2>/dev/null | tail -1)
    if [ -z "$last_login" ]; then
        echo "9999"
        return
    fi
    
    local log_ts=""
    log_ts=$(echo "$last_login" | grep -oE '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}' | head -1)
    if [ -z "$log_ts" ]; then
        local log_time=$(echo "$last_login" | grep -oE '^[0-9]{2}:[0-9]{2}:[0-9]{2}' | head -1)
        [ -n "$log_time" ] && log_ts="$(date +%Y-%m-%d)T$log_time"
    fi
    if [ -z "$log_ts" ]; then
        echo "9999"
        return
    fi

    local now_epoch log_epoch
    now_epoch=$(date +%s 2>/dev/null || echo 0)
    log_epoch=$(date -d "${log_ts/T/ }" +%s 2>/dev/null || echo 0)
    if [ "$now_epoch" -le 0 ] || [ "$log_epoch" -le 0 ]; then
        echo "9999"
        return
    fi

    local diff=$(((now_epoch - log_epoch) / 60))
    [ "$diff" -lt 0 ] && diff=9999
    echo "$diff"
}

# 执行检测
MEMORY_MB=$(get_memory_mb)
PLAYER_COUNT=$(get_player_count)
LAST_LOGIN_MIN=$(check_last_login)

# 数值兜底，避免异常值导致比较失败
[[ "$MEMORY_MB" =~ ^[0-9]+$ ]] || MEMORY_MB=0
[[ "$PLAYER_COUNT" =~ ^[0-9]+$ ]] || PLAYER_COUNT=0
[[ "$LAST_LOGIN_MIN" =~ ^[0-9]+$ ]] || LAST_LOGIN_MIN=9999

log_msg "检测 - 内存: ${MEMORY_MB}MB, 玩家: $PLAYER_COUNT, 最后登录: ${LAST_LOGIN_MIN}分钟前"

# 判断是否需要重启（严格要求：当前无玩家在线）
NEED_RESTART=0
RESTART_REASON=""

if [ "$MEMORY_MB" -ge "$MEMORY_THRESHOLD" ]; then
    if [ "$PLAYER_COUNT" -eq 0 ] && [ "$LAST_LOGIN_MIN" -ge "$IDLE_MINUTES" ]; then
        NEED_RESTART=1
        RESTART_REASON="内存使用${MEMORY_MB}MB超过阈值，当前无玩家在线，且空闲${LAST_LOGIN_MIN}分钟"
    fi
fi

if [ "$NEED_RESTART" -eq 1 ]; then
    log_msg "触发闲时重启: $RESTART_REASON"
    set_restart_marker
    set_manual_stop_flag "idle_restart"
    
    # 重启前广播（可配置）
    if [ "${BROADCAST_BEFORE_RESTART:-1}" = "1" ]; then
        screen -S 7DaysToDie -p 0 -X stuff "say \"[系统] 服务器将在60秒后自动重启，请尽快保存进度\"" 2>/dev/null
        sleep 30
        screen -S 7DaysToDie -p 0 -X stuff "say \"[系统] 服务器将在30秒后自动重启\"" 2>/dev/null
        sleep 20
        screen -S 7DaysToDie -p 0 -X stuff "say \"[系统] 服务器将在10秒后自动重启\"" 2>/dev/null
        sleep 10
    fi
    
    # 保存并关闭
    screen -S 7DaysToDie -p 0 -X stuff "saveworld" 2>/dev/null
    sleep 5
    screen -S 7DaysToDie -p 0 -X stuff $'\003' 2>/dev/null
    
    log_msg "已发送关闭命令，等待服务器关闭..."
    
    # 等待关闭
    for i in {1..30}; do
        if ! pgrep -f "7DaysToDieServer" > /dev/null; then
            break
        fi
        sleep 1
    done
    
    # 如果还在运行，强制关闭
    if pgrep -f "7DaysToDieServer" > /dev/null; then
        pkill -9 -f "7DaysToDieServer"
        sleep 2
    fi
    
    log_msg "服务器已关闭，准备重启..."
    
    # 启动服务器
    SERVER_DIR="SERVER_DIR_PLACEHOLDER"
    STEAMCMD_DIR="STEAMCMD_DIR_PLACEHOLDER"
    cd "$SERVER_DIR"
    export LD_LIBRARY_PATH=".:$SERVER_DIR:$STEAMCMD_DIR/linux64:$LD_LIBRARY_PATH"
    logfile="output_log__$(date +%Y-%m-%d__%H-%M-%S).txt"
    STARTUP_FLAGS=$(get_runtime_startup_flags)
    prepare_server_launch_cmd
    screen -dmS 7DaysToDie bash -c "cd '$SERVER_DIR' && export LD_LIBRARY_PATH='.':'$SERVER_DIR':'$STEAMCMD_DIR/linux64':\$LD_LIBRARY_PATH && $SERVER_LAUNCH_CMD -logfile '$logfile' $STARTUP_FLAGS -configfile=serverconfig.xml"
    
    # 等待启动，最长60秒，避免5秒误判
    started=0
    for i in {1..60}; do
        if pgrep -f "7DaysToDieServer.x86_64" > /dev/null; then
            started=1
            break
        fi
        sleep 1
    done
    if [ "$started" = "1" ]; then
        log_msg "服务器重启成功"
        clear_manual_stop_flag
    else
        log_msg "服务器重启失败"
    fi
    clear_restart_marker
fi
EOF

    # 替换占位符
    sed -i "s|CONFIG_FILE_PLACEHOLDER|$home_dir/.7dtd_idle_restart.conf|g" "$script_path"
    sed -i "s|LOG_FILE_PLACEHOLDER|$home_dir/7dtd_idle_restart.log|g" "$script_path"
    sed -i "s|LOCK_FILE_PLACEHOLDER|$home_dir/.7dtd_idle_restart.lock|g" "$script_path"
    sed -i "s|PRESET_FILE_PLACEHOLDER|$home_dir/.7dtd_startup_preset.conf|g" "$script_path"
    sed -i "s|MARKER_FILE_PLACEHOLDER|$home_dir/.7dtd_restart_maintenance|g" "$script_path"
    sed -i "s|MANUAL_STOP_FILE_PLACEHOLDER|$home_dir/.7dtd_manual_stop.flag|g" "$script_path"
    sed -i "s|SERVER_DIR_PLACEHOLDER|$server_dir|g" "$script_path"
    sed -i "s|STEAMCMD_DIR_PLACEHOLDER|$steamcmd_dir|g" "$script_path"
    
    chmod +x "$script_path"
    echo "$script_path"
}

# 配置闲时重启
setup_idle_restart() {
    local config_file="$home_dir/.7dtd_idle_restart.conf"
    local cron_file="/etc/cron.d/7dtd_idle_restart"
    local restart_script="$home_dir/7dtd_idle_restart.sh"
    
    echo "====== 闲时自动重启设置 ======"
    
    # 读取当前配置（统一使用大写字段，兼容旧小写字段）
    local ENABLED=0
    local MEMORY_THRESHOLD=4096
    local IDLE_MINUTES=30
    local BROADCAST_BEFORE_RESTART=1
    
    if [ -f "$config_file" ]; then
        source "$config_file"
        [ -n "$enabled" ] && ENABLED="$enabled"
        [ -n "$memory_threshold" ] && MEMORY_THRESHOLD="$memory_threshold"
        [ -n "$idle_minutes" ] && IDLE_MINUTES="$idle_minutes"
        [ -n "$broadcast_before_restart" ] && BROADCAST_BEFORE_RESTART="$broadcast_before_restart"
    fi
    
    echo "当前状态:"
    if [ "$ENABLED" = "1" ]; then
        green_echo "✓ 已启用"
        echo "  内存阈值: ${MEMORY_THRESHOLD}MB"
        echo "  空闲时间: ${IDLE_MINUTES}分钟"
        echo "  重启前广播: $([ "$BROADCAST_BEFORE_RESTART" = "1" ] && echo '开启' || echo '关闭')"
        echo "  配置文件: $config_file $([ -f "$config_file" ] && echo '(存在)' || echo '(缺失)')"
        echo "  检测脚本: $restart_script $([ -f "$restart_script" ] && echo '(存在)' || echo '(缺失)')"
        echo "  日志文件: $home_dir/7dtd_idle_restart.log $([ -f "$home_dir/7dtd_idle_restart.log" ] && echo '(存在)' || echo '(缺失)')"
        echo "  计划任务: $cron_file $([ -f "$cron_file" ] && echo '(存在)' || echo '(缺失)')"
    else
        yellow_echo "✗ 未启用"
    fi
    
    echo ""
    echo "请选择操作:"
    echo "1) 启用闲时自动重启"
    echo "2) 关闭闲时自动重启"
    echo "3) 查看重启日志"
    echo "4) 手动执行一次检测"
    echo "5) 重建检测脚本"
    echo "0) 返回"
    
    read -p "请选择: " choice
    
    case $choice in
        1)
            echo ""
            echo "配置闲时重启参数:"
            echo "内存阈值: 当服务器内存使用超过此值(MB)时触发检测"
            read -p "内存阈值 [默认4096]: " input_memory
            MEMORY_THRESHOLD=${input_memory:-4096}
            
            echo ""
            echo "空闲时间: 多少分钟内无玩家登录视为空闲"
            read -p "空闲时间(分钟) [默认30]: " input_idle
            IDLE_MINUTES=${input_idle:-30}

            echo ""
            echo "是否在闲时重启前发送游戏内广播倒计时?"
            echo "1) 开启 (推荐)"
            echo "0) 关闭"
            read -p "选择 [默认1]: " input_broadcast
            BROADCAST_BEFORE_RESTART=${input_broadcast:-1}
            
            if ! [[ "$MEMORY_THRESHOLD" =~ ^[0-9]+$ ]] || [ "$MEMORY_THRESHOLD" -le 0 ]; then
                red_echo "内存阈值无效，使用默认值 4096MB"
                MEMORY_THRESHOLD=4096
            fi
            if ! [[ "$IDLE_MINUTES" =~ ^[0-9]+$ ]] || [ "$IDLE_MINUTES" -le 0 ]; then
                red_echo "空闲时间无效，使用默认值 30分钟"
                IDLE_MINUTES=30
            fi

            # 先清理旧文件，确保每次启用都全新生成
            sudo rm -f "$cron_file"
            rm -f "$config_file" "$restart_script"
            
            # 保存配置
            cat > "$config_file" << EOF
# 七日杀闲时自动重启配置
ENABLED=1
MEMORY_THRESHOLD=$MEMORY_THRESHOLD
IDLE_MINUTES=$IDLE_MINUTES
BROADCAST_BEFORE_RESTART=$BROADCAST_BEFORE_RESTART
# 兼容旧版本字段
enabled=1
memory_threshold=$MEMORY_THRESHOLD
idle_minutes=$IDLE_MINUTES
broadcast_before_restart=$BROADCAST_BEFORE_RESTART
EOF
            chmod 600 "$config_file"
            chown $REAL_user:$REAL_user "$config_file" 2>/dev/null
            
            # 创建重启脚本
            local restart_script=$(create_idle_restart_script)
            local cron_user="${REAL_user:-root}"
            
            # 创建cron任务 (每10分钟检测一次)
            sudo tee "$cron_file" > /dev/null << EOF
# 七日杀闲时自动重启检测 (每10分钟)
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
*/10 * * * * $cron_user $restart_script
EOF
            
            green_echo "✓ 闲时自动重启已启用"
            echo "检测频率: 每10分钟"
            echo "执行用户: $cron_user"
            echo "内存阈值: ${MEMORY_THRESHOLD}MB"
            echo "空闲时间: ${IDLE_MINUTES}分钟"
            echo "重启前广播: $([ "$BROADCAST_BEFORE_RESTART" = "1" ] && echo '开启' || echo '关闭')"
            echo "日志文件: $home_dir/7dtd_idle_restart.log"
            ;;
        2)
            # 关闭时删除该功能生成文件
            sudo rm -f "$cron_file"
            rm -f "$config_file" "$restart_script"
            green_echo "✓ 闲时自动重启已关闭（已删除配置/脚本/计划任务）"
            ;;
        3)
            local log_file="$home_dir/7dtd_idle_restart.log"
            if [ -f "$log_file" ]; then
                echo "重启日志 (最近20行):"
                tail -20 "$log_file"
            else
                yellow_echo "暂无日志记录: $log_file"
            fi
            ;;
        4)
            if [ -f "$restart_script" ]; then
                bash "$restart_script"
                green_echo "✓ 已手动执行一次检测"
            else
                red_echo "无法执行：未找到检测脚本 $restart_script"
                yellow_echo "请先执行 5) 重建检测脚本，或先关闭再启用闲时自动重启"
            fi
            ;;
        5)
            if [ ! -f "$config_file" ]; then
                red_echo "未找到配置文件: $config_file"
                yellow_echo "请先执行 1) 启用闲时自动重启"
            else
                restart_script=$(create_idle_restart_script)
                green_echo "✓ 检测脚本已重建: $restart_script"
            fi
            ;;
        0)
            return 0
            ;;
    esac
}

# ============================================
# 配置宕机自动恢复
# ============================================
setup_crash_recovery() {
    local config_file="$home_dir/.7dtd_crash_recovery.conf"
    local cron_file="/etc/cron.d/7dtd_crash_recovery"
    local monitor_script="$home_dir/7dtd_crash_recovery.sh"
    local restart_count_file="$home_dir/.7dtd_restart_count"
    local restart_hour_file="$home_dir/.7dtd_restart_hour"
    
    echo "====== 宕机自动恢复设置 ======"
    echo ""
    echo "此功能将监控服务器状态，在服务器崩溃后自动重启"
    echo "检测间隔: 每5分钟"
    echo ""
    
    # 读取当前配置
    local enabled=0
    local restart_delay=30
    local max_restarts=3
    
    if [ -f "$config_file" ]; then
        source "$config_file"
    fi
    
    echo "当前状态:"
    if [ "$enabled" = "1" ]; then
        green_echo "✓ 已启用"
        echo "  启动延迟: ${restart_delay}秒"
        echo "  最大重启次数/小时: ${max_restarts}"
    else
        yellow_echo "✗ 未启用"
    fi
    
    echo ""
    echo "请选择操作:"
    echo "1) 启用宕机自动恢复"
    echo "2) 关闭宕机自动恢复"
    echo "3) 查看恢复日志"
    echo "0) 返回"
    
    read -p "请选择: " choice
    
    case $choice in
        1)
            echo ""
            echo "配置自动恢复参数:"
            
            read -p "检测到崩溃后等待多少秒再重启 [默认30]: " input_delay
            restart_delay=${input_delay:-30}
            
            echo ""
            read -p "每小时最多重启几次(防止无限重启) [默认3]: " input_max
            max_restarts=${input_max:-3}
            
            # 先清理旧文件，确保每次启用都全新生成
            sudo rm -f "$cron_file"
            rm -f "$config_file" "$monitor_script" "$restart_count_file" "$restart_hour_file"
            
            # 保存配置
            cat > "$config_file" << EOF
# 七日杀宕机自动恢复配置
enabled=1
restart_delay=$restart_delay
max_restarts=$max_restarts
EOF
            chmod 600 "$config_file"
            chown $REAL_user:$REAL_user "$config_file" 2>/dev/null
            
            # 创建监控脚本
            cat > "$monitor_script" << 'SCRIPT'
#!/bin/bash
# 七日杀宕机自动恢复脚本

CONFIG_FILE="CONFIG_FILE_PLACEHOLDER"
source "$CONFIG_FILE" 2>/dev/null
PRESET_FILE="PRESET_FILE_PLACEHOLDER"
MARKER_FILE="MARKER_FILE_PLACEHOLDER"
MANUAL_STOP_FILE="MANUAL_STOP_FILE_PLACEHOLDER"

home_dir="HOME_DIR_PLACEHOLDER"

log_file="$home_dir/7dtd_crash_recovery.log"
server_dir="$home_dir/7DaysToDie/server"
restart_count_file="$home_dir/.7dtd_restart_count"
last_hour_file="$home_dir/.7dtd_restart_hour"
MANUAL_STOP_GRACE_SECONDS=1800

# 运行时读取启动参数预设
get_runtime_startup_flags() {
    local STARTUP_PRESET="standard"
    local CUSTOM_ARGS=""
    local EXTRA_ARGS=""
    local FORCE_DEDICATED="1"
    local FORCE_BATCHMODE="1"
    local FORCE_NOGRAPHICS="1"
    local FORCE_QUIT="1"
    local flags=""

    if [ -f "$PRESET_FILE" ]; then
        source "$PRESET_FILE" 2>/dev/null
    fi

    case "$STARTUP_PRESET" in
        standard)    flags="-quit -batchmode -nographics -dedicated" ;;
        performance) flags="-quit -batchmode -nographics -dedicated" ;;
        compatible)  flags="-quit -batchmode -dedicated" ;;
        minimal)     flags="-batchmode -dedicated" ;;
        debug)       flags="-batchmode -dedicated" ;;
        custom)      flags="${CUSTOM_ARGS:--quit -batchmode -nographics -dedicated}" ;;
        *)           flags="-quit -batchmode -nographics -dedicated" ;;
    esac

    if [ "$FORCE_DEDICATED" = "1" ]; then flags="$flags -dedicated"; else flags=$(echo " $flags " | sed 's/ -dedicated / /g'); fi
    if [ "$FORCE_BATCHMODE" = "1" ]; then flags="$flags -batchmode"; else flags=$(echo " $flags " | sed 's/ -batchmode / /g'); fi
    if [ "$FORCE_NOGRAPHICS" = "1" ]; then flags="$flags -nographics"; else flags=$(echo " $flags " | sed 's/ -nographics / /g'); fi
    if [ "$FORCE_QUIT" = "1" ]; then flags="$flags -quit"; else flags=$(echo " $flags " | sed 's/ -quit / /g'); fi
    [ -n "$EXTRA_ARGS" ] && flags="$flags $EXTRA_ARGS"
    echo "$flags" | xargs
}

# ARM64运行时启动命令准备
get_box64_cmd_runtime() {
    for b in box64 /usr/bin/box64 /usr/local/bin/box64 /snap/bin/box64-with-gl4es.box64 box64-with-gl4es.box64; do
        if command -v "$b" >/dev/null 2>&1; then command -v "$b"; return 0; fi
        if [ -x "$b" ]; then echo "$b"; return 0; fi
    done
    return 1
}
prepare_server_launch_cmd() {
    SERVER_LAUNCH_CMD="./7DaysToDieServer.x86_64"
    case "$(uname -m 2>/dev/null)" in
        aarch64|arm64)
            local b
            b=$(get_box64_cmd_runtime)
            if [ -z "$b" ]; then
                echo "[$(date '+%Y-%m-%d %H:%M:%S')] ARM64缺少Box64，无法自动恢复七日杀" >> "${log_file:-/tmp/7dtd_arm64_compat.log}"
                exit 1
            fi
            export BOX64_DYNAREC_BIGBLOCK="${BOX64_DYNAREC_BIGBLOCK:-0}"
            export BOX64_DYNAREC_SAFEFLAGS="${BOX64_DYNAREC_SAFEFLAGS:-2}"
            export BOX64_DYNAREC_STRONGMEM="${BOX64_DYNAREC_STRONGMEM:-3}"
            export BOX64_DYNAREC_FASTROUND="${BOX64_DYNAREC_FASTROUND:-0}"
            export BOX64_DYNAREC_FASTNAN="${BOX64_DYNAREC_FASTNAN:-0}"
            export BOX64_DYNAREC_X87DOUBLE="${BOX64_DYNAREC_X87DOUBLE:-1}"
            SERVER_LAUNCH_CMD="$b ./7DaysToDieServer.x86_64"
            ;;
    esac
}

# 检查是否在运行
is_server_running() {
    pgrep -f "7DaysToDieServer" > /dev/null
}

# 检查是否处于计划重启维护窗口（10分钟内）
is_maintenance_window() {
    if [ ! -f "$MARKER_FILE" ]; then
        return 1
    fi
    local marker_ts now_ts
    marker_ts=$(awk '{print $1}' "$MARKER_FILE" 2>/dev/null)
    now_ts=$(date +%s 2>/dev/null || echo 0)
    if ! [[ "$marker_ts" =~ ^[0-9]+$ ]] || [ "$now_ts" -le 0 ]; then
        rm -f "$MARKER_FILE" 2>/dev/null
        return 1
    fi
    if [ $((now_ts - marker_ts)) -le 600 ]; then
        return 0
    fi
    rm -f "$MARKER_FILE" 2>/dev/null
    return 1
}

is_manual_stop_window() {
    if [ ! -f "$MANUAL_STOP_FILE" ]; then
        return 1
    fi
    local marker_ts now_ts
    marker_ts=$(awk '{print $1}' "$MANUAL_STOP_FILE" 2>/dev/null)
    now_ts=$(date +%s 2>/dev/null || echo 0)
    if ! [[ "$marker_ts" =~ ^[0-9]+$ ]] || [ "$now_ts" -le 0 ]; then
        rm -f "$MANUAL_STOP_FILE" 2>/dev/null
        return 1
    fi
    if [ $((now_ts - marker_ts)) -le "$MANUAL_STOP_GRACE_SECONDS" ]; then
        return 0
    fi
    rm -f "$MANUAL_STOP_FILE" 2>/dev/null
    return 1
}

# 获取当前小时
current_hour=$(date +%H)

# 检查是否需要重置计数
if [ -f "$last_hour_file" ]; then
    last_hour=$(cat "$last_hour_file")
    if [ "$last_hour" != "$current_hour" ]; then
        echo 0 > "$restart_count_file"
        echo "$current_hour" > "$last_hour_file"
        restart_count=0
    else
        restart_count=$(cat "$restart_count_file" 2>/dev/null || echo 0)
    fi
else
    echo "$current_hour" > "$last_hour_file"
    echo 0 > "$restart_count_file"
    restart_count=0
fi

if ! is_server_running; then
    if is_manual_stop_window; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] 检测到人工停服保护窗口，跳过本次宕机恢复" >> "$log_file"
        exit 0
    fi

    if is_maintenance_window; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] 检测到计划重启维护标记，跳过本次宕机恢复" >> "$log_file"
        exit 0
    fi

    # 检查是否超过最大重启次数
    if [ "$restart_count" -ge "$max_restarts" ]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] 服务器未运行，但已达到本小时最大重启次数($max_restarts)，跳过" >> "$log_file"
        exit 0
    fi
    
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] 检测到服务器崩溃，准备重启 (延迟${restart_delay}秒)..." >> "$log_file"
    sleep "$restart_delay"
    
    # 再次检查，防止手动启动
    if is_server_running; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] 服务器已被手动启动，取消自动恢复" >> "$log_file"
        exit 0
    fi
    
    # 启动服务器
    cd "$server_dir" || exit 1

    logfile="output_log__$(date +%Y-%m-%d__%H-%M-%S).txt"
    STARTUP_FLAGS=$(get_runtime_startup_flags)
    prepare_server_launch_cmd
    screen -dmS 7DaysToDie bash -c "cd '$server_dir' && export LD_LIBRARY_PATH='.':'$server_dir':'STEAMCMD_DIR_PLACEHOLDER/linux64':\$LD_LIBRARY_PATH && $SERVER_LAUNCH_CMD -logfile '$logfile' $STARTUP_FLAGS -configfile=serverconfig.xml"
    
    # 等待启动，最长60秒
    started=0
    for i in {1..60}; do
        if pgrep -f "7DaysToDieServer.x86_64" > /dev/null; then
            started=1
            break
        fi
        sleep 1
    done

    if [ "$started" = "1" ]; then
        restart_count=$((restart_count + 1))
        echo "$restart_count" > "$restart_count_file"
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] 服务器已自动重启 (本小时第${restart_count}次)" >> "$log_file"
    else
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] 自动恢复启动失败（60秒内未检测到进程）" >> "$log_file"
        exit 1
    fi
else
    # 服务器正常运行，无需操作
    :
fi
SCRIPT
            
            # 替换配置文件路径
            sed -i "s|CONFIG_FILE_PLACEHOLDER|$config_file|g" "$monitor_script"
            sed -i "s|PRESET_FILE_PLACEHOLDER|$home_dir/.7dtd_startup_preset.conf|g" "$monitor_script"
            sed -i "s|MARKER_FILE_PLACEHOLDER|$home_dir/.7dtd_restart_maintenance|g" "$monitor_script"
            sed -i "s|MANUAL_STOP_FILE_PLACEHOLDER|$home_dir/.7dtd_manual_stop.flag|g" "$monitor_script"
            sed -i "s|HOME_DIR_PLACEHOLDER|$home_dir|g" "$monitor_script"
            sed -i "s|STEAMCMD_DIR_PLACEHOLDER|$steamcmd_dir|g" "$monitor_script"
            chmod +x "$monitor_script"
            chown $REAL_user:$REAL_user "$monitor_script" 2>/dev/null
            
            # 创建cron任务 (每5分钟检测一次)
            sudo tee "$cron_file" > /dev/null << EOF
# 七日杀宕机自动恢复检测 (每5分钟)
*/5 * * * * root $monitor_script
EOF
            
            green_echo "✓ 宕机自动恢复已启用"
            echo "检测频率: 每5分钟"
            echo "启动延迟: ${restart_delay}秒"
            echo "最大重启次数: 每小时${max_restarts}次"
            echo "日志文件: $home_dir/7dtd_crash_recovery.log"
            ;;
        2)
            # 关闭时删除该功能生成文件
            sudo rm -f "$cron_file"
            rm -f "$config_file" "$monitor_script" "$restart_count_file" "$restart_hour_file"
            green_echo "✓ 宕机自动恢复已关闭（已删除配置/脚本/计划任务）"
            ;;
        3)
            local log_file="$home_dir/7dtd_crash_recovery.log"
            if [ -f "$log_file" ]; then
                echo "恢复日志 (最近20行):"
                tail -20 "$log_file"
            else
                yellow_echo "暂无日志记录"
            fi
            ;;
        0)
            return 0
            ;;
    esac
}

# --- 关闭服务器 ---
stop_server() {
    echo "====== 关闭七日杀服务器 ======"

    if ! pgrep -f "7DaysToDieServer" > /dev/null; then
        yellow_echo "服务器未在运行"
        return 0
    fi

    # 手动关闭服务器时写入停服标记，避免宕机恢复误判
    set_manual_stop_flag "manual_stop"

    echo "正在尝试关闭服务器..."

    # 尝试通过screen发送 Ctrl+C（多次尝试）
    local attempts=0
    local max_attempts=3
    local screen_session=""
    screen_session=$(get_server_screen_session 2>/dev/null)
    [ -z "$screen_session" ] && screen_session="7DaysToDie"
    
    while [ $attempts -lt $max_attempts ]; do
        screen -S "$screen_session" -p 0 -X stuff $'\003' 2>/dev/null
        
        for i in {1..10}; do
            sleep 1
            if ! pgrep -f "7DaysToDieServer" > /dev/null; then
                green_echo "✓ 服务器已正常关闭"
                auto_backup_current_save "关闭后"
                return 0
            fi
        done
        
        attempts=$((attempts+1))
        if [ $attempts -lt $max_attempts ]; then
            yellow_echo "  服务器未响应，第 $((attempts+1)) 次尝试..."
        fi
    done

    echo "尝试保存并退出..."
    screen -S 7DaysToDie -p 0 -X stuff "saveworld" 2>/dev/null
    sleep 3
    screen -S 7DaysToDie -p 0 -X stuff "quit" 2>/dev/null
    sleep 5

    if pgrep -f "7DaysToDieServer" > /dev/null; then
        yellow_echo "服务器未响应关闭命令，执行强制关闭..."
        pkill -TERM -f "7DaysToDieServer" 2>/dev/null
        sleep 3
        
        if pgrep -f "7DaysToDieServer" > /dev/null; then
            pkill -9 -f "7DaysToDieServer" 2>/dev/null
            sleep 2
        fi
    fi

    if ! pgrep -f "7DaysToDieServer" > /dev/null; then
        green_echo "✓ 服务器已关闭"
        auto_backup_current_save "关闭后"
    else
        red_echo "✗ 关闭失败，请手动检查"
    fi
}

# --- 运行敏感操作前确保服务器已关闭 ---
ensure_server_stopped_for_operation() {
    local operation_name="$1"

    # 维护类操作前写入停服标记，防止宕机自动恢复抢拉起
    set_manual_stop_flag "operation:$operation_name"

    if ! pgrep -f "7DaysToDieServer" > /dev/null; then
        return 0
    fi

    yellow_echo "检测到七日杀服务器正在运行。"
    if ! ask_yes_no "执行“$operation_name”前需要关闭服务器，是否继续并关闭？" "Y"; then
        yellow_echo "已取消：$operation_name"
        return 1
    fi

    stop_server

    if pgrep -f "7DaysToDieServer" > /dev/null; then
        red_echo "服务器仍在运行，已取消：$operation_name"
        return 1
    fi

    green_echo "服务器已关闭，继续执行：$operation_name"
    return 0
}

# --- 查看服务器状态 ---
show_server_status() {
    echo "====== 服务器状态 ======"

    if pgrep -f "7DaysToDieServer" > /dev/null; then
        green_echo "服务器状态: 运行中"
        echo ""
        echo "进程信息:"
        local server_pid
        server_pid=$(get_runtime_server_pid)
        if [ -n "$server_pid" ]; then
            ps -p "$server_pid" -o pid,ppid,user,%cpu,%mem,etime,cmd
        else
            ps aux | grep -E "7DaysToDieServer" | grep -v grep | head -5
        fi
        echo ""
        echo "端口监听:"
        netstat -tlnp 2>/dev/null | grep -E "26900|7Days" || ss -tlnp 2>/dev/null | grep -E "26900|7Days"
    else
        red_echo "服务器状态: 未运行"
    fi

    if [ -f "$server_dir/serverconfig.xml" ]; then
        echo ""
        echo "当前配置:"
        grep -E 'ServerName|ServerPort|GameWorld|GameDifficulty|ServerMaxPlayerCount' "$server_dir/serverconfig.xml" | head -10
    fi
}

# --- 获取当前运行服务器日志文件 ---
get_runtime_server_pid() {
    ps -eo pid,args --no-headers 2>/dev/null | awk '
        /7DaysToDieServer\.x86_64/ &&
        $0 !~ /SCREEN -dmS/ &&
        $0 !~ /screen -dmS/ &&
        $0 !~ /bash -c/ {
            print $1
            exit
        }
    '
}

get_active_server_log_file() {
    local pid
    pid=$(get_runtime_server_pid)

    if [ -n "$pid" ] && [ -r "/proc/$pid/cmdline" ]; then
        local logfile
        logfile=$(tr '\0' '\n' < "/proc/$pid/cmdline" | awk '
            prev=="-logfile" { print; exit }
            { prev=$0 }
        ')
        if [ -n "$logfile" ]; then
            if [[ "$logfile" != /* ]]; then
                logfile="$server_dir/$logfile"
            fi
            if [ -f "$logfile" ]; then
                echo "$logfile"
                return 0
            fi
        fi
    fi

    local latest_log
    latest_log=$(ls -t "$server_dir"/output_log*.txt 2>/dev/null | head -1)
    if [ -n "$latest_log" ] && [ -f "$latest_log" ]; then
        echo "$latest_log"
        return 0
    fi

    latest_log=$(ls -t "$server_dir"/*.log 2>/dev/null | head -1)
    if [ -n "$latest_log" ] && [ -f "$latest_log" ]; then
        echo "$latest_log"
        return 0
    fi

    return 1
}

# --- 获取七日杀screen会话名 ---
get_server_screen_session() {
    if ! command -v screen &> /dev/null; then
        return 1
    fi
    screen -list 2>/dev/null | awk '/[[:digit:]]+\.7DaysToDie[[:space:]]/{print $1; exit}'
}

# --- 直接进入游戏服务器控制台 ---
enter_game_server_console() {
    echo "====== 进入游戏服务器控制台 ======"
    local session_name
    session_name=$(get_server_screen_session)

    if [ -z "$session_name" ]; then
        yellow_echo "未找到 7DaysToDie 的 screen 会话，请先启动服务器"
        read -p "按回车键继续..."
        return 1
    fi

    yellow_echo "兼容模式控制台已启用（适配当前终端）"
    yellow_echo "输入命令后回车发送到游戏控制台，输入 /exit 返回主菜单"
    yellow_echo "可用辅助命令:"
    yellow_echo "  /help   显示帮助"
    yellow_echo "  /tail   查看当前日志最近80行"
    yellow_echo "  /follow 实时跟踪当前日志（Ctrl+C 返回输入）"
    yellow_echo "  /clear  清屏"
    echo ""

    while true; do
        local console_cmd=""
        read -e -p "7dtd> " console_cmd

        case "$console_cmd" in
            "/exit")
                break
                ;;
            "/help")
                echo "可用辅助命令:"
                echo "  /help   显示帮助"
                echo "  /exit   退出控制台"
                echo "  /tail   查看当前日志最近80行"
                echo "  /follow 实时跟踪当前日志（Ctrl+C 返回输入）"
                echo "  /clear  清屏"
                continue
                ;;
            "/clear")
                clear
                continue
                ;;
            "/tail")
                local log_file=""
                log_file=$(get_active_server_log_file)
                if [ -n "$log_file" ] && [ -f "$log_file" ]; then
                    echo "日志文件: $(basename "$log_file")"
                    tail -n 80 "$log_file"
                else
                    yellow_echo "未找到当前日志文件"
                fi
                continue
                ;;
            "/follow")
                local log_file=""
                log_file=$(get_active_server_log_file)
                if [ -n "$log_file" ] && [ -f "$log_file" ]; then
                    yellow_echo "实时跟踪: $(basename "$log_file")，按 Ctrl+C 返回输入"
                    tail -n 50 -f "$log_file"
                else
                    yellow_echo "未找到当前日志文件"
                fi
                continue
                ;;
            "")
                continue
                ;;
        esac

        screen -S "$session_name" -p 0 -X stuff "$console_cmd"
        screen -S "$session_name" -p 0 -X stuff $'\n'

        # 命令发送后快速回显最新日志，接近游戏内F1体验
        local log_file=""
        log_file=$(get_active_server_log_file)
        if [ -n "$log_file" ] && [ -f "$log_file" ]; then
            echo "----- $(basename "$log_file") 最近20行 -----"
            tail -n 20 "$log_file"
        fi
    done
}

# --- 查看服务器实时日志 ---
view_server_logs() {
    echo "====== 查看服务器日志 ======"

    local log_file=""
    log_file=$(get_active_server_log_file)

    if [ -z "$log_file" ] || [ ! -f "$log_file" ]; then
        red_echo "未找到日志文件"
        yellow_echo "日志目录: $server_dir"
        echo "目录内容:"
        ls -la "$server_dir" 2>/dev/null || echo "  (目录为空)"
        return 1
    fi

    green_echo "日志文件: $(basename "$log_file")"
    echo ""
    yellow_echo "提示: 按回车键可随时退出日志查看并返回菜单"
    echo "      按 Enter 键开始查看..."
    read

    echo "========================================"
    echo "  实时日志输出 (最新 50 行 + 新内容)"
    echo "========================================"
    echo ""

    tail -n 50 -f "$log_file" &
    local tail_pid=$!
    read -p "按回车键退出日志查看..." _
    kill "$tail_pid" 2>/dev/null
    wait "$tail_pid" 2>/dev/null

    echo ""
    echo "========================================"
    echo "  已退出日志查看"
    echo "========================================"
    read -p "按回车键返回上级菜单..."
}

# --- 查看服务器状态和日志 ---
show_server_status_and_logs_menu() {
    while true; do
        echo "============================================="
        echo "        查看服务器状态和查看日志"
        echo "============================================="
        echo "1. 查看服务器状态"
        echo "2. 查看实时日志"
        echo "3. 游戏控制台会话（Telnet）"
        echo "0. 返回主菜单"
        echo "============================================="
        read -p "请输入操作编号: " sub_choice

        case $sub_choice in
            1) show_server_status; read -p "按回车键继续..." ;;
            2) view_server_logs ;;
            3) open_telnet_console_session; read -p "按回车键继续..." ;;
            0) return 0 ;;
            *) red_echo "无效选项，请重新输入！" ;;
        esac
    done
}

# --- 进程控制台 ---
process_console_menu() {
    while true; do
        echo "============================================="
        echo "              进程控制台"
        echo "============================================="
        echo "1. 查看七日杀进程详情"
        echo "2. 进入后台控制台（Screen直连）"
        echo "3. 命令直连模式（F1风格）"
        echo "4. 查看服务器日志（120行/实时）"
        echo "0. 返回主菜单"
        echo "============================================="
        read -p "请输入操作编号: " process_choice

        case $process_choice in
            1)
                show_server_status
                read -p "按回车键继续..." ;;
            2)
                echo "====== 进入后台控制台 ======"
                local session_name
                session_name=$(get_server_screen_session)
                if [ -n "$session_name" ]; then
                    yellow_echo "提示: 进入后可直接输入后台命令"
                    yellow_echo "退出但不关闭服务器: 按 Ctrl+A 再按 D"
                    read -p "按回车进入控制台..." _
                    # 强制接管并附加，避免会话被占用无法进入
                    screen -D -r "$session_name"
                else
                    yellow_echo "未找到 7DaysToDie 的 screen 会话，请先启动服务器"
                fi
                read -p "按回车键继续..." ;;
            3)
                echo "====== 命令直连模式 ======"
                local session_name
                session_name=$(get_server_screen_session)
                if [ -z "$session_name" ]; then
                    yellow_echo "未找到 7DaysToDie 的 screen 会话，请先启动服务器"
                    read -p "按回车键继续..."
                    continue
                fi
                yellow_echo "已进入直连模式，输入命令后回车发送；输入 exit 返回菜单。"
                while true; do
                    read -p "7dtd> " console_cmd
                    if [ "$console_cmd" = "exit" ]; then
                        break
                    fi
                    if [ -z "$console_cmd" ]; then
                        continue
                    fi
                    screen -S "$session_name" -p 0 -X stuff "$console_cmd"
                    screen -S "$session_name" -p 0 -X stuff $'\n'
                done
                read -p "按回车键继续..." ;;
            4)
                echo "====== 服务器日志 ======"
                local active_log=""
                active_log=$(get_active_server_log_file)
                if [ -z "$active_log" ] || [ ! -f "$active_log" ]; then
                    yellow_echo "未找到当前日志文件"
                    read -p "按回车键继续..."
                    continue
                fi
                echo "当前日志文件: $(basename "$active_log")"
                echo "1) 查看最近120行"
                echo "2) 实时跟踪（tail -f）"
                read -p "请选择 [默认1]: " log_mode
                log_mode=${log_mode:-1}
                if [ "$log_mode" = "2" ]; then
                    yellow_echo "提示: 按 Ctrl+C 退出实时查看"
                    tail -n 50 -f "$active_log"
                else
                    tail -n 120 "$active_log"
                fi
                read -p "按回车键继续..." ;;
            0) return 0 ;;
            *) red_echo "无效选项，请重新输入！" ;;
        esac
    done
}

# --- 选择安装位置函数（用于TS3等安装） ---
select_install_location() {
    echo "====== 选择安装位置 ======"
    
    # 获取所有已挂载的磁盘（包括当前目录）
    echo "正在获取可用安装位置..."
    
    # 获取所有挂载点，排除系统目录和EFI引导分区
    mounted_locations=()
    
    # 从df命令获取所有挂载点
    while IFS= read -r line; do
        # 跳过标题行
        if [[ "$line" =~ "Filesystem" ]] || [[ -z "$line" ]]; then
            continue
        fi
        
        # 提取挂载点
        mount_point=$(echo "$line" | awk '{print $6}')
        filesystem=$(echo "$line" | awk '{print $1}')
        size=$(echo "$line" | awk '{print $2}')
        used=$(echo "$line" | awk '{print $3}')
        avail=$(echo "$line" | awk '{print $4}')
        use_percent=$(echo "$line" | awk '{print $5}')
        
        # 排除系统目录
        if [[ "$filesystem" =~ ^/dev/ ]] && \
           [[ "$mount_point" != "/" ]] && \
           [[ "$mount_point" != "/boot" ]] && \
           [[ "$mount_point" != "/boot/efi" ]] && \
           [[ ! "$mount_point" =~ ^/boot/efi ]] && \
           [[ ! "$mount_point" =~ /efi$ ]] && \
           [[ "$mount_point" != "/home" ]] && \
           [[ ! "$mount_point" =~ ^/home/[^/]+$ ]] && \
           [[ ! "$mount_point" =~ ^/snap/ ]] && \
           [[ ! "$mount_point" =~ ^/sys/ ]] && \
           [[ ! "$mount_point" =~ ^/proc/ ]] && \
           [[ ! "$mount_point" =~ ^/dev/ ]]; then
            
            # 从设备路径获取设备名
            device_name=$(basename "$filesystem")
            
            # 获取文件系统类型并排除EFI分区（vfat格式且小于等于1GB）
            fstype=$(lsblk -no FSTYPE "$filesystem" 2>/dev/null || echo "unknown")
            
            # 排除EFI分区：vfat格式且大小≤1GB
            if [[ "$fstype" == "vfat" ]]; then
                # 检查大小（支持 M 和 G 单位）
                if [[ "$size" =~ ^[0-9]+M$ ]]; then
                    size_mb=${size%M}
                    if (( size_mb <= 1024 )); then
                        echo "跳过EFI分区: $filesystem ($size)" >&2
                        continue
                    fi
                elif [[ "$size" =~ ^[0-9]+G$ ]]; then
                    size_gb=${size%G}
                    if (( size_gb <= 1 )); then
                        echo "跳过EFI分区: $filesystem ($size)" >&2
                        continue
                    fi
                fi
            fi
            
            # 标记当前目录
            current_marker=""
            if [[ "$mount_point" == "$home_dir" ]] || [[ "$mount_point" == "$seven_days_dir" ]]; then
                current_marker="[当前目录]"
            fi
            
            mounted_locations+=("$mount_point:$filesystem:$size:$fstype:$device_name:$current_marker")
        fi
    done < <(df -h 2>/dev/null)
    
    # 如果没找到已挂载的位置，至少添加当前目录
    if [ ${#mounted_locations[@]} -eq 0 ]; then
        echo "未找到其他挂载位置，使用当前目录..."
        current_size=$(df -h "$home_dir" | tail -1 | awk '{print $2}')
        current_fstype=$(lsblk -no FSTYPE "$(df -P "$home_dir" | tail -1 | cut -d' ' -f1)" 2>/dev/null || echo "unknown")
        current_device=$(basename "$(df -P "$home_dir" | tail -1 | cut -d' ' -f1)")
        mounted_locations+=("$home_dir:$(df -P "$home_dir" | tail -1 | cut -d' ' -f1):$current_size:$current_fstype:$current_device:[当前目录]")
    fi
    
    echo -e "
可用安装位置："
    echo "序号 | 挂载点 | 设备 | 大小 | 文件系统 | 备注"
    echo "--------------------------------------------------------------"
    
    for i in "${!mounted_locations[@]}"; do
        location_info=(${mounted_locations[$i]//:/ })
        mount_point=${location_info[0]}
        filesystem=${location_info[1]}
        size=${location_info[2]}
        fstype=${location_info[3]}
        device_name=${location_info[4]}
        current_marker=${location_info[5]}
        
        # 简化显示设备名
        short_device="$device_name"
        if [[ "$device_name" =~ ^[a-z]+[0-9]+$ ]]; then
            short_device="$device_name"
        else
            short_device=$(echo "$filesystem" | sed 's|^/dev/||')
        fi
        
        printf "%2d. %-20s %-10s %-8s %-10s %s\n" \
            "$((i+1))" "$mount_point" "$short_device" "$size" "$fstype" "$current_marker"
    done
    
    echo "0. 使用自定义路径"
    echo "c. 取消"
    
    read -p "请选择安装位置 (0-${#mounted_locations[@]}, 或输入c取消): " choice
    
    if [[ "$choice" == "c" ]] || [[ "$choice" == "C" ]]; then
        echo "操作已取消。"
        return 1
    fi
    
    if [[ "$choice" == "0" ]]; then
        read -p "请输入自定义路径: " custom_path
        if [ -z "$custom_path" ] || [ ! -d "$custom_path" ]; then
            red_echo "路径不存在或无效！"
            return 1
        fi
        install_dir="$custom_path"
    elif [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le ${#mounted_locations[@]} ]; then
        selected_index=$((choice-1))
        location_info=(${mounted_locations[$selected_index]//:/ })
        install_dir="${location_info[0]}"
    else
        red_echo "无效的选择！"
        return 1
    fi
    
    # 检查目标目录可写性
    if [ ! -w "$install_dir" ]; then
        red_echo "错误：没有写入权限到 $install_dir"
        return 1
    fi
    
    green_echo "已选择安装位置: $install_dir"
    return 0
}

# --- Teamspeak 3 服务器安装 ---
install_teamspeak3_server() {
    echo "====== 安装 Teamspeak 3 语音服务器 ======"

    # 选择安装位置（优化版，增加默认选项）
    echo -e "
选择Teamspeak 3服务器安装位置："
    echo "0) 使用当前默认位置 ($home_dir)"
    echo "1) 选择其他位置"
    echo "c) 取消安装"
    
    read -p "请输入选项 (0-1, c取消): " location_choice
    
    case $location_choice in
        0)
            install_dir="$home_dir"
            green_echo "使用默认位置: $install_dir"
            ;;
        1)
            if ! select_install_location; then
                red_echo "无法选择安装位置，使用默认位置: $home_dir"
                install_dir="$home_dir"
            else
                green_echo "安装位置已选择: $install_dir"
            fi
            ;;
        c|C)
            echo "安装已取消"
            return 0
            ;;
        *)
            red_echo "无效选择，使用默认位置: $home_dir"
            install_dir="$home_dir"
            ;;
    esac
    
    # 配置变量
    TS3_DOWNLOAD_URL="https://gitee.com/shaokun010/shaokuns-script-repository/releases/download/teamspeak%E6%9C%8D%E5%8A%A1%E5%99%A8%E5%AE%89%E8%A3%85%E8%84%9A%E6%9C%AC/teamspeak3-server_linux_amd64-3.13.7.zip"
    TS3_ZIP_FILE="teamspeak3-server_linux_amd64.zip"
    TS3_INSTALL_DIR="$install_dir/teamspeak3"
    TS3_USER="$REAL_user"
    
    
    yellow_echo "注意：Teamspeak 3 服务器需要以下端口："
    yellow_echo "- 9987 (UDP): 语音数据传输"
    yellow_echo "- 10011 (TCP): 文件传输"
    yellow_echo "- 30033 (TCP): ServerQuery"
    yellow_echo "请确保防火墙已开放这些端口！"
    
    red_echo "【重要提醒】该功能只用于云服务器，本地服务器需要映射！"
    yellow_echo "如果您使用的是本地服务器，需要通过FRP或其他方式映射上述端口到公网。"
    
    if ! ask_yes_no "确定要安装 Teamspeak 3 服务器吗？" "Y"; then
        echo "已取消安装 Teamspeak 3 服务器。"
        return 0
    fi

    # 检查并安装依赖
    green_echo "正在检查依赖工具..."
    if ! command -v wget &> /dev/null; then
        green_echo "安装 wget..."
        sudo apt-get install -y wget
    fi
    if ! command -v unzip &> /dev/null; then
        green_echo "安装 unzip..."
        sudo apt-get install -y unzip
    fi

    # 创建安装目录
    green_echo "创建安装目录..."
    mkdir -p "$TS3_INSTALL_DIR"

    # 下载Teamspeak 3服务器
    green_echo "正在下载 Teamspeak 3 服务器..."
    cd /tmp
    if wget -O "$TS3_ZIP_FILE" "$TS3_DOWNLOAD_URL"; then
        green_echo "下载成功。"
    else
        red_echo "下载失败，请检查网络连接。"
        return 1
    fi

    # 解压文件到临时目录
    green_echo "正在解压文件..."
    local temp_extract_dir=$(mktemp -d)
    if unzip -o "$TS3_ZIP_FILE" -d "$temp_extract_dir"; then
        green_echo "解压成功。"
    else
        red_echo "解压失败。"
        rm -rf "$temp_extract_dir"
        return 1
    fi

    # 查找解压后的所有文件并移动到安装目录
    green_echo "移动文件到安装目录..."
    
    # 查找实际的服务器文件
    local ts3server_path=$(find "$temp_extract_dir" -name "ts3server" -type f | head -1)
    if [ -z "$ts3server_path" ]; then
        red_echo "错误：未找到ts3server文件！"
        echo "解压目录内容："
        find "$temp_extract_dir" -type f -name "*" | head -20
        rm -rf "$temp_extract_dir"
        return 1
    fi
    
    green_echo "找到ts3server文件: $ts3server_path"
    
    # 获取ts3server文件所在的目录
    local ts3_server_dir=$(dirname "$ts3server_path")
    green_echo "Teamspeak服务器目录: $ts3_server_dir"
    
    # 显示服务器目录内容
    echo "服务器目录内容："
    ls -la "$ts3_server_dir"
    
    # 将服务器目录中的所有文件复制到安装目录
    green_echo "复制文件到安装目录..."
    cp -r "$ts3_server_dir"/* "$TS3_INSTALL_DIR/" || {
        red_echo "复制文件失败！"
        rm -rf "$temp_extract_dir"
        return 1
    }
    
    # 清理临时目录
    rm -rf "$temp_extract_dir"
    
    # 检查安装目录内容
    echo "安装目录内容："
    ls -la "$TS3_INSTALL_DIR"

    # 设置权限
    green_echo "设置文件权限..."
    chown -R "$TS3_USER:$TS3_USER" "$TS3_INSTALL_DIR"
    
    # 设置ts3server文件权限
    if [ -f "$TS3_INSTALL_DIR/ts3server" ]; then
        chmod +x "$TS3_INSTALL_DIR/ts3server"
        green_echo "ts3server权限设置成功"
    else
        red_echo "错误：安装目录中未找到ts3server文件！"
        return 1
    fi
    
    # 创建许可接受文件
    green_echo "创建Teamspeak 3许可接受文件..."
    touch "$TS3_INSTALL_DIR/.ts3server_license_accepted"
    chown "$TS3_USER:$TS3_USER" "$TS3_INSTALL_DIR/.ts3server_license_accepted"
    
    # 创建systemd服务文件 - 在安装目录中启动ts3server
    local ts3_exec="$TS3_INSTALL_DIR/ts3server"
    if is_arm64_host; then
        local box64_bin
        box64_bin=$(get_box64_bin)
        if [ -z "$box64_bin" ]; then
            red_echo "ARM64 运行 TeamSpeak x86_64 服务端需要 Box64，请先安装 Box64。"
            return 1
        fi
        ts3_exec="$box64_bin $TS3_INSTALL_DIR/ts3server"
    fi

    green_echo "创建系统服务..."
    sudo tee /etc/systemd/system/teamspeak3.service > /dev/null <<EOF
[Unit]
Description=TeamSpeak 3 Server
After=network.target

[Service]
Type=simple
User=$TS3_USER
Group=$TS3_USER
WorkingDirectory=$TS3_INSTALL_DIR
ExecStart=$ts3_exec
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    # 重载systemd并启用服务
    green_echo "配置系统服务..."
    sudo systemctl daemon-reload
    sudo systemctl enable teamspeak3.service

    # 启动服务
    green_echo "启动 Teamspeak 3 服务..."
    if sudo systemctl start teamspeak3.service; then
        green_echo "Teamspeak 3 服务启动成功！"
        
        # 等待服务启动并获取管理员密钥
        green_echo "正在获取管理员密钥..."
        
        # 等待一段时间让服务器生成令牌文件和日志
        sleep 5
        
        # 首先尝试从日志中提取令牌
        green_echo "从系统日志中提取管理员令牌..."
        
        # 使用更精确的方法提取令牌
        ADMIN_TOKEN=$(sudo journalctl -u teamspeak3.service --since "1 minute ago" --no-pager | grep -E "token=[A-Za-z0-9+/]+" | head -1 | sed 's/.*token=//')
        
        if [ -z "$ADMIN_TOKEN" ]; then
            # 如果第一次尝试失败，使用更宽松的匹配
            ADMIN_TOKEN=$(sudo journalctl -u teamspeak3.service --since "1 minute ago" --no-pager | grep -o "token=[^ ]*" | head -1 | cut -d'=' -f2)
        fi
        
        if [ -z "$ADMIN_TOKEN" ]; then
            # 如果还是失败，显示原始日志让用户手动查找
            yellow_echo "自动提取令牌失败，显示相关日志..."
            sudo journalctl -u teamspeak3.service --since "1 minute ago" --no-pager | grep -i -A5 -B5 "token"
            yellow_echo "请从上方日志中手动查找以 'token=' 开头的行，并记录令牌"
        else
            green_echo "管理员令牌: $ADMIN_TOKEN"
            # 保存密钥到文件
            echo "Teamspeak 3 管理员令牌: $ADMIN_TOKEN" | tee "$TS3_INSTALL_DIR/admin_token.txt" > /dev/null
            chown "$TS3_USER:$TS3_USER" "$TS3_INSTALL_DIR/admin_token.txt"
            
            # 同时保存服务器管理员账户信息
            SERVERADMIN_PASSWORD=$(sudo journalctl -u teamspeak3.service --since "1 minute ago" --no-pager | grep -o "password=.*" | head -1 | cut -d'"' -f2)
            if [ -n "$SERVERADMIN_PASSWORD" ]; then
                echo "服务器管理员账户: serveradmin" | tee -a "$TS3_INSTALL_DIR/admin_token.txt"
                echo "服务器管理员密码: $SERVERADMIN_PASSWORD" | tee -a "$TS3_INSTALL_DIR/admin_token.txt"
                green_echo "服务器管理员账户信息也已保存"
            fi
            
            green_echo "请妥善保存此令牌，这是管理Teamspeak服务器的凭证！"
        fi
    else
        red_echo "服务启动失败"
        sudo systemctl status teamspeak3.service --no-pager
    fi

    green_echo "安装完成！安装目录: $TS3_INSTALL_DIR"
}

# --- Teamspeak 3 服务器管理 ---
manage_teamspeak3_server() {
    TS3_INSTALL_DIR="$home_dir/teamspeak3"
    
    # 如果标准位置不存在，尝试查找其他位置
    if [ ! -f "$TS3_INSTALL_DIR/ts3server" ]; then
        # 尝试从systemd服务文件中查找安装位置
        if [ -f "/etc/systemd/system/teamspeak3.service" ]; then
            service_path=$(grep "ExecStart=" /etc/systemd/system/teamspeak3.service | cut -d'=' -f2 | xargs dirname 2>/dev/null)
            if [ -n "$service_path" ] && [ -f "$service_path/ts3server" ]; then
                TS3_INSTALL_DIR="$service_path"
                yellow_echo "从服务配置中找到安装位置: $TS3_INSTALL_DIR"
            fi
        fi
    fi

    if [ ! -f "$TS3_INSTALL_DIR/ts3server" ]; then
        red_echo "未检测到 Teamspeak 3 服务器安装，请先安装！"
        return 1
    fi
    
    while true; do
        echo "============================================="
        echo "          Teamspeak 3 服务器管理"
        echo "============================================="
        echo "1. 启动 Teamspeak 3 服务"
        echo "2. 停止 Teamspeak 3 服务"
        echo "3. 重启 Teamspeak 3 服务"
        echo "4. 查看 Teamspeak 3 状态"
        echo "5. 查看管理员密钥"
        echo "6. 查看服务日志"
        echo "0. 返回主菜单"
        echo "============================================="
        read -p "请输入操作编号: " choice

        case $choice in
            1)
                echo "启动 Teamspeak 3 服务..."
                if sudo systemctl start teamspeak3.service; then
                    green_echo "Teamspeak 3 服务启动成功！"
                else
                    red_echo "Teamspeak 3 服务启动失败！"
                    sudo systemctl status teamspeak3.service --no-pager
                fi
                ;;
            2)
                echo "停止 Teamspeak 3 服务..."
                if sudo systemctl stop teamspeak3.service; then
                    green_echo "Teamspeak 3 服务已停止。"
                else
                    red_echo "停止 Teamspeak 3 服务失败！"
                fi
                ;;
            3)
                echo "重启 Teamspeak 3 服务..."
                if sudo systemctl restart teamspeak3.service; then
                    green_echo "Teamspeak 3 服务重启成功！"
                else
                    red_echo "Teamspeak 3 服务重启失败！"
                    sudo systemctl status teamspeak3.service --no-pager
                fi
                ;;
            4)
                echo "Teamspeak 3 服务状态："
                sudo systemctl status teamspeak3.service --no-pager
                ;;
            5)
                echo "正在查找管理员密钥..."
                if [ -f "$TS3_INSTALL_DIR/admin_token.txt" ]; then
                    green_echo "管理员密钥："
                    cat "$TS3_INSTALL_DIR/admin_token.txt"
                else
                    yellow_echo "未找到保存的管理员密钥文件。"
                    yellow_echo "尝试从日志中提取..."
                    
                    # 从日志中提取令牌
                    ADMIN_TOKEN=$(sudo journalctl -u teamspeak3.service --no-pager | grep -E "token=[A-Za-z0-9+/]+" | head -1 | sed 's/.*token=//')
                    
                    if [ -z "$ADMIN_TOKEN" ]; then
                        # 如果第一次尝试失败，使用更宽松的匹配
                        ADMIN_TOKEN=$(sudo journalctl -u teamspeak3.service --no-pager | grep -o "token=[^ ]*" | head -1 | cut -d'=' -f2)
                    fi
                    
                    if [ -z "$ADMIN_TOKEN" ]; then
                        # 如果还是失败，显示原始日志让用户手动查找
                        yellow_echo "自动提取令牌失败，显示相关日志..."
                        sudo journalctl -u teamspeak3.service --no-pager | grep -i -A5 -B5 "token"
                        yellow_echo "请从上方日志中手动查找以 'token=' 开头的行，并记录令牌"
                    else
                        green_echo "管理员令牌: $ADMIN_TOKEN"
                        # 保存密钥到文件
                        echo "Teamspeak 3 管理员令牌: $ADMIN_TOKEN" | tee "$TS3_INSTALL_DIR/admin_token.txt" > /dev/null
                        # 兼容root和普通用户
                        if [ -n "$REAL_user" ] && [ "$REAL_user" != "root" ]; then
                            chown "$REAL_user:$REAL_user" "$TS3_INSTALL_DIR/admin_token.txt"
                        fi
                        
                        # 同时保存服务器管理员账户信息
                        SERVERADMIN_PASSWORD=$(sudo journalctl -u teamspeak3.service --no-pager | grep -o "password=.*" | head -1 | cut -d'"' -f2)
                        if [ -n "$SERVERADMIN_PASSWORD" ]; then
                            echo "服务器管理员账户: serveradmin" | tee -a "$TS3_INSTALL_DIR/admin_token.txt"
                            echo "服务器管理员密码: $SERVERADMIN_PASSWORD" | tee -a "$TS3_INSTALL_DIR/admin_token.txt"
                            green_echo "服务器管理员账户信息也已保存"
                        fi
                    fi
                fi
                ;;
            6)
                echo "查看 Teamspeak 3 服务日志..."
                sudo journalctl -u teamspeak3.service -n 50 --no-pager
                echo ""
                yellow_echo "实时查看日志: sudo journalctl -u teamspeak3.service -f"
                ;;
            0)
                return 0
                ;;
            *)
                echo "无效的选择，请重新输入！"
                ;;
        esac
        echo ""
        read -p "按回车键继续..."
    done
}

# --- 磁盘管理功能 ---
show_disk_usage() {
    echo "====== 当前磁盘使用情况 ======"
    echo "磁盘分区信息："
    lsblk -o NAME,SIZE,FSTYPE,MOUNTPOINT,LABEL,UUID
    
    echo -e "
磁盘空间使用情况："
    df -h
    
    echo -e "
用户目录所在磁盘："
    df -h "$home_dir"
    
    # 显示所有相关目录的磁盘使用情况
    echo -e "
相关目录磁盘使用："
    for dir in "$server_dir" "$steamcmd_dir" "$home_dir/teamspeak3" "$home_dir/.local" "$seven_days_dir"; do
        if [ -d "$dir" ]; then
            echo -n "$dir: "
            df -h "$dir" | tail -1 | awk '{print $4 "/" $2 " 使用" $5}'
        fi
    done
    
    # 显示当前路径配置
    echo -e "
当前路径配置："
    echo "home_dir: $home_dir"
    echo "seven_days_dir: $seven_days_dir"
    echo "server_dir: $server_dir"
    echo "steamcmd_dir: $steamcmd_dir"
}

get_available_disks() {
    local disks=()

    echo "正在扫描未挂载的磁盘..." >&2

    local root_disk
    root_disk=$(df -P / | tail -1 | cut -d' ' -f1)
    if [[ $root_disk =~ /dev/(sd[a-z]|nvme[0-9]+n[0-9]+|vd[a-z]) ]]; then
        root_disk=$(basename "$root_disk")
        root_disk=$(echo "$root_disk" | sed 's/[0-9]*$//')
    fi

    while IFS= read -r line; do
        if [[ "$line" =~ "NAME" ]] || [[ -z "$line" ]]; then
            continue
        fi

        disk_name=$(echo "$line" | awk '{print $1}')
        size=$(echo "$line" | awk '{print $2}')
        fstype=$(echo "$line" | awk '{print $3}')
        mount_point=$(echo "$line" | awk '{print $4}')

        if [[ "$disk_name" == "$root_disk" ]] || [[ "$disk_name" =~ ^${root_disk}[0-9]+$ ]]; then
            continue
        fi

        if [[ "$size" == "1M" ]] || [[ "$size" == "2M" ]] || [[ "$size" == "4M" ]]; then
            continue
        fi

        if [[ "$fstype" == "vfat" ]] && [[ "$size" =~ ^[0-9]+M$ ]] && (( ${size%M} <= 1024 )); then
            continue
        fi

        if [[ "$disk_name" =~ ^(loop|sr) ]] || [[ "$size" == "0B" ]]; then
            continue
        fi

        if [[ -z "$mount_point" ]]; then
            if [[ -z "$fstype" ]] || [[ "$fstype" == "" ]]; then
                disks+=("/dev/$disk_name:$size:$fstype:$mount_point")
            fi
        fi
    done < <(lsblk -ln -o NAME,SIZE,FSTYPE,MOUNTPOINT | grep -v '^├─' | grep -v '^└─')

    echo "${disks[@]}"
}

# 检测已挂载的额外磁盘
get_mounted_extra_disks() {
    local disks=()
    
    while IFS= read -r line; do
        # 跳过标题行
        if [[ "$line" =~ "Filesystem" ]] || [[ -z "$line" ]]; then
            continue
        fi
        
        # 提取挂载点
        mount_point=$(echo "$line" | awk '{print $6}')
        filesystem=$(echo "$line" | awk '{print $1}')
        size=$(echo "$line" | awk '{print $2}')
        used=$(echo "$line" | awk '{print $3}')
        avail=$(echo "$line" | awk '{print $4}')
        use_percent=$(echo "$line" | awk '{print $5}')
        
        # 排除系统挂载点和EFI引导分区
        if [[ "$mount_point" != "/" ]] && [[ "$mount_point" != "/boot" ]] && \
           [[ "$mount_point" != "/home" ]] && [[ ! "$mount_point" =~ ^/home/[^/]+$ ]] && \
           [[ "$mount_point" != "/boot/efi" ]] && [[ ! "$mount_point" =~ /efi$ ]]; then
            
            # 排除vfat文件系统的EFI分区（双重保险）
            fstype=$(lsblk -no FSTYPE "$filesystem" 2>/dev/null)
            if [[ "$fstype" == "vfat" ]] && [[ "$size" =~ ^[0-9]+M$ ]] && (( ${size%M} <= 1024 )); then
                continue
            fi
            
            # 从设备路径提取设备名
            device_name=$(basename "$filesystem")
            
            disks+=("$device_name:$size:$mount_point:$filesystem")
        fi
    done < <(df -h 2>/dev/null | grep "^/dev/")
    
    echo "${disks[@]}"
}

detect_and_init_disk() {
    echo "====== 检测并初始化额外磁盘 ======"
    show_disk_usage

    available_disks=($(get_available_disks))

    if [ ${#available_disks[@]} -eq 0 ]; then
        green_echo "未发现可用的未格式化磁盘。"
        return 0
    fi

    echo -e "
可用磁盘列表："
    echo "序号 | 设备路径 | 大小 | 文件系统 | 状态"
    echo "--------------------------------------------------------------"

    for i in "${!available_disks[@]}"; do
        disk_info=(${available_disks[$i]//:/ })
        device_path=${disk_info[0]}
        disk_size=${disk_info[1]}
        disk_fstype=${disk_info[2]}
        mount_point=${disk_info[3]}

        if [[ ! "$device_path" =~ ^/dev/ ]]; then
            device_path="/dev/$device_path"
        fi

        if [ -z "$disk_fstype" ] || [ "$disk_fstype" = "" ]; then
            fstype_display="未格式化"
            status="可用"
        else
            fstype_display="$disk_fstype"
            status="已有文件系统"
        fi

        printf "%2d. %-12s %-8s %-12s %-15s
"             "$((i+1))" "$device_path" "$disk_size" "$fstype_display" "$status"
    done

    echo "0. 跳过磁盘初始化"

    read -p "请输入选择 (0-${#available_disks[@]}): " disk_choice

    if [ "$disk_choice" -eq 0 ]; then
        yellow_echo "跳过磁盘初始化。"
        return 0
    fi

    if [ "$disk_choice" -lt 1 ] || [ "$disk_choice" -gt ${#available_disks[@]} ]; then
        red_echo "无效的选择！"
        return 1
    fi

    selected_index=$((disk_choice-1))
    selected_disk_info=(${available_disks[$selected_index]//:/ })
    device_path=${selected_disk_info[0]}
    disk_size=${selected_disk_info[1]}
    disk_fstype=${selected_disk_info[2]}

    if [[ ! "$device_path" =~ ^/dev/ ]]; then
        device_path="/dev/$device_path"
    fi

    echo "您选择了: $device_path ($disk_size)"

    if [ -n "$disk_fstype" ] && [ "$disk_fstype" != "" ]; then
        red_echo "警告：该磁盘已有文件系统格式: $disk_fstype"
    fi

    red_echo "警告：此操作将格式化磁盘 $device_path 并删除所有数据！"
    if ! ask_yes_no "确定要继续吗？" "N"; then
        echo "操作已取消。"
        return 0
    fi

    echo -e "
请选择文件系统类型："
    echo "1) ext4 (推荐，兼容性好)"
    echo "2) xfs (高性能，适合大文件)"
    echo "3) btrfs (支持快照和压缩)"
    read -p "请输入选择 (1-3，默认1): " fs_choice
    fs_choice=${fs_choice:-1}

    case $fs_choice in
        1) fs_type="ext4" ;;
        2) fs_type="xfs" ;;
        3) fs_type="btrfs" ;;
        *) fs_type="ext4" ;;
    esac

    default_mount_point="$home_dir/disk2"
    read -p "请输入挂载点路径 [默认: $default_mount_point]: " mount_point
    mount_point=${mount_point:-$default_mount_point}

    if [ -d "$mount_point" ]; then
        if [ "$(ls -A "$mount_point" 2>/dev/null)" ]; then
            yellow_echo "警告：挂载点 $mount_point 不为空！"
            if ! ask_yes_no "继续操作将清空目录，确定要继续吗？" "N"; then
                echo "操作已取消。"
                return 1
            fi
        fi
    fi

    echo "创建挂载点目录: $mount_point"
    mkdir -p "$mount_point"

    if mount | grep -q "$device_path"; then
        echo "卸载磁盘 $device_path..."
        sudo umount "$device_path" 2>/dev/null
    fi

    echo "正在格式化 $device_path 为 $fs_type 文件系统..."
    case $fs_type in
        ext4) sudo mkfs.ext4 -F "$device_path" ;;
        xfs) sudo mkfs.xfs -f "$device_path" ;;
        btrfs) sudo mkfs.btrfs -f "$device_path" ;;
    esac

    if [ $? -ne 0 ]; then
        red_echo "格式化失败！"
        return 1
    fi

    green_echo "格式化完成！"

    echo "挂载磁盘到 $mount_point..."
    sudo mount "$device_path" "$mount_point"

    if [ $? -ne 0 ]; then
        red_echo "挂载失败！"
        return 1
    fi

    green_echo "挂载成功！"

    # 兼容root和普通用户
    if [ -n "$REAL_user" ] && [ "$REAL_user" != "root" ]; then
        sudo chown -R $REAL_user:$REAL_user "$mount_point"
    fi
    sudo chmod 755 "$mount_point"

    echo "配置开机自动挂载..."
    disk_uuid=$(sudo blkid -s UUID -o value "$device_path")

    if [ -n "$disk_uuid" ]; then
        sudo cp /etc/fstab /etc/fstab.backup.$(date +%Y%m%d%H%M%S)
        sudo sed -i "\|$mount_point|d" /etc/fstab
        sudo sed -i "\|$device_path|d" /etc/fstab

        case $fs_type in
            ext4) echo "UUID=$disk_uuid $mount_point ext4 defaults,nofail 0 2" | sudo tee -a /etc/fstab ;;
            xfs) echo "UUID=$disk_uuid $mount_point xfs defaults,nofail 0 2" | sudo tee -a /etc/fstab ;;
            btrfs) echo "UUID=$disk_uuid $mount_point btrfs defaults,nofail 0 2" | sudo tee -a /etc/fstab ;;
        esac

        green_echo "开机自动挂载已配置。"
    fi

    echo -e "
挂载信息："
    df -h "$mount_point"

    echo -e "
磁盘初始化完成！"
}

# 选择迁移目标位置
select_migration_target() {
    echo "====== 选择迁移目标位置 ======"
    
    # 获取已挂载的额外磁盘
    mounted_disks=($(get_mounted_extra_disks))
    
    if [ ${#mounted_disks[@]} -eq 0 ]; then
        echo "未发现已挂载的额外磁盘。"
        echo "请先使用'检测并初始化额外磁盘'功能挂载磁盘。"
        return 1
    fi
    
    echo -e "
已挂载的额外磁盘列表："
    echo "序号 | 磁盘名称 | 大小 | 挂载点 | 设备"
    echo "--------------------------------------------------------------"
    
    for i in "${!mounted_disks[@]}"; do
        disk_info=(${mounted_disks[$i]//:/ })
        disk_name=${disk_info[0]}
        disk_size=${disk_info[1]}
        mount_point=${disk_info[2]}
        device=${disk_info[3]}
        
        printf "%2d. %-10s %-8s %-20s %s
" \
            "$((i+1))" "$disk_name" "$disk_size" "$mount_point" "$device"
    done
    
    echo "0. 使用自定义路径"
    echo "c. 取消"
    
    read -p "请选择目标磁盘 (0-${#mounted_disks[@]}, 或输入c取消): " choice
    
    if [[ "$choice" == "c" ]] || [[ "$choice" == "C" ]]; then
        echo "操作已取消。"
        return 1
    fi
    
    if [[ "$choice" == "0" ]]; then
        read -p "请输入自定义目标路径: " custom_path
        if [ -z "$custom_path" ] || [ ! -d "$custom_path" ]; then
            red_echo "路径不存在或无效！"
            return 1
        fi
        target_dir="$custom_path"
    elif [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le ${#mounted_disks[@]} ]; then
        selected_index=$((choice-1))
        disk_info=(${mounted_disks[$selected_index]//:/ })
        target_dir="${disk_info[2]}"
    else
        red_echo "无效的选择！"
        return 1
    fi
    
    echo "迁移目标位置: $target_dir"
    
    # 检查目标目录是否为空（除了隐藏文件）
    content_count=$(find "$target_dir" -maxdepth 1 -type f -o -type d -not -name '.*' 2>/dev/null | wc -l)
    if [ "$content_count" -gt 1 ]; then
        yellow_echo "警告：目标目录 '$target_dir' 不为空！"
        echo "目录内容："
        ls -la "$target_dir" | head -20
        
        if ! ask_yes_no "继续迁移可能会覆盖现有文件，确定要继续吗？" "N"; then
            echo "操作已取消。"
            return 1
        fi
    fi
    
    return 0
}

manage_disk_menu() {
    while true; do
        echo "============================================="
        echo "            磁盘管理功能菜单"
        echo "============================================="
        echo "1. 查看当前磁盘使用情况"
        echo "2. 检测并初始化额外磁盘"
        echo "3. 迁移现有数据到挂载磁盘"
        echo "4. 更新服务配置到新磁盘路径"
        echo "0. 返回主菜单"
        echo "============================================="
        read -p "请输入操作编号: " choice

        case $choice in
            1) show_disk_usage; read -p "按回车键继续..." ;;
            2) detect_and_init_disk; read -p "按回车键继续..." ;;
            3) migrate_data; read -p "按回车键继续..." ;;
            4) update_services_for_disk; read -p "按回车键继续..." ;;
            0) return 0 ;;
            *) echo "无效的选择！" ;;
        esac
    done
}

# --- 数据迁移功能（七日杀适配版） ---
migrate_data() {
    echo "====== 迁移数据 ======"
    
    # 选择迁移目标位置
    if ! select_migration_target; then
        return 1
    fi
    
    # 确认迁移
    echo -e "
即将迁移以下数据："
    echo "源目录: $home_dir"
    echo "目标目录: $target_dir"
    
    red_echo "警告：此操作将复制大量数据，可能需要较长时间！"
    red_echo "请确保有足够的磁盘空间！"
    
    if ! ask_yes_no "确定要开始迁移吗？" "N"; then
        echo "操作已取消。"
        return 0
    fi
    
    # 检查现有数据
    existing_data=()
    source_paths=()
    
    # 检查七日杀服务器
    if [ -d "$server_dir" ]; then
        existing_data+=("七日杀服务器: $server_dir")
        source_paths+=("$server_dir")
    fi
    
    # 检查SteamCMD
    if [ -d "$steamcmd_dir" ]; then
        existing_data+=("SteamCMD: $steamcmd_dir")
        source_paths+=("$steamcmd_dir")
    fi
    
    # 检查存档数据
    if [ -d "$home_dir/.local/share/7DaysToDie" ]; then
        existing_data+=("游戏存档: $home_dir/.local/share/7DaysToDie")
        source_paths+=("$home_dir/.local/share/7DaysToDie")
    fi
    
    # 检查Teamspeak
    if [ -d "$home_dir/teamspeak3" ]; then
        existing_data+=("Teamspeak 3服务器: $home_dir/teamspeak3")
        source_paths+=("$home_dir/teamspeak3")
    fi
    
    if [ ${#existing_data[@]} -eq 0 ]; then
        yellow_echo "未发现需要迁移的数据。"
        return 0
    fi
    
    echo -e "
发现以下可迁移的数据："
    for i in "${!existing_data[@]}"; do
        echo "$((i+1)). ${existing_data[$i]}"
    done
    
    echo "a. 迁移所有数据"
    echo "c. 取消"
    
    read -p "请选择要迁移的数据 (输入编号，a迁移全部，c取消): " migrate_choice
    
    if [[ "$migrate_choice" == "c" ]] || [[ "$migrate_choice" == "C" ]]; then
        echo "操作已取消。"
        return 0
    fi
    
    # 创建目标目录结构
    echo "创建目标目录结构..."
    mkdir -p "$target_dir/7DaysToDie/server"
    mkdir -p "$target_dir/steamcmd"
    mkdir -p "$target_dir/.local/share"
    mkdir -p "$target_dir/teamspeak3"
    
    # 迁移数据
    migrate_items=()
    
    if [[ "$migrate_choice" == "a" ]] || [[ "$migrate_choice" == "A" ]]; then
        # 迁移所有数据
        migrate_items+=("7dtd_server" "steamcmd" "saves" "teamspeak")
        echo "将迁移所有数据..."
    elif [[ "$migrate_choice" =~ ^[0-9]+$ ]] && [ "$migrate_choice" -ge 1 ] && [ "$migrate_choice" -le ${#existing_data[@]} ]; then
        # 根据选择添加迁移项
        selected_index=$((migrate_choice-1))
        case $selected_index in
            0) migrate_items+=("7dtd_server") ;;
            1) migrate_items+=("steamcmd") ;;
            2) migrate_items+=("saves") ;;
            3) migrate_items+=("teamspeak") ;;
        esac
        echo "将迁移: ${existing_data[$selected_index]}"
    else
        red_echo "无效的选择！"
        return 1
    fi
    
    # 开始迁移
    total_items=${#migrate_items[@]}
    current_item=0
    
    for item in "${migrate_items[@]}"; do
        current_item=$((current_item + 1))
        echo -e "
[$current_item/$total_items] "
        
        case $item in
            "7dtd_server")
                echo "迁移七日杀服务器..."
                if [ -d "$server_dir" ]; then
                    echo "从 $server_dir 迁移到 $target_dir/7DaysToDie/server"
                    cp -r "$server_dir"/* "$target_dir/7DaysToDie/server/" 2>/dev/null
                    if [ $? -eq 0 ]; then
                        green_echo "✓ 七日杀服务器迁移完成"
                    else
                        red_echo "✗ 七日杀服务器迁移失败"
                    fi
                else
                    yellow_echo "! 未找到七日杀服务器"
                fi
                ;;
            "steamcmd")
                echo "迁移SteamCMD..."
                if [ -d "$steamcmd_dir" ]; then
                    echo "从 $steamcmd_dir 迁移到 $target_dir/steamcmd"
                    cp -r "$steamcmd_dir"/* "$target_dir/steamcmd/" 2>/dev/null
                    if [ $? -eq 0 ]; then
                        green_echo "✓ SteamCMD迁移完成"
                    else
                        red_echo "✗ SteamCMD迁移失败"
                    fi
                else
                    yellow_echo "! 未找到SteamCMD"
                fi
                ;;
            "saves")
                echo "迁移游戏存档..."
                if [ -d "$home_dir/.local/share/7DaysToDie" ]; then
                    echo "从 $home_dir/.local/share/7DaysToDie 迁移到 $target_dir/.local/share/7DaysToDie"
                    mkdir -p "$target_dir/.local/share"
                    cp -r "$home_dir/.local/share/7DaysToDie" "$target_dir/.local/share/" 2>/dev/null
                    if [ $? -eq 0 ]; then
                        green_echo "✓ 游戏存档迁移完成"
                    else
                        red_echo "✗ 游戏存档迁移失败"
                    fi
                else
                    yellow_echo "! 未找到游戏存档"
                fi
                ;;
            "teamspeak")
                echo "迁移Teamspeak 3服务器..."
                if [ -d "$home_dir/teamspeak3" ]; then
                    echo "从 $home_dir/teamspeak3 迁移到 $target_dir/teamspeak3"
                    cp -r "$home_dir/teamspeak3" "$target_dir/" 2>/dev/null
                    if [ $? -eq 0 ]; then
                        green_echo "✓ Teamspeak 3服务器迁移完成"
                    else
                        red_echo "✗ Teamspeak 3服务器迁移失败"
                    fi
                else
                    yellow_echo "! 未找到Teamspeak 3服务器"
                fi
                ;;
        esac
    done
    
    green_echo "数据迁移完成！"
    echo -e "
请使用'更新服务配置到新磁盘路径'功能更新服务配置。"
}

# --- 更新服务配置（七日杀适配版） ---
update_services_for_disk() {
    echo "====== 更新服务配置到新磁盘路径 ======"
    
    # 选择目标位置
    if ! select_migration_target; then
        return 1
    fi
    
    echo -e "
将更新服务配置使用以下路径："
    echo "目标目录: $target_dir"
    
    red_echo "警告：此操作将修改系统服务配置！"
    red_echo "请确保数据已迁移到目标目录！"
    
    if ! ask_yes_no "确定要更新服务配置吗？" "N"; then
        echo "操作已取消。"
        return 0
    fi
    
    # 更新Teamspeak服务
    if [ -f "/etc/systemd/system/teamspeak3.service" ]; then
        echo "更新Teamspeak服务..."
        sudo sed -i "s|WorkingDirectory=.*|WorkingDirectory=$target_dir/teamspeak3|" /etc/systemd/system/teamspeak3.service
        sudo sed -i "s|ExecStart=.*|ExecStart=$target_dir/teamspeak3/ts3server|" /etc/systemd/system/teamspeak3.service
        green_echo "✓ Teamspeak服务已更新"
    else
        yellow_echo "! 未找到Teamspeak服务文件"
    fi
    
    # 重载服务配置
    echo "重载服务配置..."
    sudo systemctl daemon-reload
    
    # 重启相关服务
    services_to_restart=()
    
    if systemctl is-enabled --quiet teamspeak3.service 2>/dev/null; then
        services_to_restart+=("teamspeak3")
    fi
    
    if [ ${#services_to_restart[@]} -gt 0 ]; then
        echo "重启相关服务..."
        for service in "${services_to_restart[@]}"; do
            echo "重启 $service 服务..."
            sudo systemctl restart "$service"
            sleep 2
            if systemctl is-active --quiet "$service"; then
                green_echo "✓ $service 服务已重启"
            else
                red_echo "✗ $service 服务重启失败"
            fi
        done
    else
        yellow_echo "! 未找到需要重启的服务"
    fi
    
    green_echo "服务配置更新完成！"
    
    # 显示更新后的服务状态
    echo -e "
更新后的服务状态："
    for service in teamspeak3; do
        if systemctl is-enabled --quiet "$service" 2>/dev/null; then
            echo -e "
$service 服务状态："
            sudo systemctl status "$service" --no-pager | grep -A3 "Active:"
        fi
    done
    
    return 0
}

# ============================================
# FRP 功能模块（从 frp.sh 同步并适配七日杀）
# ============================================

# 获取FRP基础目录
get_frp_dir() {
    local current_user=$(whoami)
    if [ "$current_user" = "root" ]; then
        echo "/usr/local/frp"
    else
        echo "/home/$current_user/frp"
    fi
}

# 获取FRP配置目录（用于多节点）
get_frp_config_dir() {
    local frp_dir=$(get_frp_dir)
    echo "$frp_dir/nodes"
}

# 确保FRP目录结构存在
ensure_frp_structure() {
    local frp_dir=$(get_frp_dir)
    local config_dir=$(get_frp_config_dir)
    sudo mkdir -p "$config_dir"
    sudo chmod -R 775 "$frp_dir"
}

# 检查FRP客户端是否已安装
check_frp_installed() {
    local frp_dir=$(get_frp_dir)
    if [ -f "$frp_dir/frpc.toml" ] && [ -f "$frp_dir/frpc" ]; then
        return 0
    else
        return 1
    fi
}

# 安装FRP客户端（已安装则跳过）
install_frp_client() {
    echo "====== 安装FRP客户端 ======"
    
    # 检查是否已安装
    if check_frp_installed; then
        local frp_dir=$(get_frp_dir)
        green_echo "检测到FRP客户端已安装在: $frp_dir"
        yellow_echo "如需重新安装，请先卸载现有安装"
        return 0
    fi
    
    echo "注意：FRP客户端功能只用于本地服务器，云服务器不需要使用！"
    echo "此功能用于将本地服务器端口映射到公网，方便外部访问。"
    echo "如果您使用的是云服务器，已经有公网IP，则不需要安装FRP。"
    read -p "确定要安装FRP客户端吗？(y/N): " confirm
    if [[ ! $confirm =~ ^[Yy]$ ]]; then
        echo "取消安装FRP客户端。"
        return 0
    fi

    local frp_dir=$(get_frp_dir)
    local current_user=$(whoami)

    # 创建目录并设置权限
    echo "创建FRP目录: $frp_dir"
    sudo mkdir -p $frp_dir
    sudo chmod -R 775 $frp_dir
    cd $frp_dir

    # 下载FRP（按系统架构自动选择 amd64/arm64）
    echo "下载FRP客户端..."
    local frp_version="${FRP_VERSION:-0.61.1}"
    local frp_arch="linux_amd64"
    case "$(detect_host_arch)" in
        amd64) frp_arch="linux_amd64" ;;
        arm64) frp_arch="linux_arm64" ;;
        arm32) frp_arch="linux_arm" ;;
        *) red_echo "未知架构，无法自动选择FRP包"; return 1 ;;
    esac
    local frp_pkg="frp_${frp_version}_${frp_arch}"
    local frp_archive="${frp_pkg}.tar.gz"
    local frp_urls=(
        "https://github.com/fatedier/frp/releases/download/v${frp_version}/${frp_archive}"
    )
    if [ "$frp_arch" = "linux_amd64" ]; then
        frp_urls+=("https://gitee.com/shaokun010/shaokuns-script-repository/releases/download/frp%E5%AE%A2%E6%88%B7%E7%AB%AF%E5%92%8C%E6%9C%8D%E5%8A%A1%E5%99%A8%E5%AE%89%E8%A3%85%E8%84%9A%E6%9C%AC/frp_0.61.1_linux_amd64.tar.gz")
    fi

    local frp_download_ok=0
    local frp_url
    for frp_url in "${frp_urls[@]}"; do
        echo "尝试下载: $frp_url"
        sudo rm -f "$frp_archive"
        if sudo wget --limit-rate=5000000k --progress=bar:force -O "$frp_archive" "$frp_url"; then
            if tar -tzf "$frp_archive" >/dev/null 2>&1; then
                frp_download_ok=1
                break
            fi
        fi
    done
    if [ "$frp_download_ok" -ne 1 ]; then
        red_echo "FRP下载失败，请检查网络或手动下载 ${frp_archive}"
        return 1
    fi
    sudo tar -xzf "$frp_archive"
    sudo mv "$frp_pkg"/* "$frp_dir/"
    sudo rm -rf "$frp_pkg" "$frp_archive"

    # 客户端配置
    echo "配置FRP客户端..."
    sudo tee $frp_dir/frpc.toml << EOF
serverAddr = ""
serverPort = 7000
auth.token = ""

EOF

    read -p "请输入FRP服务器IP: " server_ip
    read -p "请输入FRP令牌: " frp_token

    sudo sed -i "s/^serverAddr = \"\"/serverAddr = \"$server_ip\"/" $frp_dir/frpc.toml
    sudo sed -i "s/^auth.token = \"\"/auth.token = \"$frp_token\"/" $frp_dir/frpc.toml

    # 生成systemd服务
    create_systemd_service() {
        local service_type=$1
        local systemd_dir="/etc/systemd/system/"
        if [ ! -d "$systemd_dir" ]; then
            systemd_dir="/usr/lib/systemd/system/"
        fi
        
        sudo bash -c "cat > ${systemd_dir}frp${service_type}.service << EOF
[Unit]
Description=Frp ${service_type^} Service
After=network.target
Wants=network-online.target
Requires=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=$frp_dir
ExecStart=$frp_dir/frp${service_type} -c $frp_dir/frp${service_type}.toml
Restart=always
RestartSec=5
StartLimitInterval=60
StartLimitBurst=3

[Install]
WantedBy=multi-user.target
EOF"
        
        sudo chmod 644 ${systemd_dir}frp${service_type}.service
    }

    create_systemd_service c

    # 重载服务并启动
    sudo systemctl daemon-reload
    sudo systemctl stop frpc >/dev/null 2>&1
    if sudo systemctl enable --now frpc; then
        green_echo "FRP服务已成功设置开机自启动"
    else
        red_echo "设置FRP服务开机自启动失败！"
        return 1
    fi
    
    # 检查服务状态
    if systemctl is-active --quiet frpc; then
        green_echo "FRP服务正在运行"
    else
        yellow_echo "FRP服务未运行，尝试手动启动..."
        if sudo systemctl start frpc && systemctl is-active --quiet frpc; then
            green_echo "FRP服务已手动启动成功"
        else
            red_echo "FRP服务启动失败，请检查配置"
            sudo systemctl status frpc --no-pager
            return 1
        fi
    fi
    
    echo "FRP客户端安装完成！"
}

# 创建节点systemd服务
create_node_systemd_service() {
    local service_name=$1
    local config_file=$2
    local frp_dir=$(get_frp_dir)
    local systemd_dir="/etc/systemd/system/"
    
    if [ ! -d "$systemd_dir" ]; then
        systemd_dir="/usr/lib/systemd/system/"
    fi
    
    sudo bash -c "cat > ${systemd_dir}${service_name}.service << EOF
[Unit]
Description=FRP Client Node - ${service_name}
After=network.target
Wants=network-online.target
Requires=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=$frp_dir
ExecStart=$frp_dir/frpc -c $config_file
Restart=always
RestartSec=5
StartLimitInterval=60
StartLimitBurst=3

[Install]
WantedBy=multi-user.target
EOF"
    
    sudo chmod 644 "${systemd_dir}${service_name}.service"
    green_echo "已创建服务: $service_name"
}

# ========== 规范化 FRP 配置 ==========
normalize_frp_config() {
    local content="$1"
    
    # 1. 提取第一个全局块（从开头到第一个 [[proxies]] 之前）
    local global_block=$(echo "$content" | awk '
        BEGIN { in_global = 1 }
        /^\[\[proxies\]\]/ { in_global = 0 }
        in_global { print }
    ')
    
    # 2. 提取所有原始 proxies 块
    local raw_proxies=$(echo "$content" | awk '
        BEGIN { in_block = 0; block = ""; first = 1 }
        /^\[\[proxies\]\]/ {
            if (in_block && block != "") {
                if (!first) print "---PROXY_BLOCK---"
                print block
                first = 0
            }
            in_block = 1
            block = $0
            next
        }
        in_block {
            block = block "\n" $0
        }
        END {
            if (in_block && block != "") {
                if (!first) print "---PROXY_BLOCK---"
                print block
            }
        }
    ')
    
    # 3. 净化每个 proxies 块
    local clean_proxies=""
    if [ -n "$raw_proxies" ]; then
        clean_proxies=$(echo "$raw_proxies" | awk '
            BEGIN { RS="---PROXY_BLOCK---"; ORS="" }
            {
                block = $0
                gsub(/^serverAddr =.*\n?/, "", block)
                gsub(/\nserverAddr =.*/, "", block)
                gsub(/^serverPort =.*\n?/, "", block)
                gsub(/\nserverPort =.*/, "", block)
                gsub(/^user =.*\n?/, "", block)
                gsub(/\nuser =.*/, "", block)
                gsub(/^token =.*\n?/, "", block)
                gsub(/\ntoken =.*/, "", block)
                gsub(/^auth\.token =.*\n?/, "", block)
                gsub(/\nauth\.token =.*/, "", block)
                gsub(/^\[metadatas\]\n?/, "", block)
                gsub(/\n\[metadatas\]/, "", block)
                gsub(/\n{2,}/, "\n", block)
                if (block !~ /^[[:space:]]*$/) {
                    print block "\n"
                }
            }
        ')
    fi
    
    # 4. 组合输出
    if [ -n "$clean_proxies" ]; then
        printf "%s\n\n%s\n" "$global_block" "$clean_proxies"
    else
        printf "%s\n" "$global_block"
    fi
}

# ========== 添加 LoLiA-FRP 节点 ==========
add_lolia_frp_node() {
    echo "====== 添加 LoLiA-FRP 节点 ======"
    echo "请粘贴从LoLiA-FRP获取的TOML配置（输入END结束）："

    local config_content=""
    local line
    while IFS= read -r line; do
        [[ "$line" == "END" ]] && break
        config_content+="$line"$'\n'
    done

    if [ -z "$config_content" ]; then
        red_echo "配置内容为空，取消添加"
        return 1
    fi

    # token 一致性检查
    local all_tokens=$(echo "$config_content" | grep -oP "token\s*=\s*['\"]\K[^'\"]+")
    local unique_tokens=$(echo "$all_tokens" | sort -u)
    local token_count=$(echo "$unique_tokens" | wc -l)
    if [ "$token_count" -gt 1 ]; then
        red_echo "错误：检测到多个不同的 token 值，无法自动合并。"
        echo "$unique_tokens"
        return 1
    fi
    local token=$(echo "$unique_tokens" | head -1)
    if [ -z "$token" ]; then
        red_echo "无法解析 token，请检查配置格式"
        return 1
    fi

    local normalized_config=$(normalize_frp_config "$config_content")
    local server_addr=$(echo "$normalized_config" | grep -oP "serverAddr\s*=\s*['\"]\K[^'\"]+" | head -1)
    local user=$(echo "$normalized_config" | grep -oP "user\s*=\s*['\"]\K[^'\"]+" | head -1)

    ensure_frp_structure
    local config_dir=$(get_frp_config_dir)
    local frp_dir=$(get_frp_dir)
    local config_file="$config_dir/frpc_lolia_${token}.toml"
    local is_merge=false

    # 检查是否已存在相同配置
    local existing_file=""
    for f in "$config_dir"/frpc_*.toml; do
        if [ -f "$f" ]; then
            local file_content=$(sudo cat "$f" 2>/dev/null)
            if [ -n "$file_content" ]; then
                local existing_addr=$(echo "$file_content" | grep -oP "serverAddr\s*=\s*['\"]\K[^'\"]+" | head -1)
                local existing_user=$(echo "$file_content" | grep -oP "user\s*=\s*['\"]\K[^'\"]+" | head -1)
                if [ "$existing_addr" = "$server_addr" ] && [ "$existing_user" = "$user" ]; then
                    existing_file="$f"
                    break
                fi
            fi
        fi
    done

    if [ -n "$existing_file" ]; then
        yellow_echo "发现已存在的相同节点配置: $(basename "$existing_file")"
        if ask_yes_no "是否合并到现有配置" "Y"; then
            # 合并逻辑简化版
            echo "$normalized_config" | sudo tee -a "$existing_file" > /dev/null
            green_echo "已合并到现有配置"
            is_merge=true
            config_file="$existing_file"
        else
            local i=1
            while [ -f "$config_dir/frpc_lolia_${token}_${i}.toml" ]; do
                ((i++))
            done
            config_file="$config_dir/frpc_lolia_${token}_${i}.toml"
            echo "$normalized_config" | sudo tee "$config_file" > /dev/null
            green_echo "已创建新配置: $(basename "$config_file")"
        fi
    else
        echo "$normalized_config" | sudo tee "$config_file" > /dev/null
        green_echo "已保存配置: $(basename "$config_file")"
    fi

    local service_name="frpc-lolia-${token:0:16}"
    create_node_systemd_service "$service_name" "$config_file"

    sudo systemctl daemon-reload
    if [ "$is_merge" = true ]; then
        sudo systemctl restart "$service_name"
    fi

    if sudo systemctl enable --now "$service_name"; then
        green_echo "LoLiA-FRP节点服务已启动"
    else
        yellow_echo "服务启动失败，请检查配置"
    fi
}

# ========== 添加 SakuraFrp 节点 ==========
add_sakura_frp_node() {
    echo "====== 添加 SakuraFrp 节点 ======"
    echo "请粘贴从SakuraFrp获取的TOML配置（输入END结束）："

    local config_content=""
    local line
    while IFS= read -r line; do
        [[ "$line" == "END" ]] && break
        config_content+="$line"$'\n'
    done

    if [ -z "$config_content" ]; then
        red_echo "配置内容为空，取消添加"
        return 1
    fi

    local all_tokens=$(echo "$config_content" | grep -oP "auth\.token\s*=\s*['\"]\K[^'\"]+")
    local unique_tokens=$(echo "$all_tokens" | sort -u)
    local token_count=$(echo "$unique_tokens" | wc -l)
    if [ "$token_count" -gt 1 ]; then
        red_echo "错误：检测到多个不同的 auth.token 值"
        echo "$unique_tokens"
        return 1
    fi
    local token=$(echo "$unique_tokens" | head -1)
    if [ -z "$token" ]; then
        red_echo "无法解析 auth.token，请检查配置格式"
        return 1
    fi

    local user=$(echo "$config_content" | grep -oP "user\s*=\s*['\"]\K[^'\"]+" | head -1)
    local server_addr=$(echo "$config_content" | grep -oP "serverAddr\s*=\s*['\"]\K[^'\"]+" | head -1)
    local normalized_config=$(normalize_frp_config "$config_content")

    ensure_frp_structure
    local config_dir=$(get_frp_config_dir)
    local config_file="$config_dir/frpc_sakura_${user}.toml"
    local is_merge=false

    # 检查是否已存在
    local existing_file=""
    for f in "$config_dir"/frpc_sakura_*.toml; do
        if [ -f "$f" ]; then
            local file_content=$(sudo cat "$f" 2>/dev/null)
            if [ -n "$file_content" ]; then
                local existing_addr=$(echo "$file_content" | grep -oP "serverAddr\s*=\s*['\"]\K[^'\"]+" | head -1)
                local existing_user=$(echo "$file_content" | grep -oP "user\s*=\s*['\"]\K[^'\"]+" | head -1)
                if [ "$existing_addr" = "$server_addr" ] && [ "$existing_user" = "$user" ]; then
                    existing_file="$f"
                    break
                fi
            fi
        fi
    done

    if [ -n "$existing_file" ]; then
        yellow_echo "发现已存在的相同节点配置: $(basename "$existing_file")"
        if ask_yes_no "是否合并到现有配置" "Y"; then
            echo "$normalized_config" | sudo tee -a "$existing_file" > /dev/null
            green_echo "已合并到现有配置"
            is_merge=true
            config_file="$existing_file"
        else
            local i=1
            while [ -f "$config_dir/frpc_sakura_${user}_${i}.toml" ]; do
                ((i++))
            done
            config_file="$config_dir/frpc_sakura_${user}_${i}.toml"
            echo "$normalized_config" | sudo tee "$config_file" > /dev/null
            green_echo "已创建新配置: $(basename "$config_file")"
        fi
    else
        echo "$normalized_config" | sudo tee "$config_file" > /dev/null
        green_echo "已保存配置: $(basename "$config_file")"
    fi

    local service_name="frpc-sakura-${user}"
    create_node_systemd_service "$service_name" "$config_file"

    sudo systemctl daemon-reload
    if [ "$is_merge" = true ]; then
        sudo systemctl restart "$service_name"
    fi

    if sudo systemctl enable --now "$service_name"; then
        green_echo "SakuraFrp节点服务已启动"
    else
        yellow_echo "服务启动失败，请检查配置"
    fi
}

# ========== 添加私人FRP节点 ==========
add_private_node() {
    echo "====== 添加私人FRP节点 ======"
    echo "请选择添加方式："
    echo "1) 交互式生成配置"
    echo "2) 粘贴完整TOML配置"
    echo "0) 取消"
    
    read -p "请输入选项 (0-2): " add_method
    
    case $add_method in
        1) add_private_node_interactive ;;
        2) add_private_node_paste ;;
        0) return 0 ;;
        *) red_echo "无效选项"; return 1 ;;
    esac
}

# 交互式生成私人节点配置
add_private_node_interactive() {
    echo "====== 添加私人FRP节点 - 交互式生成 ======"
    
    ensure_frp_structure
    local config_dir=$(get_frp_config_dir)
    local frp_dir=$(get_frp_dir)
    
    if [ ! -f "$frp_dir/frpc" ]; then
        yellow_echo "未检测到FRP客户端，先执行安装..."
        install_frp_client
        frp_dir=$(get_frp_dir)
        config_dir=$(get_frp_config_dir)
    fi
    
    local node_name=""
    while true; do
        read -p "请输入节点名称（仅限英文、数字、下划线、连字符）: " node_name
        
        if [ -z "$node_name" ]; then
            red_echo "节点名称不能为空"
            continue
        fi
        
        if echo "$node_name" | grep -qP '[\x{4e00}-\x{9fa5}]'; then
            red_echo "节点名称不能包含中文"
            continue
        fi
        
        if [[ ! "$node_name" =~ ^[a-zA-Z0-9_-]+$ ]]; then
            red_echo "节点名称包含非法字符"
            continue
        fi
        
        if [ ${#node_name} -lt 2 ] || [ ${#node_name} -gt 30 ]; then
            red_echo "节点名称长度需在2-30字符之间"
            continue
        fi
        
        break
    done
    
    local safe_name="$node_name"
    local config_file="$config_dir/frpc_private_${safe_name}.toml"
    
    if [ -f "$config_file" ]; then
        yellow_echo "配置已存在: $(basename "$config_file")"
        if ! ask_yes_no "是否覆盖" "N"; then
            return 1
        fi
    fi
    
    read -p "请输入FRP服务器地址: " server_addr
    read -p "请输入FRP服务器端口 [7000]: " server_port
    server_port=${server_port:-7000}
    read -p "请输入认证Token: " auth_token
    
    sudo tee "$config_file" << EOF
serverAddr = "$server_addr"
serverPort = $server_port
auth.token = "$auth_token"

EOF
    
    green_echo "基础配置已生成: $(basename "$config_file")"
    
    # 询问是否添加端口映射
    while ask_yes_no "是否添加端口映射" "Y"; do
        echo -e "\n--- 添加端口映射 ---"
        read -p "映射名称: " proxy_name
        read -p "类型 [tcp/udp]: " proxy_type
        proxy_type=${proxy_type:-tcp}
        read -p "本地IP [127.0.0.1]: " local_ip
        local_ip=${local_ip:-127.0.0.1}
        read -p "本地端口: " local_port
        read -p "远程端口: " remote_port
        
        sudo tee -a "$config_file" << EOF

[[proxies]]
name = "$proxy_name"
type = "$proxy_type"
localIP = "$local_ip"
localPort = $local_port
remotePort = $remote_port
EOF
        green_echo "已添加映射: $proxy_name ($local_port -> $remote_port)"
    done
    
    local service_name="frpc-private-${safe_name}"
    create_node_systemd_service "$service_name" "$config_file"
    
    sudo systemctl daemon-reload
    if sudo systemctl enable --now "$service_name"; then
        green_echo "私人节点 '$node_name' 服务已启动"
    else
        yellow_echo "服务启动失败，请检查配置"
    fi
}

# 粘贴配置添加私人节点
add_private_node_paste() {
    echo "====== 添加私人FRP节点 - 粘贴配置 ======"
    echo "请粘贴完整的FRP TOML配置（输入END结束）："
    
    local config_content=""
    local line
    
    while IFS= read -r line; do
        [[ "$line" == "END" ]] && break
        config_content+="$line"$'\n'
    done
    
    if [ -z "$config_content" ]; then
        red_echo "配置内容为空，取消添加"
        return 1
    fi
    
    local server_addr=$(echo "$config_content" | grep -oP "serverAddr\s*=\s*['\"]\K[^'\"]+" | head -1)
    if [ -z "$server_addr" ]; then
        red_echo "无法解析serverAddr，请检查配置格式"
        return 1
    fi
    
    local safe_name=$(echo "$server_addr" | sed 's/[^a-zA-Z0-9_-]/_/g')
    local timestamp=$(date +%s%N | cut -c1-8)
    local config_file_name="frpc_private_${safe_name}_${timestamp}"
    
    ensure_frp_structure
    local config_dir=$(get_frp_config_dir)
    local config_file="$config_dir/${config_file_name}.toml"
    
    echo "$config_content" | sudo tee "$config_file" > /dev/null
    green_echo "已保存配置: $(basename "$config_file")"
    
    local service_name="${config_file_name:0:30}"
    create_node_systemd_service "$service_name" "$config_file"
    
    sudo systemctl daemon-reload
    if sudo systemctl enable --now "$service_name"; then
        green_echo "私人节点服务已启动: $service_name"
    else
        yellow_echo "服务启动失败，请检查配置"
    fi
}

# ========== FRP自动映射端口管理（七日杀适配版） ==========
auto_map_ports_7dtd() {
    echo "====== FRP自动映射端口（七日杀适配版） ======"
    echo "注意：此功能只用于本地服务器，云服务器不需要使用！"
    echo "此功能将自动读取serverconfig.xml中的端口配置并映射到公网。"

    local current_user
    current_user=$(whoami)

    local frp_base_path
    frp_base_path=$(get_frp_dir)
    if [ -z "$frp_base_path" ] || [ ! -d "$frp_base_path" ]; then
        if [ "$current_user" = "root" ] && [ -d "/usr/local/frp" ]; then
            frp_base_path="/usr/local/frp"
        elif [ -d "/home/$current_user/frp" ]; then
            frp_base_path="/home/$current_user/frp"
        else
            frp_base_path="$home_dir/frp"
        fi
    fi

    local config_dir="$frp_base_path/nodes"

    if [ ! -f "$server_dir/serverconfig.xml" ]; then
        red_echo "未找到serverconfig.xml文件！"
        yellow_echo "请先配置七日杀服务器。"
        return 1
    fi

    ensure_newline_at_eof() {
        local file="$1"
        if [ -f "$file" ] && [ "$(tail -c 1 "$file" | wc -l)" -eq 0 ]; then
            sudo bash -c "echo >> '$file'"
        fi
    }

    infer_node_type() {
        local cfg="$1"
        local base
        base=$(basename "$cfg")
        if [ "$cfg" = "$frp_base_path/frpc.toml" ]; then
            echo "主配置"
        elif [[ "$base" == frpc_private_* ]]; then
            echo "私人节点"
        elif [[ "$base" == frpc_lolia_* ]]; then
            echo "LoLiA节点"
        elif [[ "$base" == frpc_sakura_* ]]; then
            echo "Sakura节点"
        else
            echo "其他节点"
        fi
    }

    get_server_ip_from_config() {
        local cfg="$1"
        local ip
        ip=$(grep -oP '^\s*serverAddr\s*=\s*"\K[^"]+' "$cfg" | head -1)
        [ -z "$ip" ] && ip="未配置"
        echo "$ip"
    }

    get_service_for_config() {
        local cfg="$1"
        if [ "$cfg" = "$frp_base_path/frpc.toml" ]; then
            echo "frpc"
            return 0
        fi

        local svc
        for svc in $(systemctl list-unit-files --type=service --no-pager 2>/dev/null | awk '/^frpc/{print $1}'); do
            if systemctl cat "$svc" 2>/dev/null | grep -Fq " -c $cfg"; then
                echo "${svc%.service}"
                return 0
            fi
        done

        echo ""
    }

    list_proxy_entries() {
        local cfg="$1"
        awk '
            BEGIN { in_block=0; name=""; type=""; lport=""; rport="" }
            function flush_block() {
                if (in_block && name != "") {
                    printf "%s|%s|%s|%s\n", name, type, lport, rport
                }
            }
            /^\[\[proxies\]\]/ {
                flush_block()
                in_block=1
                name=""; type=""; lport=""; rport=""
                next
            }
            in_block {
                if ($0 ~ /^name[ \t]*=/) {
                    match($0, /"([^"]+)"/, arr)
                    name=arr[1]
                } else if ($0 ~ /^type[ \t]*=/) {
                    match($0, /"([^"]+)"/, arr)
                    type=arr[1]
                } else if ($0 ~ /^localPort[ \t]*=/) {
                    val=$0
                    sub(/^[^=]*=[ \t]*/, "", val)
                    gsub(/[ \t\r]/, "", val)
                    lport=val
                } else if ($0 ~ /^remotePort[ \t]*=/) {
                    val=$0
                    sub(/^[^=]*=[ \t]*/, "", val)
                    gsub(/[ \t\r]/, "", val)
                    rport=val
                }
            }
            END {
                flush_block()
            }
        ' "$cfg"
    }

    delete_proxy_block_local() {
        local file="$1"
        local target_name="$2"
        local temp_file
        temp_file=$(mktemp)

        awk -v name="$target_name" '
            BEGIN { in_block=0; delete_block=0; block="" }
            /^\[\[proxies\]\]/ {
                if (in_block && !delete_block) printf "%s", block
                in_block=1
                delete_block=0
                block=$0 "\n"
                next
            }
            in_block {
                block = block $0 "\n"
                if ($0 ~ /^name[ \t]*=/) {
                    match($0, /"([^"]+)"/, arr)
                    if (arr[1] == name) delete_block=1
                }
                next
            }
            { print }
            END {
                if (in_block && !delete_block) printf "%s", block
            }
        ' "$file" > "$temp_file"

        sudo mv "$temp_file" "$file"
    }

    port_conflict_name() {
        local cfg="$1"
        local proxy_type="$2"
        local local_port="$3"
        local remote_port="$4"

        while IFS='|' read -r name ptype lport rport; do
            [ -z "$name" ] && continue
            if [ "$ptype" = "$proxy_type" ] && { [ "$lport" = "$local_port" ] || [ "$rport" = "$remote_port" ]; }; then
                echo "$name"
                return 0
            fi
        done < <(list_proxy_entries "$cfg")

        return 1
    }

    add_proxy_if_needed() {
        local cfg="$1"
        local proxy_name="$2"
        local proxy_type="$3"
        local local_port="$4"
        local remote_port="$5"

        local conflict
        conflict=$(port_conflict_name "$cfg" "$proxy_type" "$local_port" "$remote_port")
        if [ $? -eq 0 ]; then
            yellow_echo "跳过端口 $local_port/$remote_port：已存在映射 '$conflict'"
            return 2
        fi

        delete_proxy_block_local "$cfg" "$proxy_name"
        ensure_newline_at_eof "$cfg"

        local proxy_config
        proxy_config="[[proxies]]
name = \"$proxy_name\"
type = \"$proxy_type\"
localIP = \"127.0.0.1\"
localPort = $local_port
remotePort = $remote_port
"
        echo "$proxy_config" | sudo tee -a "$cfg" > /dev/null
        return 0
    }

    safe_restart_frp_with_check() {
        local target_config="$1"
        local backup_file="$2"
        local target_service="$3"

        if [ -z "$target_service" ]; then
            yellow_echo "未找到与配置匹配的systemd服务，已保存配置: $target_config"
            yellow_echo "请手动重启对应frpc服务使配置生效。"
            return 0
        fi

        echo "尝试重启服务: $target_service"
        if sudo systemctl restart "$target_service"; then
            green_echo "服务重启成功: $target_service"
            return 0
        fi

        red_echo "服务重启失败: $target_service"
        sudo systemctl status "$target_service" --no-pager | head -n 10

        if [ -n "$backup_file" ] && [ -f "$backup_file" ]; then
            read -p "是否还原修改前配置并重试重启？(y/N): " restore_choice
            if [[ "$restore_choice" =~ ^[Yy]$ ]]; then
                sudo cp "$backup_file" "$target_config"
                if sudo systemctl restart "$target_service"; then
                    green_echo "已还原并重启成功"
                    return 0
                fi
            fi
        fi

        return 1
    }

    target_configs=()
    target_labels=()
    target_ips=()
    target_services=()

    collect_target_configs() {
        target_configs=()
        target_labels=()
        target_ips=()
        target_services=()

        if [ -f "$frp_base_path/frpc.toml" ]; then
            target_configs+=("$frp_base_path/frpc.toml")
            target_labels+=("主配置")
            target_ips+=("$(get_server_ip_from_config "$frp_base_path/frpc.toml")")
            target_services+=("$(get_service_for_config "$frp_base_path/frpc.toml")")
        fi

        if [ -d "$config_dir" ]; then
            local f
            for f in "$config_dir"/frpc_private_*.toml; do
                [ -f "$f" ] || continue
                target_configs+=("$f")
                target_labels+=("私人节点")
                target_ips+=("$(get_server_ip_from_config "$f")")
                target_services+=("$(get_service_for_config "$f")")
            done
        fi

        [ ${#target_configs[@]} -gt 0 ]
    }

    selected_config=""
    selected_label=""
    selected_ip=""
    selected_service=""

    select_target_config() {
        if ! collect_target_configs; then
            red_echo "未找到可用FRP配置（frpc.toml 或 nodes/frpc_*.toml）"
            return 1
        fi

        echo -e "\n请选择目标节点（按IP识别）:"
        local i
        for i in "${!target_configs[@]}"; do
            local svc_disp="${target_services[$i]}"
            [ -z "$svc_disp" ] && svc_disp="未匹配服务"
            printf "%d) [%s] IP: %s | 服务: %s | 配置: %s\n" \
                "$((i+1))" "${target_labels[$i]}" "${target_ips[$i]}" "$svc_disp" "$(basename "${target_configs[$i]}")"
        done

        local choice
        read -p "请输入节点编号 [1-${#target_configs[@]}，0取消]: " choice
        if [ "$choice" = "0" ]; then
            return 1
        fi

        if [[ ! "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 1 ] || [ "$choice" -gt ${#target_configs[@]} ]; then
            red_echo "无效的选择"
            return 1
        fi

        local idx=$((choice-1))
        selected_config="${target_configs[$idx]}"
        selected_label="${target_labels[$idx]}"
        selected_ip="${target_ips[$idx]}"
        selected_service="${target_services[$idx]}"

        green_echo "已选择节点: [$selected_label] IP=$selected_ip 配置=$(basename "$selected_config")"
        return 0
    }

    while true; do
        echo -e "\n请选择操作："
        echo "1) 自动添加七日杀端口映射"
        echo "2) 删除端口映射"
        echo "3) 还原节点配置备份"
        echo "0) 退出"
        read -p "请输入选项: " choice

        case $choice in
            1)
                if ! select_target_config; then
                    continue
                fi

                local game_port
                game_port=$(grep -oP 'name="ServerPort" value="\K\d+' "$server_dir/serverconfig.xml" | head -1)
                [ -z "$game_port" ] && game_port="26900"

                echo ""
                echo "七日杀建议映射以下端口："
                echo "  - TCP $game_port      - 连接/服务列表"
                echo "  - UDP $game_port-$((game_port + 3)) - 游戏数据/查询"
                echo ""
                read -p "远程起始端口 [默认 $game_port]: " remote_base_port
                remote_base_port=${remote_base_port:-$game_port}
                if [[ ! "$remote_base_port" =~ ^[0-9]+$ ]]; then
                    red_echo "远程端口必须是数字"
                    continue
                fi

                local backup_file="$selected_config.bak_$(date +%Y%m%d%H%M%S)"
                sudo cp "$selected_config" "$backup_file"

                local added=0
                add_proxy_if_needed "$selected_config" "7DaysToDie_TCP_${game_port}" "tcp" "$game_port" "$remote_base_port"
                [ $? -eq 0 ] && added=$((added+1))

                local offset local_port remote_port
                for offset in 0 1 2 3; do
                    local_port=$((game_port + offset))
                    remote_port=$((remote_base_port + offset))
                    add_proxy_if_needed "$selected_config" "7DaysToDie_UDP_${local_port}" "udp" "$local_port" "$remote_port"
                    [ $? -eq 0 ] && added=$((added+1))
                done

                if [ $added -gt 0 ]; then
                    safe_restart_frp_with_check "$selected_config" "$backup_file" "$selected_service"
                    green_echo "七日杀端口映射已更新（新增 $added 个）"
                    echo "访问地址示例: $selected_ip:$remote_base_port"
                else
                    yellow_echo "未新增映射（同端口已存在）"
                fi
                ;;

            2)
                if ! select_target_config; then
                    continue
                fi

                entries=()
                while IFS='|' read -r name ptype lport rport; do
                    [ -z "$name" ] && continue
                    entries+=("$name|$ptype|$lport|$rport")
                done < <(list_proxy_entries "$selected_config")

                if [ ${#entries[@]} -eq 0 ]; then
                    yellow_echo "当前节点没有端口映射"
                    continue
                fi

                echo "当前节点映射列表:"
                for i in "${!entries[@]}"; do
                    IFS='|' read -r name ptype lport rport <<< "${entries[$i]}"
                    printf "%d) %s [%s] 本地:%s -> 外网:%s\n" "$((i+1))" "$name" "$ptype" "$lport" "$rport"
                done

                read -p "请选择要删除的映射编号 [1-${#entries[@]}，可输入多个编号或all，0取消]: " selected
                if [ "$selected" = "0" ]; then
                    continue
                fi

                selected_indices=()
                valid_selection=1
                if [ "$selected" = "all" ] || [ "$selected" = "ALL" ]; then
                    for ((i=0; i<${#entries[@]}; i++)); do selected_indices+=("$i"); done
                else
                    if [[ ! "$selected" =~ ^[0-9]+( [0-9]+)*$ ]]; then
                        red_echo "无效输入"
                        continue
                    fi
                    for num in $selected; do
                        if [[ ! "$num" =~ ^[0-9]+$ ]] || [ "$num" -lt 1 ] || [ "$num" -gt ${#entries[@]} ]; then
                            red_echo "无效选择: $num"
                            valid_selection=0
                            break
                        fi
                        selected_indices+=("$((num-1))")
                    done
                fi
                [ $valid_selection -eq 0 ] && continue

                backup_file="$selected_config.bak_$(date +%Y%m%d%H%M%S)"
                sudo cp "$selected_config" "$backup_file"

                for index in "${selected_indices[@]}"; do
                    IFS='|' read -r name ptype lport rport <<< "${entries[$index]}"
                    delete_proxy_block_local "$selected_config" "$name"
                    echo "已删除: $name"
                done

                safe_restart_frp_with_check "$selected_config" "$backup_file" "$selected_service"
                ;;

            3)
                if ! select_target_config; then
                    continue
                fi

                backups=($(ls -t "$selected_config".bak_* 2>/dev/null))
                if [ ${#backups[@]} -eq 0 ]; then
                    yellow_echo "该节点未找到备份"
                    continue
                fi

                for i in "${!backups[@]}"; do
                    printf "%d) %s\n" "$((i+1))" "$(basename "${backups[$i]}")"
                done

                read -p "请选择要还原的备份编号 [1-${#backups[@]}，0取消]: " restore_choice
                if [ "$restore_choice" = "0" ]; then
                    continue
                fi
                if [[ ! "$restore_choice" =~ ^[0-9]+$ ]] || [ "$restore_choice" -lt 1 ] || [ "$restore_choice" -gt ${#backups[@]} ]; then
                    red_echo "无效选择"
                    continue
                fi

                selected_backup="${backups[$((restore_choice-1))]}"
                sudo cp "$selected_backup" "$selected_config"
                safe_restart_frp_with_check "$selected_config" "" "$selected_service"
                green_echo "还原完成"
                ;;

            0)
                return 0
                ;;

            *)
                red_echo "无效选项"
                ;;
        esac

        echo ""
        read -p "按回车键继续..."
    done
}
# ========== FRP进程管理 ==========
manage_frp_processes() {
    while true; do
        echo -e "\n====== FRP进程管理 ======"
        sudo systemctl daemon-reload >/dev/null 2>&1

        declare -a all_services=()

        echo "--- FRP服务列表 ---"
        local idx=0
        
        # 获取所有FRP相关服务
        while IFS= read -r service; do
            [ -z "$service" ] && continue
            local status=$(systemctl is-active "$service" 2>/dev/null)
            local color="\033[32m"
            [[ "$status" != "active" ]] && color="\033[31m"
            echo -e "  $((++idx)). ${color}${service}\033[0m - ${status}"
            all_services+=("$service")
        done < <(systemctl list-units --type=service --all --no-pager --no-legend 2>/dev/null | grep -E 'frpc|frps' | awk '{print $1}')

        if [ ${#all_services[@]} -eq 0 ]; then
            echo "  无FRP服务"
        fi

        echo -e "\n操作选项："
        echo "1) 启动指定服务"
        echo "2) 停止指定服务"
        echo "3) 重启指定服务"
        echo "4) 查看服务状态/日志"
        echo "5) 删除节点配置"
        echo "0) 返回主菜单"

        read -p "请选择操作: " choice

        case $choice in
            1|2|3|4|5)
                if [ ${#all_services[@]} -eq 0 ]; then
                    yellow_echo "当前没有可管理的服务"
                    continue
                fi

                echo -e "\n--- 可管理的服务列表 ---"
                local s_idx=0
                for svc in "${all_services[@]}"; do
                    echo "$((++s_idx)). $svc"
                done

                read -p "请输入服务编号 [1-${#all_services[@]}，0取消]: " service_choice

                if [ "$service_choice" = "0" ]; then
                    continue
                fi

                if [[ ! "$service_choice" =~ ^[0-9]+$ ]] || [ "$service_choice" -lt 1 ] || [ "$service_choice" -gt ${#all_services[@]} ]; then
                    red_echo "无效的选择"
                    continue
                fi

                local service_name="${all_services[$((service_choice-1))]}"

                case $choice in
                    1) sudo systemctl start "$service_name" && green_echo "服务已启动" || red_echo "启动失败" ;;
                    2) sudo systemctl stop "$service_name" && green_echo "服务已停止" || red_echo "停止失败" ;;
                    3) sudo systemctl restart "$service_name" && green_echo "服务已重启" || red_echo "重启失败" ;;
                    4)
                        echo "--- 服务状态 ---"
                        sudo systemctl status "$service_name" --no-pager
                        echo -e "\n--- 最近日志 ---"
                        sudo journalctl -u "$service_name" --no-pager -n 20
                        ;;
                    5)
                        if ask_yes_no "确定要删除服务 $service_name 及其配置" "N"; then
                            local config_path=$(systemctl cat "$service_name" 2>/dev/null | grep "ExecStart=" | grep -oP "\-c \K\S+" | head -1)
                            sudo systemctl stop "$service_name" 2>/dev/null
                            sudo systemctl disable "$service_name" 2>/dev/null
                            sudo rm -f "/etc/systemd/system/$service_name" "/usr/lib/systemd/system/$service_name" 2>/dev/null
                            sudo systemctl daemon-reload
                            sudo systemctl reset-failed
                            if [ -n "$config_path" ] && [ -f "$config_path" ]; then
                                sudo rm -f "$config_path"
                                green_echo "已删除配置文件: $config_path"
                            fi
                            green_echo "节点已删除"
                        fi
                        ;;
                esac
                ;;
            0) return 0 ;;
            *) red_echo "无效选项" ;;
        esac
        
        echo ""
        read -p "按回车键继续..."
    done
}

# ========== FRP管理菜单 ==========
manage_frp_menu() {
    while true; do
        echo "============================================="
        echo "          FRP 内网穿透管理"
        echo "============================================="
        echo "1. 安装FRP客户端"
        echo "2. FRP自动映射端口管理（七日杀专用）"
        echo "3. 添加 LoLiA-FRP 节点（第三方）"
        echo "4. 添加 SakuraFrp 节点（第三方）"
        echo "5. 添加私人FRP节点"
        echo "6. FRP进程管理"
        echo "0. 返回主菜单"
        echo "============================================="
        read -p "请输入操作编号: " choice

        case $choice in
            1) install_frp_client; read -p "按回车键继续..." ;;
            2) auto_map_ports_7dtd; read -p "按回车键继续..." ;;
            3) add_lolia_frp_node; read -p "按回车键继续..." ;;
            4) add_sakura_frp_node; read -p "按回车键继续..." ;;
            5) add_private_node; read -p "按回车键继续..." ;;
            6) manage_frp_processes ;;
            0) return 0 ;;
            *) red_echo "无效选项" ;;
        esac
    done
}

# ============================================
# 存档管理功能
# ============================================

# 获取存档目录
get_saves_dir() {
    echo "$home_dir/.local/share/7DaysToDie/Saves"
}

# 获取serveradmin.xml路径
get_serveradmin_path() {
    local saves_dir=$(get_saves_dir)
    echo "$saves_dir/serveradmin.xml"
}

# 检查存档目录是否存在，不存在则创建
ensure_saves_directory() {
    local saves_dir=$(get_saves_dir)
    if [ ! -d "$saves_dir" ]; then
        echo "创建存档目录: $saves_dir"
        mkdir -p "$saves_dir"
        # 兼容root和普通用户
        if [ -n "$REAL_user" ] && [ "$REAL_user" != "root" ]; then
            chown -R $REAL_user:$REAL_user "$home_dir/.local"
        fi
        green_echo "✓ 存档目录已创建"
    fi
}

# 显示存档列表
list_saves() {
    local saves_dir=$(get_saves_dir)
    
    echo "====== 存档列表 ======"
    
    if [ ! -d "$saves_dir" ]; then
        yellow_echo "存档目录不存在: $saves_dir"
        return 1
    fi
    
    # 遍历地图文件夹
    local map_idx=0
    for map_dir in "$saves_dir"/*/; do
        [ -d "$map_dir" ] || continue
        ((map_idx++))
        local map_name=$(basename "$map_dir")
        echo ""
        echo "[$map_idx] 地图: $map_name"
        echo "    路径: $map_dir"
        
        # 显示该地图下的存档
        local save_idx=0
        for save_dir in "$map_dir"/*/; do
            [ -d "$save_dir" ] || continue
            ((save_idx++))
            local save_name=$(basename "$save_dir")
            local save_size=$(du -sh "$save_dir" 2>/dev/null | cut -f1)
            local save_time=$(stat -c "%y" "$save_dir" 2>/dev/null | cut -d' ' -f1)
            echo "      [$save_idx] $save_name (${save_size}, ${save_time})"
        done
        
        if [ $save_idx -eq 0 ]; then
            echo "      (此地图下暂无存档)"
        fi
    done
    
    if [ $map_idx -eq 0 ]; then
        yellow_echo "暂无存档数据"
        return 1
    fi
    
    return 0
}

# 备份存档
backup_save() {
    local saves_dir=$(get_saves_dir)
    
    echo "====== 备份存档 ======"
    
    if ! list_saves; then
        return 1
    fi
    
    echo ""
    echo "请选择要备份的地图文件夹:"
    local map_idx=0
    local maps=()
    for map_dir in "$saves_dir"/*/; do
        [ -d "$map_dir" ] || continue
        ((map_idx++))
        maps+=("$(basename "$map_dir")")
    done
    read -p "请输入地图编号或名称 (或按回车取消): " map_input

    if [ -z "$map_input" ]; then
        echo "已取消"
        return 0
    fi

    local map_name=""
    if [[ "$map_input" =~ ^[0-9]+$ ]]; then
        if [ "$map_input" -ge 1 ] && [ "$map_input" -le "${#maps[@]}" ]; then
            map_name="${maps[$((map_input-1))]}"
        else
            red_echo "无效的地图编号: $map_input"
            return 1
        fi
    else
        map_name="$map_input"
    fi

    local map_path="$saves_dir/$map_name"
    if [ ! -d "$map_path" ]; then
        red_echo "地图不存在: $map_name"
        return 1
    fi
    
    # 选择存档
    echo ""
    echo "该地图下的存档:"
    local idx=0
    local saves=()
    for save_dir in "$map_path"/*/; do
        [ -d "$save_dir" ] || continue
        ((idx++))
        saves+=("$(basename "$save_dir")")
        echo "  $idx) $(basename "$save_dir")"
    done
    
    if [ ${#saves[@]} -eq 0 ]; then
        red_echo "此地图下没有存档"
        return 1
    fi
    
    read -p "请选择存档编号 (1-$idx): " save_choice
    
    if [[ ! "$save_choice" =~ ^[0-9]+$ ]] || [ "$save_choice" -lt 1 ] || [ "$save_choice" -gt $idx ]; then
        red_echo "无效的选择"
        return 1
    fi
    
    local selected_save="${saves[$((save_choice-1))]}"
    local save_path="$map_path/$selected_save"
    
    # 创建备份
    local backup_dir="$home_dir/7dtd_save_backups"
    mkdir -p "$backup_dir"
    local backup_name="${map_name}_${selected_save}_$(date +%Y%m%d_%H%M%S).tar.gz"
    local backup_path="$backup_dir/$backup_name"
    
    echo "正在备份存档..."
    echo "源路径: $save_path"
    echo "备份文件: $backup_path"
    
    if tar -czf "$backup_path" -C "$map_path" "$selected_save"; then
        green_echo "✓ 备份成功!"
        echo "备份文件: $backup_path"
        ls -lh "$backup_path"
    else
        red_echo "✗ 备份失败"
        return 1
    fi
}

# 还原存档
restore_save() {
    local saves_dir=$(get_saves_dir)
    local backup_root="$home_dir/7dtd_save_backups"
    
    echo "====== 还原存档 ======"
    
    # 递归扫描所有备份目录（含 auto_关闭后/auto_切换版本前/auto_启动前/auto_更新前 等）
    if [ ! -d "$backup_root" ]; then
        red_echo "没有找到备份文件"
        return 1
    fi

    local backups=()
    while IFS= read -r file; do
        [ -f "$file" ] && backups+=("$file")
    done < <(find "$backup_root" -type f -name "*.tar.gz" -printf "%T@|%p\n" 2>/dev/null | sort -nr | cut -d'|' -f2-)

    if [ ${#backups[@]} -eq 0 ]; then
        red_echo "没有找到备份文件"
        return 1
    fi

    echo "可用的备份文件:"
    local idx=0
    for backup in "${backups[@]}"; do
        ((idx++))
        local size=$(ls -lh "$backup" 2>/dev/null | awk '{print $5}')
        local time=$(stat -c "%y" "$backup" 2>/dev/null | cut -d' ' -f1,2 | cut -d'.' -f1)
        local rel="${backup#$backup_root/}"
        echo "  $idx) $rel (${size}, ${time})"
    done
    
    read -p "请选择备份文件编号 (1-$idx, 0取消): " backup_choice
    
    if [ "$backup_choice" = "0" ]; then
        return 0
    fi
    
    if [[ ! "$backup_choice" =~ ^[0-9]+$ ]] || [ "$backup_choice" -lt 1 ] || [ "$backup_choice" -gt $idx ]; then
        red_echo "无效的选择"
        return 1
    fi
    
    local selected_backup="${backups[$((backup_choice-1))]}"
    local backup_name=$(basename "$selected_backup" .tar.gz)
    local name_wo_time
    name_wo_time=$(echo "$backup_name" | sed -E 's/_[0-9]{8}_[0-9]{6}$//')
    local guessed_map="${name_wo_time%%_*}"
    local guessed_save="${name_wo_time#*_}"
    [ "$guessed_save" = "$name_wo_time" ] && guessed_save=""
    
    echo ""
    echo "选择的备份: $(basename "$selected_backup")"
    
    # 显示备份内容
    echo "备份内容预览:"
    tar -tzf "$selected_backup" | head -10
    
    # 询问目标位置
    echo ""
    echo "请选择还原方式:"
    echo "1) 还原到原位置 (覆盖现有存档)"
    read -p "请选择 (1, 0取消): " restore_mode

    if [ "$restore_mode" = "0" ]; then
        return 0
    fi

    if [ "$restore_mode" = "1" ]; then
        local target_map="$guessed_map"
        local target_save="$guessed_save"
        local temp_dir
        temp_dir=$(mktemp -d)

        if ! tar -xzf "$selected_backup" -C "$temp_dir"; then
            rm -rf "$temp_dir"
            red_echo "✗ 解压失败"
            return 1
        fi
        local extracted_dir
        extracted_dir=$(find "$temp_dir" -mindepth 1 -maxdepth 1 -type d | head -1)
        if [ -z "$extracted_dir" ]; then
            rm -rf "$temp_dir"
            red_echo "✗ 备份内容无效"
            return 1
        fi

        [ -z "$target_save" ] && target_save="$(basename "$extracted_dir")"
        if [ -z "$target_map" ] || [ "$target_map" = "$target_save" ]; then
            echo "无法从文件名准确识别地图名，请手动输入"
            read -p "请输入目标地图名称: " target_map
            [ -z "$target_map" ] && rm -rf "$temp_dir" && red_echo "地图名不能为空" && return 1
        fi

        red_echo "警告：这将覆盖存档 $target_map/$target_save"
        if ! ask_yes_no "确定要覆盖吗" "N"; then
            rm -rf "$temp_dir"
            return 0
        fi

        mkdir -p "$saves_dir/$target_map"
        rm -rf "$saves_dir/$target_map/$target_save"
        mv "$extracted_dir" "$saves_dir/$target_map/$target_save"
        rm -rf "$temp_dir"
        green_echo "✓ 还原成功! 位置: $saves_dir/$target_map/$target_save"
    else
        red_echo "无效的选择"
        return 1
    fi
}

# 删除存档
delete_save() {
    local saves_dir=$(get_saves_dir)
    
    echo "====== 删除存档 ======"
    
    if ! list_saves; then
        return 1
    fi
    
    echo ""
    local map_idx=0
    local maps=()
    for map_dir in "$saves_dir"/*/; do
        [ -d "$map_dir" ] || continue
        ((map_idx++))
        maps+=("$(basename "$map_dir")")
    done
    read -p "请输入要删除的地图编号或名称: " map_input

    if [ -z "$map_input" ]; then
        echo "已取消"
        return 0
    fi

    local map_name=""
    if [[ "$map_input" =~ ^[0-9]+$ ]]; then
        if [ "$map_input" -ge 1 ] && [ "$map_input" -le "${#maps[@]}" ]; then
            map_name="${maps[$((map_input-1))]}"
        else
            red_echo "无效的地图编号: $map_input"
            return 1
        fi
    else
        map_name="$map_input"
    fi

    local map_path="$saves_dir/$map_name"
    if [ ! -d "$map_path" ]; then
        red_echo "地图不存在: $map_name"
        return 1
    fi
    
    echo ""
    echo "该地图下的存档:"
    local idx=0
    local saves=()
    for save_dir in "$map_path"/*/; do
        [ -d "$save_dir" ] || continue
        ((idx++))
        saves+=("$(basename "$save_dir")")
        echo "  $idx) $(basename "$save_dir")"
    done
    echo "  all) 删除整个地图及所有存档"
    
    read -p "请选择要删除的存档编号 (1-$idx, all删除全部, 0取消): " delete_choice
    
    if [ "$delete_choice" = "0" ]; then
        return 0
    fi
    
    if [ "$delete_choice" = "all" ]; then
        red_echo "警告：这将删除地图 '$map_name' 及其所有存档！"
        if ask_yes_no "确定要删除吗" "N"; then
            rm -rf "$map_path"
            green_echo "✓ 地图已删除"
        fi
        return 0
    fi
    
    if [[ ! "$delete_choice" =~ ^[0-9]+$ ]] || [ "$delete_choice" -lt 1 ] || [ "$delete_choice" -gt $idx ]; then
        red_echo "无效的选择"
        return 1
    fi
    
    local selected_save="${saves[$((delete_choice-1))]}"
    local save_path="$map_path/$selected_save"
    
    red_echo "警告：这将永久删除存档 '$selected_save'！"
    if ask_yes_no "确定要删除吗" "N"; then
        rm -rf "$save_path"
        green_echo "✓ 存档已删除"
    fi
}

# 自动备份设置
setup_auto_backup() {
    local saves_dir=$(get_saves_dir)
    local cron_file="/etc/cron.d/7dtd_auto_backup"
    
    echo "====== 自动备份设置 ======"
    
    echo "当前自动备份状态:"
    if [ -f "$cron_file" ]; then
        green_echo "✓ 已启用"
        echo "配置:"
        cat "$cron_file" | grep -v "^#" | grep -v "^$"
    else
        yellow_echo "✗ 未启用"
    fi
    
    echo ""
    echo "请选择操作:"
    echo "1) 启用自动备份"
    echo "2) 关闭自动备份"
    echo "3) 查看备份记录"
    echo "0) 返回"
    
    read -p "请选择: " choice
    
    case $choice in
        1)
            echo ""
            echo "请选择备份频率:"
            echo "1) 每小时"
            echo "2) 每6小时"
            echo "3) 每12小时"
            echo "4) 每天"
            echo "5) 自定义cron表达式"
            
            read -p "请选择 (1-5): " freq_choice
            
            local cron_expr
            case $freq_choice in
                1) cron_expr="0 * * * *" ;;
                2) cron_expr="0 */6 * * *" ;;
                3) cron_expr="0 */12 * * *" ;;
                4) cron_expr="0 0 * * *" ;;
                5) 
                    read -p "请输入cron表达式 (如 '0 3 * * *' 表示每天3点): " cron_expr
                    ;;
                *) 
                    red_echo "无效选择"
                    return 1
                    ;;
            esac
            
            # 创建备份脚本
            local backup_script="$home_dir/7dtd_auto_backup.sh"
            cat > "$backup_script" << 'EOF'
#!/bin/bash
# 七日杀自动备份脚本

# 兼容root和普通用户
current_user=$(whoami)
if [ "$current_user" = "root" ]; then
    home_dir="/root"
else
    home_dir="$HOME"
fi
saves_dir="$home_dir/.local/share/7DaysToDie/Saves"
backup_dir="$home_dir/7dtd_save_backups/auto"

mkdir -p "$backup_dir"

# 备份所有存档
for map_dir in "$saves_dir"/*/; do
    [ -d "$map_dir" ] || continue
    map_name=$(basename "$map_dir")
    
    for save_dir in "$map_dir"/*/; do
        [ -d "$save_dir" ] || continue
        save_name=$(basename "$save_dir")
        
        backup_name="${map_name}_${save_name}_$(date +%Y%m%d_%H%M%S).tar.gz"
        tar -czf "$backup_dir/$backup_name" -C "$map_dir" "$save_name" 2>/dev/null
    done
done

# 清理7天前的备份
find "$backup_dir" -name "*.tar.gz" -mtime +7 -delete

EOF
            chmod +x "$backup_script"
            
            # 创建cron任务
            sudo tee "$cron_file" << EOF
# 七日杀自动备份
$cron_expr root $backup_script
EOF
            
            green_echo "✓ 自动备份已启用"
            echo "备份频率: $cron_expr"
            echo "备份位置: $home_dir/7dtd_save_backups/auto"
            ;;
        2)
            if [ -f "$cron_file" ]; then
                sudo rm -f "$cron_file"
                green_echo "✓ 自动备份已关闭"
            else
                yellow_echo "自动备份未启用"
            fi
            ;;
        3)
            local auto_backup_dir="$home_dir/7dtd_save_backups/auto"
            if [ -d "$auto_backup_dir" ]; then
                echo "自动备份记录:"
                ls -lht "$auto_backup_dir" | head -20
            else
                yellow_echo "暂无自动备份记录"
            fi
            ;;
        0)
            return 0
            ;;
    esac
}

# 存档管理菜单
manage_saves_menu() {
    while true; do
        echo "============================================="
        echo "          存档管理"
        echo "============================================="
        echo "1. 查看存档列表"
        echo "2. 备份存档"
        echo "3. 还原存档"
        echo "4. 删除存档"
        echo "5. 定时备份存档 (每小时)"
        echo "6. 自动清理日志与备份"
        echo "0. 返回主菜单"
        echo "============================================="
        read -p "请输入操作编号: " choice

        case $choice in
            1) list_saves; read -p "按回车键继续..." ;;
            2) backup_save; read -p "按回车键继续..." ;;
            3) restore_save; read -p "按回车键继续..." ;;
            4) delete_save; read -p "按回车键继续..." ;;
            5) setup_hourly_backup; read -p "按回车键继续..." ;;
            6) setup_cleanup_policy; read -p "按回车键继续..." ;;
            0) return 0 ;;
            *) red_echo "无效选项" ;;
        esac
    done
}

# 设置定时备份
setup_hourly_backup() {
    local saves_dir=$(get_saves_dir)
    local cron_file="/etc/cron.d/7dtd_auto_backup"
    local backup_script="$home_dir/7dtd_auto_backup.sh"
    local config_file="$home_dir/.7dtd_backup_config"
    
    echo "====== 定时备份存档设置 ======"
    echo ""
    
    # 读取当前配置
    local backup_interval="60"
    local keep_count="24"
    if [ -f "$config_file" ]; then
        source "$config_file" 2>/dev/null
    fi
    
    echo "当前状态:"
    if [ -f "$cron_file" ]; then
        green_echo "✓ 已启用"
        case "$backup_interval" in
            15) echo "备份间隔: 每15分钟" ;;
            30) echo "备份间隔: 每30分钟" ;;
            60) echo "备份间隔: 每小时" ;;
            120) echo "备份间隔: 每2小时" ;;
            *) echo "备份间隔: ${backup_interval}分钟" ;;
        esac
        echo "备份位置: $home_dir/7dtd_save_backups/auto"
        # 显示最近备份
        if [ -d "$home_dir/7dtd_save_backups/auto" ]; then
            local backup_count=$(ls -1 "$home_dir/7dtd_save_backups/auto"/*.tar.gz 2>/dev/null | wc -l)
            echo "已有备份: $backup_count 个"
        fi
    else
        yellow_echo "✗ 未启用"
    fi
    
    echo ""
    echo "请选择操作:"
    echo "1) 启用定时备份"
    echo "2) 关闭定时备份"
    echo "3) 查看备份列表"
    echo "0) 返回"
    
    read -p "请选择: " choice
    
    case $choice in
        1)
            echo ""
            echo "请选择备份间隔:"
            echo "1) 每15分钟 (高频，适合重要存档)"
            echo "2) 每30分钟 (中频，推荐)"
            echo "3) 每小时 (低频，默认)"
            echo "4) 每2小时 (超低频)"
            
            read -p "请选择 (1-4) [默认3]: " interval_choice
            interval_choice=${interval_choice:-3}
            
            case "$interval_choice" in
                1) backup_interval=15; keep_count=48 ;;
                2) backup_interval=30; keep_count=48 ;;
                3) backup_interval=60; keep_count=24 ;;
                4) backup_interval=120; keep_count=12 ;;
                *) backup_interval=60; keep_count=24 ;;
            esac
            
            # 保存配置
            cat > "$config_file" << EOF
backup_interval=$backup_interval
keep_count=$keep_count
EOF
            chmod 600 "$config_file"
            chown $REAL_user:$REAL_user "$config_file" 2>/dev/null
            
            # 创建备份脚本
            cat > "$backup_script" << 'EOF'
#!/bin/bash
# 七日杀定时备份脚本

# 读取配置
CONFIG_FILE="CONFIG_FILE_PLACEHOLDER"
if [ -f "$CONFIG_FILE" ]; then
    source "$CONFIG_FILE"
fi
backup_interval=${backup_interval:-60}
keep_count=${keep_count:-24}

# 兼容root和普通用户
current_user=$(whoami)
if [ "$current_user" = "root" ]; then
    home_dir="/root"
else
    home_dir="$HOME"
fi

saves_dir="$home_dir/.local/share/7DaysToDie/Saves"
backup_dir="$home_dir/7dtd_save_backups/auto"
log_file="$home_dir/7dtd_auto_backup.log"

mkdir -p "$backup_dir"

echo "[$(date '+%Y-%m-%d %H:%M:%S')] 开始定时备份 (间隔: ${backup_interval}分钟)" >> "$log_file"

# 备份所有存档
for map_dir in "$saves_dir"/*/; do
    [ -d "$map_dir" ] || continue
    map_name=$(basename "$map_dir")
    
    for save_dir in "$map_dir"/*/; do
        [ -d "$save_dir" ] || continue
        save_name=$(basename "$save_dir")
        
        backup_name="${map_name}_${save_name}_$(date +%Y%m%d_%H%M%S).tar.gz"
        if tar -czf "$backup_dir/$backup_name" -C "$map_dir" "$save_name" 2>/dev/null; then
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] 备份成功: $backup_name" >> "$log_file"
        else
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] 备份失败: $map_name/$save_name" >> "$log_file"
        fi
    done
done

# 清理旧备份
ls -t "$backup_dir"/*.tar.gz 2>/dev/null | tail -n +$((keep_count + 1)) | xargs -r rm -f

echo "[$(date '+%Y-%m-%d %H:%M:%S')] 定时备份完成" >> "$log_file"
EOF
            
            # 替换占位符
            sed -i "s|CONFIG_FILE_PLACEHOLDER|$config_file|g" "$backup_script"
            chmod +x "$backup_script"
            chown $REAL_user:$REAL_user "$backup_script" 2>/dev/null
            
            # 计算cron表达式
            local cron_expr
            case "$backup_interval" in
                15) cron_expr="*/15 * * * *" ;;
                30) cron_expr="*/30 * * * *" ;;
                60) cron_expr="0 * * * *" ;;
                120) cron_expr="0 */2 * * *" ;;
                *) cron_expr="0 * * * *" ;;
            esac
            
            # 创建cron任务
            sudo tee "$cron_file" > /dev/null << EOF
# 七日杀定时自动备份
$cron_expr root $backup_script
EOF
            
            green_echo "✓ 定时备份已启用"
            case "$backup_interval" in
                15) echo "备份间隔: 每15分钟" ;;
                30) echo "备份间隔: 每30分钟" ;;
                60) echo "备份间隔: 每小时" ;;
                120) echo "备份间隔: 每2小时" ;;
            esac
            echo "保留数量: 最近$keep_count个备份"
            echo "备份位置: $home_dir/7dtd_save_backups/auto"
            echo "日志文件: $home_dir/7dtd_auto_backup.log"
            ;;
        2)
            if [ -f "$cron_file" ]; then
                sudo rm -f "$cron_file"
                green_echo "✓ 定时备份已关闭"
            else
                yellow_echo "定时备份未启用"
            fi
            ;;
        3)
            local auto_dir="$home_dir/7dtd_save_backups/auto"
            if [ -d "$auto_dir" ]; then
                echo "定时备份列表 (最近20个):"
                ls -lht "$auto_dir"/*.tar.gz 2>/dev/null | head -20
                echo ""
                local total_count=$(ls -1 "$auto_dir"/*.tar.gz 2>/dev/null | wc -l)
                echo "总计: $total_count 个备份"
            else
                yellow_echo "暂无定时备份记录"
            fi
            ;;
        0)
            return 0
            ;;
    esac
}

# ============================================
# 管理员管理功能
# ============================================

# 生成默认的serveradmin.xml
generate_default_serveradmin() {
    local admin_file=$(get_serveradmin_path)
    
    mkdir -p "$(dirname "$admin_file")"
    
    cat > "$admin_file" << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!--
	This file holds the settings for who is banned, whitelisted, admins and server command permissions.
	See the comments in the original file for detailed instructions.
-->
<adminTools>
  <users>
    <!-- Admin users will be added here -->
  </users>
  <whitelist>
    <!-- Whitelisted users will be added here -->
  </whitelist>
  <blacklist>
    <!-- Banned users will be added here -->
  </blacklist>
  <commands>
    <permission cmd="chunkcache" permission_level="1000" />
    <permission cmd="createwebuser" permission_level="1000" />
    <permission cmd="cvar" permission_level="1000" />
    <permission cmd="debugshot" permission_level="1000" />
    <permission cmd="debugweather" permission_level="1000" />
    <permission cmd="decomgr" permission_level="1000" />
    <permission cmd="getgamepref" permission_level="1000" />
    <permission cmd="getgamestat" permission_level="1000" />
    <permission cmd="getlogpath" permission_level="1000" />
    <permission cmd="getoptions" permission_level="1000" />
    <permission cmd="gettime" permission_level="1000" />
    <permission cmd="gfx" permission_level="1000" />
    <permission cmd="graph" permission_level="1000" />
    <permission cmd="help" permission_level="1000" />
    <permission cmd="listplayerids" permission_level="1000" />
    <permission cmd="listthreads" permission_level="1000" />
    <permission cmd="loot" permission_level="1000" />
    <permission cmd="memcl" permission_level="1000" />
    <permission cmd="meshdatamanager" permission_level="1000" />
    <permission cmd="settempunit" permission_level="1000" />
    <permission cmd="uioptions" permission_level="1000" />
  </commands>
  <apitokens>
  </apitokens>
  <webmodules />
  <webusers />
</adminTools>
EOF

    # 兼容root和普通用户
    if [ -n "$REAL_user" ] && [ "$REAL_user" != "root" ]; then
        chown $REAL_user:$REAL_user "$admin_file"
    fi
    green_echo "✓ 已生成默认 serveradmin.xml"
}

# 从日志中提取玩家ID
extract_player_ids_from_logs() {
    local log_dir="$server_dir"
    local players_file="/tmp/7dtd_players_$(date +%s).txt"
    
    echo "正在从日志中提取玩家信息..."
    echo "日志目录: $log_dir"
    
    # 查找最新的日志文件（支持 .log 和 output_log*.txt 格式）
    local latest_log=""
    
    # 首先尝试查找 .log 文件
    if ls "$log_dir"/*.log 1>/dev/null 2>&1; then
        latest_log=$(ls -t "$log_dir"/*.log 2>/dev/null | head -1)
    fi
    
    # 如果没找到，尝试查找 output_log*.txt 文件
    if [ -z "$latest_log" ] && ls "$log_dir"/output_log*.txt 1>/dev/null 2>&1; then
        latest_log=$(ls -t "$log_dir"/output_log*.txt 2>/dev/null | head -1)
    fi
    
    # 还是没找到，尝试查找任何 .txt 文件
    if [ -z "$latest_log" ] && ls "$log_dir"/*.txt 1>/dev/null 2>&1; then
        latest_log=$(ls -t "$log_dir"/*.txt 2>/dev/null | head -1)
    fi
    
    if [ -z "$latest_log" ]; then
        yellow_echo "未找到日志文件"
        yellow_echo "支持的日志格式: *.log, output_log*.txt, *.txt"
        echo "日志目录内容:"
        ls -la "$log_dir" 2>/dev/null || echo "  (目录为空或不存在)"
        return 1
    fi
    
    echo "分析日志文件: $(basename "$latest_log")"
    
    # 提取玩家信息（名字+ID）
    # 日志格式1（旧）: Player '玩家名' connected with Steam ID: 76561197960265728
    # 日志格式2（新）: [Auth] ... PltfmId='Steam_7656...', PlayerName='玩家名'
    
    echo ""
    echo "正在解析玩家连接记录..."
    
    # 创建临时文件存储结果
    local parsed_file="/tmp/7dtd_parsed_$(date +%s).txt"
    
    # 首先尝试提取 [Auth] 格式的记录（新版本日志）
    grep -E "\[Auth\].*PltfmId.*PlayerName" "$latest_log" 2>/dev/null | \
        grep -oE "PltfmId='[^']+'.*PlayerName='[^']+'" | \
        sed "s/PltfmId='//g; s/', CrossId//g; s/PlayerName='//g; s/'$//g; s/Steam_//g; s/EOS_//g" | \
        sort -u > "$parsed_file"
    
    # 如果没找到，尝试旧格式
    if [ ! -s "$parsed_file" ]; then
        grep -E "Player.*connected.*with.*(Steam|EOS).*ID" "$latest_log" 2>/dev/null | \
            grep -oE "Player\s+'[^']+'.*ID:\s*[0-9a-fA-F]+" | \
            sort -u > "$parsed_file"
    fi
    
    if [ -s "$parsed_file" ]; then
        echo ""
        echo "========================================"
        echo "  从日志中找到的玩家信息"
        echo "========================================"
        echo ""
        
        # 解析并显示玩家名字和ID
        local idx=0
        while IFS= read -r line; do
            ((idx++))
            
            # 检查是否是ID+名字格式（新格式）
            if echo "$line" | grep -q ","; then
                # 格式: SteamID,玩家名字
                local id_part=$(echo "$line" | cut -d',' -f1)
                local name_part=$(echo "$line" | cut -d',' -f2-)
                
                # 判断是Steam还是EOS
                if echo "$id_part" | grep -qE "^[0-9]{17}$"; then
                    # 17位数字是Steam ID
                    if [ -n "$name_part" ]; then
                        echo "  $idx) 名字: $name_part"
                        echo "      Steam ID: $id_part"
                    else
                        echo "  $idx) Steam ID: $id_part"
                    fi
                elif echo "$id_part" | grep -qE "^[0-9a-fA-F]{32}$"; then
                    # 32位十六进制是EOS ID
                    if [ -n "$name_part" ]; then
                        echo "  $idx) 名字: $name_part"
                        echo "      EOS ID: $id_part"
                    else
                        echo "  $idx) EOS ID: $id_part"
                    fi
                fi
            else
                # 旧格式
                local player_name=$(echo "$line" | grep -oE "'[^']+'" | tr -d "'")
                local steam_id=$(echo "$line" | grep -oE "7656119[0-9]{10}")
                local eos_id=$(echo "$line" | grep -oE "0002[0-9a-fA-F]{28}")
                
                if [ -n "$player_name" ] && [ -n "$steam_id" ]; then
                    echo "  $idx) 名字: $player_name"
                    echo "      Steam ID: $steam_id"
                elif [ -n "$player_name" ] && [ -n "$eos_id" ]; then
                    echo "  $idx) 名字: $player_name"
                    echo "      EOS ID: $eos_id"
                elif [ -n "$steam_id" ]; then
                    echo "  $idx) Steam ID: $steam_id"
                fi
            fi
            echo ""
        done < "$parsed_file"
        
        echo "========================================"
        echo ""
        
        # 同时提取所有Steam ID列表（用于快速复制）
        local steam_ids=$(grep -oE "7656119[0-9]{10}" "$latest_log" | sort -u)
        if [ -n "$steam_ids" ]; then
            echo "Steam ID列表（快速复制）:"
            local id_idx=0
            for sid in $steam_ids; do
                ((id_idx++))
                echo "  $id_idx) $sid"
            done
            echo ""
        fi
        
        rm -f "$players_file" "$parsed_file"
        return 0
    else
        # 如果没解析到带名字的记录，尝试简单提取Steam ID
        local steam_ids=$(grep -oE "7656119[0-9]{10}" "$latest_log" | sort -u)
        if [ -n "$steam_ids" ]; then
            echo ""
            echo "找到以下Steam ID（未解析到玩家名字）:"
            local id_idx=0
            for sid in $steam_ids; do
                ((id_idx++))
                echo "  $id_idx) $sid"
            done
            echo ""
            rm -f "$players_file" "$parsed_file"
            return 0
        fi
        
        yellow_echo "未从日志中提取到玩家信息"
        yellow_echo "提示: 需要服务器运行且有玩家连接后才能记录到日志"
        rm -f "$players_file" "$parsed_file"
        return 1
    fi
}

# 列出当前管理员
list_admins() {
    local admin_file=$(get_serveradmin_path)
    
    echo "====== 当前管理员列表 ======"
    
    if [ ! -f "$admin_file" ]; then
        yellow_echo "serveradmin.xml 不存在，将创建默认文件"
        generate_default_serveradmin
        return 1
    fi
    
    echo "--- 管理员 (users) ---"
    grep -E "<user .*permission_level" "$admin_file" | grep -v "<!--" | while read line; do
        local platform=$(echo "$line" | grep -oP 'platform="\K[^"]+')
        local userid=$(echo "$line" | grep -oP 'userid="\K[^"]+')
        local name=$(echo "$line" | grep -oP 'name="\K[^"]+' | head -1)
        local level=$(echo "$line" | grep -oP 'permission_level="\K[^"]+')
        echo "  [$platform] $name (ID: $userid) - 权限等级: $level"
    done
    
    local admin_count
    admin_count=$(grep -E "<user .*permission_level" "$admin_file" 2>/dev/null | grep -vc "<!--")
    if [ "${admin_count:-0}" -eq 0 ]; then
        echo "  (暂无管理员)"
    fi
    
    echo ""
    echo "--- 白名单 (whitelist) ---"
    local whitelist_count=$(grep -c "<user " "$admin_file" | grep -v "permission_level" || echo "0")
    if [ "$whitelist_count" -gt 0 ]; then
        grep "<user " "$admin_file" | grep -v "permission_level" | grep -v "<!--" | while read line; do
            local platform=$(echo "$line" | grep -oP 'platform="\K[^"]+')
            local userid=$(echo "$line" | grep -oP 'userid="\K[^"]+')
            local name=$(echo "$line" | grep -oP 'name="\K[^"]+' | head -1)
            echo "  [$platform] $name (ID: $userid)"
        done
    else
        echo "  (暂无白名单用户)"
    fi
    
    echo ""
    echo "--- 黑名单 (blacklist) ---"
    local blacklist_count=$(grep -c "<blacklisted " "$admin_file" || echo "0")
    if [ "$blacklist_count" -gt 0 ]; then
        grep "<blacklisted " "$admin_file" | grep -v "<!--" | while read line; do
            local platform=$(echo "$line" | grep -oP 'platform="\K[^"]+')
            local userid=$(echo "$line" | grep -oP 'userid="\K[^"]+')
            local name=$(echo "$line" | grep -oP 'name="\K[^"]+' | head -1)
            local reason=$(echo "$line" | grep -oP 'reason="\K[^"]+')
            echo "  [$platform] $name (ID: $userid) - 原因: $reason"
        done
    else
        echo "  (暂无黑名单用户)"
    fi
}

# 添加管理员
add_admin() {
    local admin_file=$(get_serveradmin_path)
    
    echo "====== 添加管理员 ======"
    
    if [ ! -f "$admin_file" ]; then
        generate_default_serveradmin
    fi
    
    echo "请选择玩家ID来源:"
    echo "1) 从服务器日志中查找"
    echo "2) 手动输入"
    
    read -p "请选择 (1-2): " source_choice
    
    local platform="Steam"
    local userid=""
    local name=""
    
    case $source_choice in
        1)
            # 从日志提取并选择
            local parsed_file="/tmp/7dtd_parsed_$(date +%s).txt"
            local log_dir="$server_dir"
            
            # 查找日志文件
            local latest_log=""
            latest_log=$(get_active_server_log_file 2>/dev/null)
            if [ -z "$latest_log" ] && ls "$log_dir"/*.log 1>/dev/null 2>&1; then
                latest_log=$(ls -t "$log_dir"/*.log 2>/dev/null | head -1)
            fi
            if [ -z "$latest_log" ] && ls "$log_dir"/output_log*.txt 1>/dev/null 2>&1; then
                latest_log=$(ls -t "$log_dir"/output_log*.txt 2>/dev/null | head -1)
            fi
            if [ -z "$latest_log" ] && ls "$log_dir"/*.txt 1>/dev/null 2>&1; then
                latest_log=$(ls -t "$log_dir"/*.txt 2>/dev/null | head -1)
            fi
            
            if [ -z "$latest_log" ]; then
                yellow_echo "未找到日志文件"
                return 1
            fi
            
            echo "分析日志文件: $(basename "$latest_log")"
            
            # 提取玩家信息（支持多种日志格式）
            # 格式1: Player '名字' connected with Steam ID: 7656...
            # 格式2: [Auth] ... PltfmId='Steam_7656...', PlayerName='名字'
            
            # 先提取 [Auth] 记录，统一输出: 平台<TAB>ID<TAB>名字
            grep -E "\[Auth\].*PltfmId=.*PlayerName=" "$latest_log" 2>/dev/null | \
                sed -n "s/.*PltfmId='\([^']*\)'.*PlayerName='\([^']*\)'.*/\1\t\2/p" | \
                awk -F '\t' '{
                    pid=$1; name=$2;
                    if (pid ~ /^Steam_/) {
                        print "Steam\t" substr(pid, 7) "\t" name
                    } else if (pid ~ /^EOS_/) {
                        print "EOS\t" substr(pid, 5) "\t" name
                    } else if (pid != "") {
                        print "Unknown\t" pid "\t" name
                    }
                }' | sort -u > "$parsed_file"
            
            # 如果没找到，尝试旧格式
            if [ ! -s "$parsed_file" ]; then
                grep -E "Player.*connected.*with.*(Steam|EOS).*ID" "$latest_log" 2>/dev/null | \
                    sed -n "s/.*Player '\([^']*\)'.*\(Steam\|EOS\) ID:[[:space:]]*\([0-9a-fA-F]*\).*/\2\t\3\t\1/p" | \
                    sort -u > "$parsed_file"
            fi
            
            # 还是没找到，尝试只提取Steam ID
            if [ ! -s "$parsed_file" ]; then
                grep -oE "7656119[0-9]{10}" "$latest_log" | sort -u | awk '{print "Steam\t"$1"\t"}' > "$parsed_file"
                if [ ! -s "$parsed_file" ]; then
                    yellow_echo "未从日志中提取到玩家信息"
                    rm -f "$parsed_file"
                    return 1
                fi
            fi
            
            echo ""
            echo "========================================"
            echo "  从日志中找到的玩家列表"
            echo "========================================"
            echo ""
            
            # 显示带序号的列表
            local idx=0
            declare -a player_names
            declare -a player_ids
            declare -a player_platforms
            
            while IFS= read -r line; do
                local rec_platform=""
                local rec_id=""
                local rec_name=""
                rec_platform=$(echo "$line" | awk -F '\t' '{print $1}')
                rec_id=$(echo "$line" | awk -F '\t' '{print $2}')
                rec_name=$(echo "$line" | awk -F '\t' '{print $3}')

                if [ -n "$rec_id" ]; then
                    ((idx++))
                    player_ids[$idx]="$rec_id"
                    player_platforms[$idx]="$rec_platform"
                    player_names[$idx]="$rec_name"
                    if [ -n "$rec_name" ]; then
                        echo "  $idx) $rec_name (${rec_platform}: $rec_id)"
                    else
                        echo "  $idx) ${rec_platform} ID: $rec_id"
                    fi
                fi
            done < "$parsed_file"
            
            echo ""
            echo "========================================"
            
            if [ $idx -eq 0 ]; then
                yellow_echo "未解析到有效玩家信息"
                rm -f "$parsed_file"
                return 1
            fi
            
            # 让用户选择序号
            echo ""
            read -p "请选择玩家序号 (1-$idx): " player_choice
            
            if [[ ! "$player_choice" =~ ^[0-9]+$ ]] || [ "$player_choice" -lt 1 ] || [ "$player_choice" -gt $idx ]; then
                red_echo "无效的选择"
                rm -f "$parsed_file"
                return 1
            fi
            
            userid="${player_ids[$player_choice]}"
            name="${player_names[$player_choice]}"
            platform="${player_platforms[$player_choice]}"
            
            rm -f "$parsed_file"
            
            green_echo "已选择: ${name:-$userid}"
            ;;
        2)
            echo "平台类型:"
            echo "1) Steam"
            echo "2) EOS"
            read -p "请选择 (1-2, 默认Steam): " platform_choice
            
            if [ "$platform_choice" = "2" ]; then
                platform="EOS"
            fi
            
            read -p "请输入玩家ID: " userid
            read -p "请输入玩家名称 (可选): " name
            ;;
        *)
            red_echo "无效选择"
            return 1
            ;;
    esac
    
    if [ -z "$userid" ]; then
        red_echo "玩家ID不能为空"
        return 1
    fi
    
    read -p "请输入权限等级 (0-1000, 默认0最高权限): " level
    level=${level:-0}
    
    # 检查是否已存在
    if grep -q "userid=\"$userid\"" "$admin_file"; then
        yellow_echo "该玩家ID已存在于配置中"
        if ! ask_yes_no "是否更新权限" "N"; then
            return 0
        fi
        # 删除旧的条目
        sed -i "/userid=\"$userid\"/d" "$admin_file"
    fi
    
    # 添加新管理员
    local new_entry="    <user platform=\"$platform\" userid=\"$userid\" name=\"$name\" permission_level=\"$level\" />"
    
    # 在 </users> 标签前插入
    sed -i "/<\/users>/i\\$new_entry" "$admin_file"
    
    green_echo "✓ 管理员已添加"
    echo "  平台: $platform"
    echo "  ID: $userid"
    echo "  名称: $name"
    echo "  权限等级: $level"
    audit_admin_action "add_admin" "platform=$platform userid=$userid name=$name level=$level"
}

# 移除管理员
remove_admin() {
    local admin_file=$(get_serveradmin_path)
    
    echo "====== 移除管理员 ======"
    
    if [ ! -f "$admin_file" ]; then
        red_echo "serveradmin.xml 不存在"
        return 1
    fi
    
    list_admins
    
    echo ""
    read -p "请输入要移除的管理员ID: " userid
    
    if [ -z "$userid" ]; then
        echo "已取消"
        return 0
    fi
    
    if grep -q "userid=\"$userid\"" "$admin_file"; then
        # 备份原文件
        cp "$admin_file" "$admin_file.bak_$(date +%Y%m%d%H%M%S)"
        
        # 删除该用户条目
        sed -i "/userid=\"$userid\"/d" "$admin_file"
        green_echo "✓ 已移除"
        audit_admin_action "remove_admin" "userid=$userid"
    else
        red_echo "未找到该ID"
        return 1
    fi
}

# 添加到白名单
add_whitelist() {
    local admin_file=$(get_serveradmin_path)
    
    echo "====== 添加到白名单 ======"
    
    if [ ! -f "$admin_file" ]; then
        generate_default_serveradmin
    fi
    
    read -p "请输入玩家平台 (Steam/EOS): " platform
    platform=${platform:-Steam}
    
    read -p "请输入玩家ID: " userid
    read -p "请输入玩家名称 (可选): " name
    
    if [ -z "$userid" ]; then
        red_echo "玩家ID不能为空"
        return 1
    fi
    
    local new_entry="    <user platform=\"$platform\" userid=\"$userid\" name=\"$name\" />"
    
    # 在 </whitelist> 标签前插入
    sed -i "/<\/whitelist>/i\\$new_entry" "$admin_file"
    
    green_echo "✓ 已添加到白名单"
    audit_admin_action "add_whitelist" "platform=$platform userid=$userid name=$name"
}

# 添加到黑名单
add_blacklist() {
    local admin_file=$(get_serveradmin_path)
    
    echo "====== 添加到黑名单 ======"
    
    if [ ! -f "$admin_file" ]; then
        generate_default_serveradmin
    fi
    
    read -p "请输入玩家平台 (Steam/EOS): " platform
    platform=${platform:-Steam}
    
    read -p "请输入玩家ID: " userid
    read -p "请输入玩家名称 (可选): " name
    read -p "请输入封禁原因: " reason
    
    if [ -z "$userid" ]; then
        red_echo "玩家ID不能为空"
        return 1
    fi
    
    local unbandate=$(date -d "+7 days" +%Y-%m-%d 2>/dev/null || echo "")
    
    local new_entry="    <blacklisted platform=\"$platform\" userid=\"$userid\" name=\"$name\" unbandate=\"$unbandate\" reason=\"$reason\" />"
    
    # 在 </blacklist> 标签前插入
    sed -i "/<\/blacklist>/i\\$new_entry" "$admin_file"
    
    green_echo "✓ 已添加到黑名单"
    audit_admin_action "add_blacklist" "platform=$platform userid=$userid name=$name reason=$reason"
}

# 编辑serveradmin.xml文件
edit_serveradmin() {
    local admin_file=$(get_serveradmin_path)
    
    if [ ! -f "$admin_file" ]; then
        generate_default_serveradmin
    fi
    
    echo "正在打开 serveradmin.xml..."
    echo "文件路径: $admin_file"
    echo ""
    
    # 检测可用的编辑器
    if command -v nano &> /dev/null; then
        nano "$admin_file"
    elif command -v vim &> /dev/null; then
        vim "$admin_file"
    else
        echo "未找到文本编辑器，请手动编辑:"
        echo "$admin_file"
    fi
}

# 管理员管理菜单
manage_admins_menu() {
    while true; do
        echo "============================================="
        echo "          管理员管理"
        echo "============================================="
        echo "1. 查看管理员/白名单/黑名单"
        echo "2. 添加管理员"
        echo "3. 移除管理员"
        echo "4. 添加到白名单"
        echo "5. 添加到黑名单"
        echo "6. 手动编辑 serveradmin.xml"
        echo "7. 查看管理员审计日志"
        echo "0. 返回主菜单"
        echo "============================================="
        read -p "请输入操作编号: " choice

        case $choice in
            1) list_admins; read -p "按回车键继续..." ;;
            2) add_admin; read -p "按回车键继续..." ;;
            3) remove_admin; read -p "按回车键继续..." ;;
            4) add_whitelist; read -p "按回车键继续..." ;;
            5) add_blacklist; read -p "按回车键继续..." ;;
            6) edit_serveradmin; read -p "按回车键继续..." ;;
            7)
                local audit_file="$home_dir/7dtd_admin_audit.log"
                if [ -f "$audit_file" ]; then
                    echo "管理员审计日志（最近50行）:"
                    tail -50 "$audit_file"
                else
                    yellow_echo "暂无管理员审计日志"
                fi
                read -p "按回车键继续..." ;;
            0) return 0 ;;
            *) red_echo "无效选项" ;;
        esac
    done
}

# --- 主菜单 ---
main_menu() {
    while true; do
        # 获取当前服务器版本
        local current_version=$(get_current_version)
        
        echo "============================================="
        echo "      七日杀服务器多功能管理脚本 v1.2.4 Oracle/Debian12 ARM64兼容版"
        echo "      当前服务器版本: $current_version"
        echo "============================================="
        echo "===  脚本来自 伶依nekochan 抖音 ACFUN同名主播 ==="
        echo "===  本脚本部分代码由kimi生成 有问题请进群告诉我 737331541 记得上传日志 ==="
        echo "============================================="
        echo "1. 安装/更新服务器"
        echo "2. 切换服务器版本（稳定版/实验版）"
        echo "3. 修改服务器配置文件"
        echo "4. 启动服务器"
        echo "5. 关闭服务器"
        echo "6. 查看服务器状态和查看日志"
        echo "7. 重装游戏服务器"
        echo "8. 存档管理（备份/还原/删除）"
        echo "9. 管理员管理（权限/白名单/黑名单）"
        echo "10. Mod管理（添加/删除/还原官方Mod）"
        echo "11. 闲时自动重启（内存>4GB+无玩家时重启）"
        echo "12. 宕机自动恢复（崩溃后自动重启）"
        echo "13. 启动参数预设管理"
        echo "14. 安装 Teamspeak 3 语音服务器"
        echo "15. Teamspeak 3 服务器管理"
        echo "16. FRP 内网穿透管理"
        echo "17. 检查系统依赖"
        echo "18. 更换 APT 软件源"
        echo "19. 设置系统虚拟内存"
        echo "20. 磁盘管理（检测/挂载/迁移）"
        echo "21. ARM64兼容环境（Box64/Docker/下载工具）"
        echo "0. 退出脚本"
        echo "============================================="
        read -p "请输入操作编号: " choice

        case $choice in
            1) ensure_server_stopped_for_operation "安装/更新服务器" && install_7dtd_server; read -p "按回车键继续..." ;;
            2) ensure_server_stopped_for_operation "切换服务器版本" && switch_server_version; read -p "按回车键继续..." ;;
            3) ensure_server_stopped_for_operation "修改服务器配置文件" && modify_server_config; read -p "按回车键继续..." ;;
            4) start_server; read -p "按回车键继续..." ;;
            5) stop_server; read -p "按回车键继续..." ;;
            6) show_server_status_and_logs_menu ;;
            7) ensure_server_stopped_for_operation "重装游戏服务器" && reinstall_server; read -p "按回车键继续..." ;;
            8) manage_saves_menu ;;
            9) ensure_server_stopped_for_operation "管理员管理（权限/白名单/黑名单）" && manage_admins_menu ;;
            10) ensure_server_stopped_for_operation "Mod管理（添加/删除/还原官方Mod）" && manage_mods_menu ;;
            11) setup_idle_restart; read -p "按回车键继续..." ;;
            12) setup_crash_recovery; read -p "按回车键继续..." ;;
            13) setup_startup_preset; read -p "按回车键继续..." ;;
            14) install_teamspeak3_server; read -p "按回车键继续..." ;;
            15) manage_teamspeak3_server ;;
            16) manage_frp_menu ;;
            17) check_system_dependencies; read -p "按回车键继续..." ;;
            18) change_apt_source; read -p "按回车键继续..." ;;
            19) set_swap_memory; read -p "按回车键继续..." ;;
            20) manage_disk_menu ;;
            21) arm64_compat_menu ;;
            0) echo "感谢使用，再见！"; exit 0 ;;
            *) red_echo "无效选项，请重新输入！" ;;
        esac
    done
}

# --- 主流程 ---
init_logging

# 尝试读取历史安装配置
echo "====== 检测历史安装配置 ======"
if read_install_config; then
    green_echo "✓ 已检测到历史安装配置，使用配置的安装目录"
else
    yellow_echo "未检测到历史安装配置，使用默认安装目录"
fi

debug_info
print_arch_notice

# 检查是否为首次运行
if [ ! -f "$config_file" ]; then
    echo "=== 首次运行，执行初始化配置 ==="
    yellow_echo "首次运行脚本，将执行必要的系统配置..."

    if ask_yes_no "是否更换为国内软件源以提升下载速度？" "Y"; then
        change_apt_source
    fi

    if ask_yes_no "是否设置系统虚拟内存？（推荐内存小于8GB的服务器设置）" "Y"; then
        set_swap_memory
    fi

    install_dependencies

    echo "=== 安装 SteamCMD ==="
    install_steamcmd

    echo ""
    echo "====== 首次安装版本选择 ======"
    echo "1) 稳定版 (public，推荐)"
    echo "2) 实验版 (latest_experimental)"
    echo "3) 自定义版本号"
    read -p "请选择安装版本 (1-3, 默认1): " first_version_choice
    first_version_choice=${first_version_choice:-1}

    first_install_version="public"
    case "$first_version_choice" in
        1)
            first_install_version="public"
            ;;
        2)
            first_install_version="latest_experimental"
            ;;
        3)
            read -p "请输入版本号 (例如: v2.5 / alpha21.2): " custom_version
            if [ -n "$custom_version" ]; then
                first_install_version="$custom_version"
            else
                yellow_echo "未输入版本号，已回退到 public"
                first_install_version="public"
            fi
            ;;
        *)
            yellow_echo "无效选择，已回退到 public"
            first_install_version="public"
            ;;
    esac

    save_current_version "$first_install_version"
    green_echo "首次安装版本: $first_install_version"

    echo "=== 安装七日杀服务器 ==="
    install_7dtd_server

    echo "=== 生成默认配置文件 ==="
    generate_default_config
    
    # 首次安装后提示配置
    echo ""
    echo "====== 服务器首次配置 ======"
    echo ""
    echo "服务器基本配置"
    echo ""
    echo "请选择配置方式："
    echo "1) 交互式配置（基础+高级，推荐）"
    echo "2) 使用默认配置模板（快速开始，之后可修改）"
    echo ""
    read -p "请选择 (1-2, 默认1): " config_choice
    config_choice=${config_choice:-1}
    
    case $config_choice in
        1)
            interactive_config
            green_echo "✓ 基本配置已完成"
            ;;
        2)
            # 明确按默认模板再次写入，确保首次安装后配置落盘一致
            generate_default_config
            green_echo "✓ 已使用默认配置"
            yellow_echo "提示：您可以在主菜单使用选项1进行交互式修改，或选项3手动修改配置文件"
            ;;
        *)
            red_echo "无效选择，使用默认配置"
            yellow_echo "提示：您可以在主菜单使用选项1进行交互式修改，或选项3手动修改配置文件"
            ;;
    esac

    save_install_config "$home_dir"

    green_echo "✓ 服务器初始化完成！"
    echo ""
    echo "您现在可以："
    echo "  1. 使用选项3修改服务器配置"
    echo "  2. 使用选项4启动服务器"
    echo ""
fi

# 进入主菜单
main_menu
