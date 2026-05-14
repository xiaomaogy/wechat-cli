"""macOS 密钥提取 — 通过 C 二进制扫描微信进程内存"""

import os
import platform
import plistlib
import subprocess
import sys
import tempfile

from .common import collect_db_files, cross_verify_keys, save_results, scan_memory_for_keys


def _find_binary():
    """查找对应架构的 C 二进制。"""
    machine = platform.machine()
    if machine == "arm64":
        name = "find_all_keys_macos.arm64"
    elif machine == "x86_64":
        name = "find_all_keys_macos.x86_64"
    else:
        raise RuntimeError(f"不支持的 macOS 架构: {machine}")

    # PyInstaller 运行时：从临时解压目录查找
    if getattr(sys, 'frozen', False):
        base = sys._MEIPASS
    else:
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    bin_path = os.path.join(base, "wechat_cli", "bin", name)
    if os.path.isfile(bin_path):
        return bin_path

    # fallback: 直接在 bin/ 下
    bin_path = os.path.join(base, "bin", name)
    if os.path.isfile(bin_path):
        return bin_path

    raise RuntimeError(
        f"找不到密钥提取二进制: {bin_path}\n"
        "请确认安装包完整"
    )


def _get_original_entitlements(app_path):
    """提取 app 当前的签名 entitlements，返回 dict 或 None。"""
    try:
        result = subprocess.run(
            ["codesign", "-d", "--entitlements", ":-", app_path],
            capture_output=True,
            timeout=15,
        )
        if result.returncode == 0 and result.stdout:
            return plistlib.loads(result.stdout)
    except Exception:
        pass
    return None


def _build_entitlements_xml(app_path):
    """构建 entitlements：保留原有权限 + 添加 get-task-allow。"""
    entitlements = _get_original_entitlements(app_path)
    if entitlements is None:
        entitlements = {}

    entitlements["com.apple.security.get-task-allow"] = True

    return plistlib.dumps(entitlements, fmt=plistlib.FMT_XML)


def _resign_wechat():
    """Re-sign WeChat: 保留原有 entitlements，仅添加 get-task-allow。"""
    wechat_paths = [
        "/Applications/WeChat.app",
        os.path.expanduser("~/Applications/WeChat.app"),
    ]
    wechat_app = None
    for p in wechat_paths:
        if os.path.isdir(p):
            wechat_app = p
            break

    if wechat_app is None:
        return False, "未找到 WeChat.app（已搜索 /Applications 和 ~/Applications）"

    print(f"\n[*] 检测到 task_for_pid 权限不足，正在对微信重新签名...")
    print(f"    目标: {wechat_app}")

    # 提取并合并 entitlements
    try:
        ent_data = _build_entitlements_xml(wechat_app)
    except Exception as e:
        return False, f"提取微信原始权限失败: {e}"

    ent_fd, ent_path = tempfile.mkstemp(suffix=".plist")
    try:
        with os.fdopen(ent_fd, "wb") as f:
            f.write(ent_data)

        result = subprocess.run(
            ["codesign", "--force", "--sign", "-", "--entitlements", ent_path, wechat_app],
            capture_output=True,
            text=True,
            timeout=60,
        )
    finally:
        os.unlink(ent_path)

    if result.returncode != 0:
        return False, f"codesign 失败: {result.stderr.strip()}"

    print("[+] 签名完成（已保留微信原有权限，仅添加调试访问权限）。")
    print("[+] 请重新启动微信后再执行 init。")
    print("[!] 注意：如果微信自动更新，可能需要重新签名。")
    return True, None


def _list_encrypted_dbs(db_dir):
    """枚举 db_dir 下所有已加密的 .db 文件（相对路径），用于校验密钥完整性。

    与 C 二进制写入 all_keys.json 时使用的 key 格式一致：
    "<top_level>/<filename.db>"（forward slashes），仅取相对 db_dir 的路径。
    """
    encrypted = set()
    for root, _dirs, files in os.walk(db_dir):
        for fn in files:
            if not fn.endswith(".db"):
                continue
            full = os.path.join(root, fn)
            try:
                with open(full, "rb") as f:
                    header = f.read(16)
            except OSError:
                continue
            if len(header) < 16 or header[:15] == b"SQLite format 3":
                # 未加密或读不到完整 header，跳过
                continue
            rel = os.path.relpath(full, db_dir).replace(os.sep, "/")
            encrypted.add(rel)
    return encrypted


def _run_c_scanner(binary, work_dir):
    """运行一次 C 扫描二进制，返回 subprocess.CompletedProcess。"""
    try:
        return subprocess.run(
            [binary],
            cwd=work_dir,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("密钥提取超时（120s）")
    except PermissionError:
        raise RuntimeError(
            f"无法执行 {binary}\n"
            "请确保文件有执行权限: chmod +x " + binary
        )


def extract_keys(db_dir, output_path, pid=None):
    """通过 C 二进制提取 macOS 微信数据库密钥。

    C 二进制需要在微信数据目录的父目录下运行，
    因为它会自动检测 db_storage 子目录。
    输出 all_keys.json 到当前工作目录。

    内存扫描在 macOS 上是非确定性的：某次扫描可能错过部分
    数据库的密钥（VM 区域可读性、chunk 边界等）。因此这里
    会重试若干次并合并结果，直到所有已加密的 .db 文件都有
    对应密钥，或达到重试上限。

    Args:
        db_dir: 微信 db_storage 目录
        output_path: all_keys.json 输出路径
        pid: 未使用（C 二进制自动检测进程）

    Returns:
        dict: db 相对路径 -> enc_key 映射
    """
    import json

    binary = _find_binary()

    # C 二进制的工作目录需要是 db_storage 的父目录
    work_dir = os.path.dirname(db_dir)
    if not os.path.isdir(work_dir):
        raise RuntimeError(f"微信数据目录不存在: {work_dir}")

    expected_dbs = _list_encrypted_dbs(db_dir)
    if not expected_dbs:
        raise RuntimeError(
            f"在 {db_dir} 中未找到任何已加密的 .db 文件。\n"
            "请确认微信至少已登录过一次。"
        )

    print(f"[+] 使用 C 二进制提取密钥: {binary}")
    print(f"[+] 工作目录: {work_dir}")
    print(f"[+] 已加密数据库数: {len(expected_dbs)}")

    c_output = os.path.join(work_dir, "all_keys.json")
    accumulated = {}
    max_attempts = 3

    for attempt in range(1, max_attempts + 1):
        if attempt > 1:
            missing = sorted(expected_dbs - set(accumulated))
            print(f"\n[!] 第 {attempt - 1} 次扫描后仍缺少 {len(missing)} 个密钥，重试…")
            print(f"    缺失: {missing}")

        result = _run_c_scanner(binary, work_dir)

        if result.stdout:
            print(result.stdout)
        if result.stderr:
            print(result.stderr, file=sys.stderr)

        # 检测 task_for_pid 失败 → 尝试 re-sign（第一次失败就处理，无需重试）
        combined_output = (result.stdout or "") + (result.stderr or "")
        if "task_for_pid" in combined_output:
            print("\n[!] task_for_pid 失败：macOS 安全策略阻止了进程内存访问。")
            print("[!] 需要对微信重新签名以允许调试访问（不影响微信正常功能）。")

            ok, err = _resign_wechat()
            if ok:
                raise RuntimeError(
                    "已对微信重新签名（保留原有权限）。请执行以下步骤后重试：\n"
                    "  1. 退出微信（完全退出，不是最小化）\n"
                    "  2. 重新打开微信并登录\n"
                    "  3. 再次执行: sudo wechat-cli init"
                )
            raise RuntimeError(
                f"自动签名失败: {err}\n"
                "请手动执行以下命令后重试：\n"
                "  # 1. 提取微信原有权限\n"
                "  codesign -d --entitlements wechat_ent.plist /Applications/WeChat.app\n"
                "  # 2. 用 PlistBuddy 添加 get-task-allow\n"
                '  /usr/libexec/PlistBuddy -c "Add :com.apple.security.get-task-allow bool true" wechat_ent.plist\n'
                "  # 3. 重新签名\n"
                "  codesign --force --sign - --entitlements wechat_ent.plist /Applications/WeChat.app\n"
                "  # 4. 清理\n"
                "  rm wechat_ent.plist\n"
                "然后重启微信，再执行: sudo wechat-cli init"
            )

        if not os.path.exists(c_output):
            raise RuntimeError(
                "C 二进制未能生成密钥文件。\n"
                f"stdout: {result.stdout}\nstderr: {result.stderr}"
            )

        with open(c_output, encoding="utf-8") as f:
            this_run = json.load(f)

        # 合并本次结果（只接受已加密 db 列表中的 key，避免误纳入陌生条目）
        for rel, info in this_run.items():
            if rel in expected_dbs and rel not in accumulated:
                accumulated[rel] = info

        if expected_dbs.issubset(accumulated):
            break

    # 写入合并后的密钥（即使有缺失也写入，以便用户可见状态）
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(accumulated, f, indent=2, ensure_ascii=False)

    # 清理 C 二进制的临时输出
    try:
        if os.path.abspath(c_output) != os.path.abspath(output_path):
            os.remove(c_output)
    except OSError:
        pass

    missing = sorted(expected_dbs - set(accumulated))
    if missing:
        print(
            f"\n[!] 已保存 {len(accumulated)}/{len(expected_dbs)} 个密钥，"
            f"但仍有 {len(missing)} 个数据库未提取到密钥:"
        )
        for m in missing:
            print(f"    - {m}")
        print(
            "[!] 提示：在微信中打开对应聊天/会话使其加载到内存，然后重新运行 "
            "`sudo wechat-cli init --force`。"
        )
    else:
        print(f"\n[+] 提取到全部 {len(accumulated)} 个密钥，保存到: {output_path}")

    return accumulated
