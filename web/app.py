"""Entry point for the RustSL NiceGUI app."""

import asyncio
import sys
from pathlib import Path

# Fix for Windows asyncio event loop policy to support subprocesses
if sys.platform.startswith("win"):
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

from nicegui import app, ui

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.append(str(ROOT))

from ui_components import RustSLWebGUI  # noqa: E402


@ui.page('/')
def main_page():
    ui.dark_mode(True)
    RustSLWebGUI()


if __name__ in {"__main__", "__mp_main__"}:
    app.add_static_files('/icons', str(ROOT / 'icons'))
    app.add_static_files('/static', str(ROOT / 'static'))
    ui.run(title='RustSL by echQoQ', host='127.0.0.1', port=8050, reload=False, favicon=str(ROOT / 'icons' / 'icon.ico'))


