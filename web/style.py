from nicegui import ui

# ---------- Global Styles ----------
def apply_global_styles():
    """Apply global CSS styles for the entire application."""
    ui.add_css('''
        /* One Dark Pro theme colors */
        .dark-theme {
            --q-primary: #61dafb;
            --q-secondary: #abb2bf;
            --q-accent: #c678dd;
            --q-dark: #282c34;
            --q-positive: #98c379;
            --q-negative: #e06c75;
            --q-info: #61dafb;
            --q-warning: #d19a66;
        }

        /* One Dark Pro scrollbar */
        ::-webkit-scrollbar {
            width: 10px;
            height: 10px;
        }

        ::-webkit-scrollbar-track {
            background: #21252b;
            border-radius: 6px;
        }

        ::-webkit-scrollbar-thumb {
            background: #3e4451;
            border-radius: 6px;
            border: 1px solid #21252b;
        }

        ::-webkit-scrollbar-thumb:hover {
            background: #5c6370;
        }

        /* Smooth transitions - disabled */
        /*
        * {
            transition: all 0.2s ease-in-out;
        }
        */

        /* One Dark Pro focus */
        .q-field--focused .q-field__control {
            box-shadow: 0 0 0 2px rgba(97, 218, 251, 0.5);
            border-color: #61dafb !important;
        }

        /* One Dark Pro border effects */
        .border-glow {
            position: relative;
        }
        .border-glow::before {
            content: '';
            position: absolute;
            top: -1px;
            left: -1px;
            right: -1px;
            bottom: -1px;
            background: rgba(97, 218, 251, 0.2);
            border-radius: inherit;
            z-index: -1;
        }
    ''')

# ---------- Component Styles ----------
def get_group_box_styles():
    """Get styles for group boxes."""
    return {
        'container': 'w-full border border-slate-600/50 rounded-xl p-0 mb-1 bg-slate-900/60 shadow-xl backdrop-blur-md texture-overlay border-glow card-hover',
        'header': 'w-full bg-slate-800 px-3 py-2 border-b border-slate-600/50 items-center h-10',
        'header_text': 'text-sm font-bold text-slate-100 tracking-wide text-shadow',
        'content': 'w-full p-3 gap-2'
    }

def get_button_styles():
    """Get styles for buttons."""
    return {
        'primary': 'bg-cyan-600 hover:bg-cyan-700 text-white font-semibold py-2 px-4 rounded-xl shadow-lg border border-cyan-500/30',
        'secondary': 'bg-slate-600 hover:bg-slate-700 text-white font-semibold py-2 px-4 rounded-xl shadow-lg border border-slate-500/30',
        'icon': 'bg-gray-200 hover:bg-gray-300 rounded-xl shadow-lg border border-gray-300/50'
    }

def get_input_styles():
    """Get styles for input fields."""
    return {
        'base': 'border border-gray-600/50 rounded-xl bg-gray-800/80 text-gray-100 placeholder-gray-400 focus:border-cyan-400 focus:ring-2 focus:ring-cyan-400/30 shadow-lg backdrop-blur-sm',
        'textarea': 'font-mono text-sm bg-gray-900/90 text-green-400 border border-gray-700/50 rounded-xl p-3 resize-none focus:border-green-400 focus:ring-2 focus:ring-green-400/30 shadow-lg backdrop-blur-sm'
    }

def get_progress_styles():
    """Get styles for progress bars."""
    return {
        'base': 'w-full h-4 rounded-full shadow-inner border border-slate-600/50 overflow-hidden bg-slate-800/50 backdrop-blur-sm',
        'track': 'h-full bg-cyan-500 rounded-full shadow-lg'
    }

# ---------- Advanced Components ----------
def create_enhanced_group_box(title: str, icon_name: str = None, header_controls=None, classes: str = ""):
    """Create an enhanced group box with advanced styling."""
    styles = get_group_box_styles()

    with ui.column().classes(f"{styles['container']} {classes}"):
        with ui.row().classes(styles['header']):
            if icon_name:
                ui.image(f"icons/{icon_name}.ico").classes("w-5 h-5 mr-1 filter brightness-110")
            ui.label(title).classes(styles['header_text'])
            if header_controls:
                ui.space()
                header_controls()

        return ui.column().classes(styles['content'])

def create_enhanced_button(text: str = "", icon: str = "", on_click=None, style: str = 'primary'):
    """Create an enhanced button with advanced styling."""
    styles = get_button_styles()

    button_classes = styles.get(style, styles['primary'])
    if icon and not text:
        button_classes += ' w-12 h-12 flex items-center justify-center p-0'

    return ui.button(text, icon=icon, on_click=on_click).classes(button_classes)

def create_enhanced_textarea(**kwargs):
    """Create an enhanced textarea with advanced styling."""
    styles = get_input_styles()
    classes = kwargs.pop('classes', '')
    textarea = ui.textarea(**kwargs)
    textarea.classes(f"{styles['textarea']} {classes}")
    return textarea

def create_enhanced_progress(**kwargs):
    """Create an enhanced progress bar with advanced styling."""
    styles = get_progress_styles()
    classes = kwargs.pop('classes', '')
    progress = ui.linear_progress(**kwargs)
    progress.classes(f"{styles['base']} {classes}")
    return progress

# ---------- Theme Management ----------
def set_dark_theme():
    """Apply dark theme to the application."""
    ui.dark_mode(True)
    apply_global_styles()

def set_light_theme():
    """Apply light theme to the application."""
    ui.dark_mode(False)
    # Light theme styles would go here if needed

# ---------- Utility Functions ----------
def add_log_scroll_css():
    """Add CSS for log area scrolling."""
    css = '''
        .log-area .q-field__control {
            height: 100% !important;
        }
        .log-area .q-field__native {
            height: 100% !important;
            resize: none;
        }
        .log-area textarea {
            scrollbar-width: thin;
            scrollbar-color: #4a5568 #2d3748;
        }
    '''
    ui.add_css(css)

def create_gradient_background():
    """Create a full-page background with custom image."""
    css = '''
        body {
            background: url('/static/bg.jpg') no-repeat center center fixed;
            background-size: cover;
            margin: 0;
            padding: 0;
            min-height: 100vh;
        }

        .main-container {
            position: relative;
            min-height: 100vh;
        }

        .main-container::before {
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(40, 44, 52, 0.85);
            z-index: -1;
            pointer-events: none;
        }
    '''
    ui.add_css(css)

# ---------- Animation Helpers ----------
def add_hover_animations():
    """Add sophisticated hover animations to interactive elements."""
    ui.add_css('''
        .hover-lift:hover {
            transform: translateY(-1px);
        }

        .hover-glow:hover {
            box-shadow: 0 0 4px rgba(97, 218, 251, 0.2);
        }

        /* One Dark Pro card hover effects */
        .card-hover:hover {
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
        }
    ''')

# ---------- Initialize Styles ----------
def init_styles():
    """Initialize all styles for the application."""
    set_dark_theme()
    create_gradient_background()
    add_hover_animations()
    add_log_scroll_css()