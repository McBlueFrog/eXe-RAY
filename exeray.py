import pefile
import dearpygui.dearpygui as dpg
import typing

# eXeRAY - A simple graphics API analyzer for Windows executables
GRAPHICS_DLLS = {
    "d3dim.dll": "DirectX 3-6 (Immediate Mode)",
    "ddraw.dll": "DirectDraw (DX 1-7)",
    "glide2x.dll": "3dfx Glide 2.x",
    "glide3x.dll": "3dfx Glide 3.x",
    "d3d8.dll": "DirectX 8",
    "d3d9.dll": "DirectX 9",
    "d3d10.dll": "DirectX 10",
    "d3d11.dll": "DirectX 11",
    "d3d12.dll": "DirectX 12",
    "opengl32.dll": "OpenGL",
    "vulkan-1.dll": "Vulkan",
}

class ExecutableAnalyzer:
    def __init__(self):
        self.exe_path = None
        self.pe = None
        self.imported_dlls = []
        self.analysis_result = "" # Store result here

    def set_exe_path(self, exe_path: str):
        """Set the path to the executable file to be analyzed."""
        self.exe_path = exe_path
        self.pe = None
        self.imported_dlls = []
        self.analysis_result = ""
        print(f"Analyzer path set to: {self.exe_path}")

    def load_pe(self) -> bool:
        """Load the PE file and parse its import directory."""
        if not self.exe_path:
            self.analysis_result = "Error: No executable path set."
            print(self.analysis_result)
            return False
        try:
            print(f"Loading PE file: {self.exe_path}")
            self.pe = pefile.PE(self.exe_path, fast_load=True) # fast_load is often sufficient
            self.pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']]) # Only parse imports
            return True
        except FileNotFoundError:
            self.analysis_result = f"Error: File not found - {self.exe_path}"
            print(self.analysis_result)
            self.pe = None
            return False
        except pefile.PEFormatError as e:
            self.analysis_result = f"Error: Invalid PE file format - {e}"
            print(self.analysis_result)
            self.pe = None
            return False
        except Exception as e:
            self.analysis_result = f"Error loading PE file: {e}"
            print(self.analysis_result)
            self.pe = None
            return False

    def get_imported_dlls(self) -> typing.List[str]:
        """Extract the imported DLLs from the PE file."""
        # Ensure previous results are cleared
        self.imported_dlls = []
        if not self.pe:
            print("Info: PE object not loaded, cannot get imports.")
            return []

        dll_list = []
        try:
            print("Extracting imported DLLs...")
            # The check for DIRECTORY_ENTRY_IMPORT is implicitly handled by parse_data_directories
            # or will raise AttributeError if parsing failed/skipped and attribute accessed directly
            if not hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
                 print("Info: No import directory found in the PE file.")
                 return []

            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                if entry.dll:
                    try:
                        dll_name = entry.dll.decode('utf-8').lower()
                        dll_list.append(dll_name)
                    except UnicodeDecodeError:
                        print(f"Warning: Could not decode DLL name: {entry.dll}")
        except AttributeError:
            print("Info: No import directory structure found (AttributeError).")
        except Exception as e:
            print(f"Warning: Error processing imports: {e}")

        self.imported_dlls = dll_list
        print(f"Found DLLs: {self.imported_dlls}")
        return self.imported_dlls

    def detect_graphics_api(self) -> str:
        """Detect the graphics API based on imported DLLs."""
        if not self.imported_dlls:
            # Handle cases where imports couldn't be read or PE wasn't loaded
             if not self.analysis_result:
                 self.analysis_result = "Could not determine APIs (no DLLs found or loaded)."
             return self.analysis_result

        result_lines = []
        try:
            used_apis = {GRAPHICS_DLLS[dll] for dll in self.imported_dlls if dll in GRAPHICS_DLLS}
            if used_apis:
                result_lines.append("Detected Graphics APIs:")
                for api in sorted(list(used_apis)):
                    result_lines.append(f" - {api}")
            else:
                result_lines.append("No known graphics APIs found among imported DLLs.")

            self.analysis_result = "\n".join(result_lines)

        except Exception as e:
            self.analysis_result = f"Error during API detection: {e}"

        print(f"Analysis result:\n{self.analysis_result}")
        return self.analysis_result

# --- GUI Code ---

dpg.create_context()

analyzer = ExecutableAnalyzer()


def file_dialog_callback(sender, app_data):
    """Called when a file is selected in the file dialog."""
    selected_path = app_data['file_path_name']
    print(f"File selected: {selected_path}")
    # Update the input text widget
    dpg.set_value("exe_input", selected_path)
    # Set the path in our analyzer instance
    analyzer.set_exe_path(selected_path)
    # Clear previous results and hide the result text area
    dpg.set_value("result_text", "")
    dpg.configure_item("result_text", show=False)

def cancel_callback(sender, app_data):
    """Called when the file dialog is cancelled."""
    print("File dialog cancelled")

def analyze_button_callback():
    """Called when the 'Analyze' button is clicked."""
    print("Analyze button clicked.")
    # Optional: Get path from input field again, in case it was manually changed
    current_path = dpg.get_value("exe_input")
    if not current_path:
         dpg.set_value("result_text", "Error: Please select an executable file first.")
         dpg.configure_item("result_text", show=True)
         return
    if current_path != analyzer.exe_path: # Update analyzer if path changed manually
        analyzer.set_exe_path(current_path)

    if analyzer.load_pe():
        analyzer.get_imported_dlls()
        result_string = analyzer.detect_graphics_api()
    else:
        # Loading failed, result string should be set within load_pe
        result_string = analyzer.analysis_result

    dpg.set_value("result_text", result_string)
    dpg.configure_item("result_text", show=True)

# --- UI Definition ---

with dpg.viewport_menu_bar():
    with dpg.menu(label="Menu"):
        dpg.add_menu_item(label="Open Analyzer", callback=lambda: dpg.configure_item("gfx_analizer_window", show=True))
        dpg.add_menu_item(label="Exit", callback=lambda: dpg.stop_dearpygui())

# Setup the file dialog
with dpg.file_dialog(
    directory_selector=False,
    show=False,
    width=600,
    height=400,
    callback=file_dialog_callback,
    cancel_callback=cancel_callback,
    file_count=1,
    tag="file_dialog_id",
    modal=True
):
    dpg.add_file_extension("", color=(150, 255, 150, 255))
    dpg.add_file_extension(".exe", color=(128, 128, 255, 255), custom_text="[EXE]")

# Setup the main window
with dpg.window(label="Graphics API Analyzer", width=400, height=200, tag="gfx_analizer_window", show=False):
    dpg.add_text("Select a Windows '.exe' file:")
    dpg.add_input_text(tag="exe_input", label="File Path", width=400)
    dpg.add_button(label="Browse...", callback=lambda: dpg.show_item("file_dialog_id"))
    dpg.add_button(label="Analyze", callback=analyze_button_callback)
    dpg.add_separator()
    dpg.add_text("Analysis results will appear here.", tag="result_text", wrap=480)
    dpg.configure_item("result_text", show=False)

# DPG Setup & Run
dpg.create_viewport(title='eXeRAY', width=800, height=600)
dpg.setup_dearpygui()
dpg.show_viewport()
dpg.start_dearpygui()
dpg.destroy_context()