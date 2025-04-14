import pefile
import sys

GRAPHICS_DLLS = {
    "d3dim.dll": "DirectX 3–6 (Immediate Mode)",
    "ddraw.dll": "DirectDraw (DX 1–7)",
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

def detect_graphics_api(exe_path):
    try:
        pe = pefile.PE(exe_path)
        imports = []
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode('utf-8').lower()
                imports.append(dll)

        used_apis = [GRAPHICS_DLLS[dll] for dll in imports if dll in GRAPHICS_DLLS]
        if used_apis:
            print(f"Detected graphics APIs in {exe_path}:")
            for api in set(used_apis):
                print(f"  - {api}")
        else:
            print("No known graphics API detected.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python detect_graphics_api.py <path_to_exe>")
    else:
        detect_graphics_api(sys.argv[1])
