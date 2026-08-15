import angr
import sys

def main():
    exe_path = sys.argv[1]
    proj = angr.Project(exe_path, load_options={'auto_load_libs': False})
    print(f"Sections for {exe_path}:")
    for section in proj.loader.main_object.sections:
        print(f"  Name: {section.name}, Vaddr: {hex(section.vaddr)}, Memsize: {section.memsize}, Executable: {section.is_executable}")

if __name__ == "__main__":
    main()
