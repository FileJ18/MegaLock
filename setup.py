from cx_Freeze import setup, Executable

setup(
    name="Megalock",
    version="1.0.0",
    description="My Python App",
    executables=[Executable("lock.py")],
)
