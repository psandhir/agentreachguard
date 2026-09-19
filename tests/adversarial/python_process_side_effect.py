import subprocess

subprocess.run(["touch", "SHOULD_NOT_EXIST"], check=True)
