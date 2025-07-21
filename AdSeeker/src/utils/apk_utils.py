import subprocess
import os

class APKUtils:
    @staticmethod
    def decompile_apk(apk_path, output_dir):
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        subprocess.run(
            ["apktool", "d", apk_path, "-o", output_dir, "-f"],
            check=True,
            capture_output=True
        )
        return output_dir

    @staticmethod
    def get_manifest_path(decompile_dir):
        return os.path.join(decompile_dir, "AndroidManifest.xml")



\\\


