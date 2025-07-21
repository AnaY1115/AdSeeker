'''
Time: 2025.7.12
We will upload the comments for the code as soon as possible and update the document content so that you can better understand the code.
'''

import json
from src.emulator.ui_explorer import UIExplorer
from src.emulator.ad_detector import AdDetector
from src.analysis.sdk_analyzer import SDKAnalyzer
from src.analysis.permission_analyzer import PermissionAnalyzer
from src.analysis.link_analyzer import LinkAnalyzer
from src.analysis.image_analyzer import ImageAnalyzer
from src.report.report_generator import ReportGenerator

def main(apk_path, package_name):
    # 1. Initialize module
    emulator_config = "./config/emulator_config.json"
    llm_config = "./config/llm_config.json"
    ui_explorer = UIExplorer(emulator_config)
    ad_detector = AdDetector(emulator_config)
    sdk_analyzer = SDKAnalyzer()
    perm_analyzer = PermissionAnalyzer(
        adb_path=json.load(open(emulator_config))["adb_path"]
    )
    link_analyzer = LinkAnalyzer(emulator_config)
    image_analyzer = ImageAnalyzer(llm_config)
    report_generator = ReportGenerator(llm_config)

    # 2. UI automated exploration
    ui_elements = ui_explorer.parse_view_tree(apk_path)
    utg = ui_explorer.build_utg(ui_elements)
    ui_explorer.save_task_knowledge(utg)
    script = ui_explorer.generate_operation_script("...") # Please modify this to the command you want to execute

    # 3. targeted advertising page
    frida_session = ad_detector.hook_http_library(package_name)
    # Executing UI operations triggers ad loading.
    ad_detector.ad_pages  # Ad page recorded through Frida callback

    # 4. multi-dimensional detection
    sdk_result = sdk_analyzer.analyze_sdk(apk_path)
    static_perms = perm_analyzer.get_static_permissions(package_name)
    dynamic_perms = perm_analyzer.get_dynamic_permissions(package_name)
    perm_result = perm_analyzer.analyze_permission_legitimacy(static_perms, dynamic_perms)
    links = link_analyzer.capture_https_traffic(package_name)
    link_result = link_analyzer.check_link_safety(links)
    image_result = image_analyzer.analyze_ad_image(ad_detector.ad_pages[0]["screenshot"])

    # 5. Generate a report
    integrated_data = report_generator.integrate_results(
        sdk_result, perm_result, link_result, image_result
    )
    final_report = report_generator.generate_report(integrated_data)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--apk", required=True, help="APK file path")
    parser.add_argument("-p", "--package", required=True, help="application package name")
    args = parser.parse_args()
    main(args.apk, args.package)