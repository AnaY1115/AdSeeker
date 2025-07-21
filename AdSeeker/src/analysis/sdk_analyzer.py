'''
Time: 2025.7.15
We will upload the comments for the code as soon as possible and update the document content so that you can better understand the code.
'''

import xml.etree.ElementTree as ET
import json
import os
import datetime
from src.utils.apk_utils import APKUtils
from src.utils.logger import Logger


class SDKAnalyzer:
    def __init__(self):
        self.logger = Logger.get_logger("SDKAnalyzer")
        self.certified_sdks = json.load(open("./config/certified_sdks.json"))  # List of authentication SDKs
        self.report_dir = "E:\\Ad_REPORT_Set\\sdk_reports"  # report save directory
        self._init_report_dir()  # Initialize report directory

    def _init_report_dir(self):
        """Initialize the report save directory and ensure that the directory exists."""
        if not os.path.exists(self.report_dir):
            os.makedirs(self.report_dir)
            self.logger.info(f"Create a report directory: {self.report_dir}")

    def analyze_sdk(self, apk_path):
        """Check if the SDK used for advertising has been certified, and generate and save a report."""
        # Decompile an APK and extract the AndroidManifest.xml
        decompile_dir = APKUtils.decompile_apk(apk_path, "./temp_decompile")
        manifest_path = APKUtils.get_manifest_path(decompile_dir)

        # Parse XML files
        tree = ET.parse(manifest_path)
        root = tree.getroot()

        # Extract advertising-related tags
        ad_tags = {
            "activities": [elem.attrib for elem in root.findall(".//activity")],
            "services": [elem.attrib for elem in root.findall(".//service")],
            "meta_data": [elem.attrib for elem in root.findall(".//meta-data")]
        }

        # convert into natural language description
        description = self._convert_to_nl(ad_tags)

        # Analyze package name features
        sdk_packages = self._extract_package_names(ad_tags)

        certification_result = self._check_certification(sdk_packages)

        # Generate complete report
        report = self._generate_report(
            apk_path=apk_path,
            ad_tags=ad_tags,
            natural_language=description,
            certification_result=certification_result
        )

        self._save_report(report, apk_path)
        return certification_result

    def _convert_to_nl(self, tags):
        """Convert XML tags into natural language descriptions."""
        nl = []
        # Event tag description
        for act in tags["activities"]:
            act_name = act.get("android:name", "none")
            nl.append(f"active component：{act_name}，responsible for user interaction（attributes：{json.dumps(act)}）")
        # 服务标签描述
        for svc in tags["services"]:
            svc_name = svc.get("android:name", "none")
            nl.append(f"service component：{svc_name}，Handling background tasks（attributes：{json.dumps(svc)}）")
        # 元数据标签描述
        for meta in tags["meta_data"]:
            meta_name = meta.get("android:name", "unknown metadata")
            meta_value = meta.get("android:value", "none")
            nl.append(f"metadata tags：{meta_name}，store key configuration information（值：{meta_value}，attributes：{json.dumps(meta)}）")
        return "\n".join(nl)

    def _extract_package_names(self, tags):
        """Extract the package name from the label"""
        packages = []
        for act in tags["activities"]:
            if "android:name" in act:
                full_name = act["android:name"]
                # Extract full package name（如com.example.ad -> com.example）
                pkg_parts = full_name.split(".")
                if len(pkg_parts) >= 2:
                    pkg = ".".join(pkg_parts[:-1])  # Extract the package part before the class name
                else:
                    pkg = full_name  # Handling short package names
                if "ad" in pkg.lower() or "advert" in pkg.lower():
                    packages.append(pkg)
        # Extract from service tags
        for svc in tags["services"]:
            if "android:name" in svc:
                full_name = svc["android:name"]
                pkg_parts = full_name.split(".")
                if len(pkg_parts) >= 2:
                    pkg = ".".join(pkg_parts[:-1])
                else:
                    pkg = full_name
                if "ad" in pkg.lower() or "advert" in pkg.lower():
                    packages.append(pkg)
        return list(set(packages))

    def _check_certification(self, sdk_packages):
        """Check if the SDK is in the authentication list."""
        result = {
            "detected_sdks": sdk_packages,
            "certified": [pkg for pkg in sdk_packages if pkg in self.certified_sdks],
            "uncertified": [pkg for pkg in sdk_packages if pkg not in self.certified_sdks]
        }
        self.logger.info(f"SDK detection complete：{len(result['detected_sdks'])} SDK，here {len(result['uncertified'])}not authenticated")
        return result

    def _generate_report(self, apk_path, ad_tags, natural_language, certification_result):
        """Generate a complete JSON report"""
        apk_name = os.path.basename(apk_path)
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return {
            "report_info": {
                "apk_name": apk_name,
                "analysis_time": timestamp,
                "report_version": "1.0"
            },
            "raw_tags": ad_tags,
            "natural_language_description": natural_language,
            "sdk_analysis": {
                "detected_sdks_count": len(certification_result["detected_sdks"]),
                "certified_sdks_count": len(certification_result["certified"]),
                "uncertified_sdks_count": len(certification_result["uncertified"]),
                **certification_result
            }
        }

    def _save_report(self, report, apk_path):
        """Save the report as a JSON file to the local directory."""
        apk_name = os.path.splitext(os.path.basename(apk_path))[0]
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_filename = f"{apk_name}_sdk_analysis_{timestamp}.json"
        report_path = os.path.join(self.report_dir, report_filename)

        try:
            with open(report_path, "w", encoding="utf-8") as f:
                json.dump(report, f, ensure_ascii=False, indent=2)
            self.logger.info(f"The report has been saved to：{report_path}")
        except Exception as e:
            self.logger.error(f"Failed to save the report：{str(e)}")