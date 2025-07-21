'''
Time: 2025.7.15
We will upload the comments for the code as soon as possible and update the document content so that you can better understand the code.
'''


import subprocess
import json
import os
import datetime
import time
from src.utils.logger import Logger


class PermissionAnalyzer:
    def __init__(self, adb_path):
        self.adb_path = adb_path
        self.logger = Logger.get_logger("PermissionAnalyzer")
        self.report_dir = "E:\\Ad_REPORT_Set\\permission_reports"
        self._init_report_dir()
        self.sensitive_permission_categories = {
            "location information": ["android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_COARSE_LOCATION"],
            "device information": ["android.permission.READ_PHONE_STATE", "android.permission.READ_PRIVILEGED_PHONE_STATE"],
            "storage access": ["android.permission.READ_EXTERNAL_STORAGE", "android.permission.WRITE_EXTERNAL_STORAGE"],
            "network communication": ["android.permission.IN  TERNET", "android.permission.ACCESS_NETWORK_STATE"],
            "personal data": ["android.permission.READ_CONTACTS", "android.permission.READ_CALENDAR"]
        }

    def _init_report_dir(self):
        if not os.path.exists(self.report_dir):
            os.makedirs(self.report_dir)
            self.logger.info(f"Create a directory for permission analysis reports: {self.report_dir}")

    def get_static_permissions(self, package_name):
        self.logger.info(f"Getting  {package_name}  Static Permission...")
        try:
            result = subprocess.run(
                [self.adb_path, "shell", "dumpsys", "package", package_name],
                capture_output=True,
                text=True,
                timeout=30
            ).stdout

            permissions = []
            self.static_perm_details = []
            in_permission_section = False

            for line in result.splitlines():
                line = line.strip()
                if "Requested permissions:" in line:
                    in_permission_section = True
                    continue
                if in_permission_section and line.startswith("Installed"):
                    break

                if in_permission_section and "permission:" in line:
                    # Extract permission name
                    perm_name = line.split("permission:")[1].split()[0].strip()
                    # extract authorization status
                    status = "granted" if "status: granted" in line else "denied"
                    # Mark whether it is a sensitive permission
                    is_sensitive = self._is_sensitive_permission(perm_name)
                    # Store detailed information
                    self.static_perm_details.append({
                        "permission": perm_name,
                        "status": status,
                        "is_sensitive": is_sensitive,
                        "source": "static"
                    })
                    permissions.append(perm_name)

            self.logger.info(f"Successfully extracted {len(permissions)} static permissions")
            return permissions
        except subprocess.TimeoutExpired:
            self.logger.error("Failed to obtain static permissions within the time limit")
            return []
        except Exception as e:
            self.logger.error(f"Failed to obtain static permissions: {str(e)}")
            return []

    def get_dynamic_permissions(self, package_name):

        self.logger.info(f"Pronunciation {package_name} dynamic permission request...")
        self.dynamic_event_details = []
        dynamic_events = []

        try:
            # Clear history logs
            subprocess.run(
                [self.adb_path, "logcat", "-c"],
                capture_output=True,
                text=True
            )

            # Start Logcat monitoring and filter logs related to permissions.
            logcat = subprocess.Popen(
                [self.adb_path, "logcat", "PermissionManager:I", "ActivityManager:I", "*:S"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            start_time = time.time()
            timeout = 30

            while time.time() - start_time < timeout:
                line = logcat.stdout.readline()
                if not line:
                    continue

                if package_name in line and ("requestPermissions" in line or "checkSelfPermission" in line):
                    timestamp = " ".join(line.split()[:2])
                    perm_match = self._extract_permissions_from_log(line)
                    is_risky = "without user interaction" in line.lower() or "background request" in line.lower()
                    event_detail = {
                        "time": timestamp,
                        "full_event": line.strip(),
                        "permissions": perm_match,
                        "is_risky": is_risky,
                        "risk_level": "high" if is_risky else "low"
                    }
                    self.dynamic_event_details.append(event_detail)
                    dynamic_events.append({
                        "time": timestamp,
                        "event": line.strip()
                    })

                if len(dynamic_events) >= 50:
                    self.logger.info("The maximum number of dynamic permission events has been reached; monitoring has stopped.")
                    break

            logcat.terminate()
            self.logger.info(f"Successfully capture {len(dynamic_events)} A dynamic permission event")
            return dynamic_events
        except Exception as e:
            self.logger.error(f"Failed to obtain dynamic permission event: {str(e)}")
            return []

    def analyze_permission_legitimacy(self, static_perms, dynamic_events):
        self.logger.info("Analyze the legitimacy of permission requests....")

        # Sensitive permissions classification
        sensitive_categories = self._categorize_sensitive_permissions(static_perms)
        risky_events = [e for e in self.dynamic_event_details if e["is_risky"]]
        high_risk_events = [e for e in risky_events if e["risk_level"] == "high"]
#score rules
        base_score = 100
        sensitive_deduction = len(sensitive_categories["all"]) * 5
        risky_deduction = len(high_risk_events) * 10 + (len(risky_events) - len(high_risk_events)) * 3
        final_score = max(0, base_score - sensitive_deduction - risky_deduction)

        result = {
            "sensitive_permissions": sensitive_categories["all"],
            "risky_dynamic_events": risky_events,
            "legitimacy_score": final_score
        }

        self._generate_and_save_report(
            package_name=self.current_package,
            analysis_result=result,
            static_details=self.static_perm_details,
            dynamic_details=self.dynamic_event_details,
            sensitive_categories=sensitive_categories
        )

        return result

    def _is_sensitive_permission(self, permission):
        for cat_perms in self.sensitive_permission_categories.values():
            if permission in cat_perms:
                return True
        return False

    def _extract_permissions_from_log(self, log_line):
        perm_prefixes = ["android.permission.", "com.android.", package_name + "."]
        perms = []
        for prefix in perm_prefixes:
            start = log_line.find(prefix)
            if start != -1:
                end = log_line.find(" ", start)
                if end == -1:
                    end = len(log_line)
                perm = log_line[start:end].strip()
                if perm not in perms:
                    perms.append(perm)
        return perms

    def _categorize_sensitive_permissions(self, permissions):
        categorized = {cat: [] for cat in self.sensitive_permission_categories.keys()}
        categorized["all"] = []
        for perm in permissions:
            if self._is_sensitive_permission(perm):
                categorized["all"].append(perm)
                for cat, cat_perms in self.sensitive_permission_categories.items():
                    if perm in cat_perms:
                        categorized[cat].append(perm)
        return categorized

    def _generate_and_save_report(self, package_name, analysis_result, static_details, dynamic_details, sensitive_categories):
        # Generate report content
        report = {
            "report_info": {
                "package_name": package_name,
                "analysis_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "report_version": "1.0"
            },
            "static_permissions": {
                "total_count": len(static_details),
                "sensitive_count": len(sensitive_categories["all"]),
                "by_category": sensitive_categories,
                "details": static_details
            },
            "dynamic_permissions": {
                "total_events": len(dynamic_details),
                "risky_events_count": len(analysis_result["risky_dynamic_events"]),
                "details": dynamic_details
            },
            "legitimacy_analysis": {
                "legitimacy_score": analysis_result["legitimacy_score"],
                "score_interpretation": self._interpret_score(analysis_result["legitimacy_score"]),
                "sensitive_permissions": analysis_result["sensitive_permissions"],
                "risky_dynamic_events": [e["full_event"] for e in analysis_result["risky_dynamic_events"]],
                "suggestions": self._generate_suggestions(analysis_result, sensitive_categories)
            }
        }

        self._save_report(report, package_name)

    def _interpret_score(self, score):
        if score >= 80:
            return "The legitimacy of permission requests is high, and the risk is low."
        elif score >= 60:
            return "The legitimacy of the permission request is moderate, with minor risks present."
        elif score >= 40:
            return "The legitimacy of permission requests is low, posing certain risks."
        else:
            return "The legitimacy of the permission request is low, and the risk is high; it requires thorough review."

    # Generate improvement suggestions
    def _generate_suggestions(self, analysis_result, sensitive_categories):
        suggestions = []
        if len(sensitive_categories["all"]) > 5:
            suggestions.append(f"app request{len(sensitive_categories['all'])}sensitive permissions, it is recommended to only keep necessary permissions.")
        if len(analysis_result["risky_dynamic_events"]) > 0:
            suggestions.append(f"Here {len(analysis_result['risky_dynamic_events'])} risk-based permission request, it is recommended to avoid background permission requests without user interaction.")
        if analysis_result["legitimacy_score"] < 60:
            suggestions.append("Overall permission request legitimacy is low; it is recommended to optimize permission application strategies and follow the principle of least privilege.")
        return suggestions if suggestions else ["The permission request complies with standard regulations, and the risk is controllable."]

    # Save the report locally
    def _save_report(self, report, package_name):
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_filename = f"{package_name}_permission_analysis_{timestamp}.json"
        report_path = os.path.join(self.report_dir, report_filename)

        try:
            with open(report_path, "w", encoding="utf-8") as f:
                json.dump(report, f, ensure_ascii=False, indent=2)
            self.logger.info(f"The permission analysis report has been saved to: {report_path}")
        except Exception as e:
            self.logger.error(f"Failed to save the permission analysis report: {str(e)}")

    # Set the current package name for analysis (for reporting).
    def set_package(self, package_name):
        self.current_package = package_name