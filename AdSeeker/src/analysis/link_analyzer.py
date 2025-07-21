'''
Time: 2025.7.12
We will upload the comments for the code as soon as possible and update the document content so that you can better understand the code.
'''

import subprocess
import json
import re
import requests
import os
import datetime
import base64
from src.utils.logger import Logger


class LinkAnalyzer:
    def __init__(self, config_path):
        self.config = json.load(open(config_path))
        self.logger = Logger.get_logger("LinkAnalyzer")
        self.virustotal_api_key = self.config.get("virustotal_api_key")   #Replace with your own key
        self.report_dir = "    link_analysis_reports"
        self.temp_dir = "../temp"
        self.icann_domain_regex = self.config.get("icann_domain_regex", r"https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}")
        self._init_directories()

    def _init_directories(self):
        """Initialize temporary directory and report directory"""
        for dir_path in [self.report_dir, self.temp_dir]:
            if not os.path.exists(dir_path):
                os.makedirs(dir_path)
                self.logger.info(f"create directory: {dir_path}")

    def capture_https_traffic(self, package_name):
        self.logger.info(f"Start capturing {package_name} HTTPS traffic...")

        try:
            self._configure_charles_certificate()

            self._bypass_ssl_pinning(package_name)

            self._monitor_ui_events(package_name)

            self.logger.info("Start Charles Proxy...")
            subprocess.run(["open", "/Applications/Charles.app"], check=True)

            self.logger.info("Waiting for user interaction to trigger advertising traffic...")
            import time
            time.sleep(10)

            har_path = os.path.join(self.temp_dir, f"{package_name}_ads_traffic.har")
            device_har_path = "/sdcard/charles/ads.har"
            subprocess.run([self.config["adb_path"], "shell", "mkdir -p /sdcard/charles/"], check=True)
            subprocess.run([self.config["adb_path"], "pull", device_har_path, har_path], check=True)
            self.logger.info(f"Obtained HAR traffic file: {har_path}")

            parsed_links = self._parse_har(har_path)
            self.captured_har_path = har_path
            self.captured_package = package_name
            return parsed_links

        except Exception as e:
            self.logger.error(f"HTTPS traffic capture failed: {str(e)}")
            raise

    def _configure_charles_certificate(self):
        self.logger.info("Configure Charles certificate to the system certificate directory...")
        cert_path = self.config.get("charles_cert_path", "./certs/charles.pem")
        if not os.path.exists(cert_path):
            raise FileNotFoundError(f"Charles certificate file does not exist: {cert_path}")

        cert_hash = subprocess.run(
            ["openssl", "x509", "-inform", "PEM", "-subject_hash_old", "-in", cert_path, "|", "head", "-1"],
            capture_output=True, text=True, shell=True
        ).stdout.strip()

        try:
            subprocess.run([self.config["adb_path"], "push", cert_path, f"/sdcard/{cert_hash}.0"], check=True)
            subprocess.run(
                [self.config["adb_path"], "shell", "su -c 'mv /sdcard/{cert_hash}.0 /system/etc/security/cacerts/'"],
                check=True)
            subprocess.run(
                [self.config["adb_path"], "shell", "su -c 'chmod 644 /system/etc/security/cacerts/{cert_hash}.0'"],
                check=True)
            self.logger.info("Charles certificate configuration successful")
        except Exception as e:
            self.logger.warning(f"Certificate configuration may require root privileges, and non root environments may not be able to decrypt HTTPS: {str(e)}")

    def _monitor_ui_events(self, package_name):
        self.logger.info("Start monitoring UI interaction events...")
        ui_log = subprocess.Popen(
            [self.config["adb_path"], "logcat", "-s", "ViewRootImpl", "InputEventReceiver"],
            stdout=subprocess.PIPE, text=True
        )

        import threading
        def _ui_event_handler():
            for line in ui_log.stdout:
                if package_name in line and ("click" in line.lower() or "touch" in line.lower()):
                    self.logger.info(f"Detected user interaction event: {line.strip()}")
                    self.last_ui_event_time = datetime.datetime.now()

        threading.Thread(target=_ui_event_handler, daemon=True).start()

    def _bypass_ssl_pinning(self, package_name):
        self.logger.info(f"By  {package_name} SSL verification...")
        try:
            subprocess.run(["frida", "--version"], capture_output=True, check=True)
        except subprocess.CalledProcessError:
            raise RuntimeError("Frida is not installed, please install Frida tool first")

        ssl_script_path = "./scripts/bypass_ssl.js"
        if not os.path.exists(ssl_script_path):
            raise FileNotFoundError(f"Frida script does not exist: {ssl_script_path}")

        self.logger.info(f"Inject Frida script into {package_name}...")
        subprocess.Popen([
            "frida", "-U", "-f", package_name,
            "-l", ssl_script_path, "--no-pause"
        ])
        import time
        time.sleep(5)

    def _parse_har(self, har_path):
        try:
            with open(har_path, "r", encoding="utf-8") as f:
                har_data = json.load(f)
        except json.JSONDecodeError:
            self.logger.error(f"HAR file parsing failed: {har_path}")
            return []

        redirect_links = []
        for entry in har_data.get("log", {}).get("entries", []):
            response = entry.get("response", {})
            headers = response.get("headers", [])

            for header in headers:
                if header.get("name", "").lower() == "location":
                    redirect_url = header.get("value", "")
                    if redirect_url:
                        redirect_links.append(redirect_url)

            content = response.get("content", {})
            body = content.get("text", "") or content.get("encoding", "")
            if body:
                if content.get("encoding", "").lower() == "base64":
                    try:
                        body = base64.b64decode(body).decode("utf-8", errors="ignore")
                    except Exception as e:
                        self.logger.warning(f"Decoding response body failed: {str(e)}")
                body_links = re.findall(self.icann_domain_regex, body)
                redirect_links.extend(body_links)

        unique_links = [link for link in list(set(redirect_links)) if link.strip()]
        self.logger.info(f"Extract from HAR file {len(unique_links)} unique link")
        return unique_links

    def check_link_safety(self, links):
        if not self.virustotal_api_key:
            self.logger.warning("VirusTotal API key not configured, skip link security check")
            return []

        results = []
        self.link_safety_details = []  #

        for link in links:
            self.logger.info(f"Check link security: {link}")
            try:
                import hashlib
                url_id = base64.urlsafe_b64encode(link.encode()).decode().strip("=")
                url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
                headers = {"x-apikey": self.virustotal_api_key}

                response = requests.get(url, headers=headers, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    attributes = data.get("data", {}).get("attributes", {})
                    safety_result = {
                        "link": link,
                        "reputation": attributes.get("reputation", 0),
                        "malicious_tags": attributes.get("last_analysis_tags", {}),
                        "malicious_detected": attributes.get("last_analysis_stats", {}).get("malicious", 0),
                        "total_scans": attributes.get("last_analysis_stats", {}).get("total", 0)
                    }
                    results.append(safety_result)
                    self.link_safety_details.append(safety_result)
                elif response.status_code == 404:
                    self.logger.info(f"VirusTotal does not include this link: {link}")
                    results.append({"link": link, "reputation": 0, "malicious_tags": "None", "malicious_detected": 0})
                else:
                    self.logger.warning(f"VirusTotal API call failed, status code: {response.status_code}")
            except Exception as e:
                self.logger.error(f"Check {link} file: {str(e)}")
                results.append({"link": link, "error": str(e)})

        self._generate_and_save_report()
        return results

    def _generate_and_save_report(self):
        if not hasattr(self, "captured_package"):
            self.logger.warning("Traffic data not captured, unable to generate report")
            return

        report = {
            "report_info": {
                "package_name": self.captured_package,
                "analysis_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "har_file_path": self.captured_har_path,
                "total_links_extracted": len(self._parse_har(self.captured_har_path))
            },
            "extracted_links": self._parse_har(self.captured_har_path),
            "safety_check_results": self.link_safety_details,
            "summary": {
                "malicious_links_count": sum(
                    1 for res in self.link_safety_details if res.get("malicious_detected", 0) > 0),
                "total_checked": len(self.link_safety_details)
            }
        }

        self._save_report(report)

    def _save_report(self, report):
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_filename = f"{report['report_info']['package_name']}_link_analysis_{timestamp}.json"
        report_path = os.path.join(self.report_dir, report_filename)

        try:
            with open(report_path, "w", encoding="utf-8") as f:
                json.dump(report, f, ensure_ascii=False, indent=2)
            self.logger.info(f"The link analysis report has been saved to: {report_path}")
        except Exception as e:
            self.logger.error(f"Failed to save report: {str(e)}")