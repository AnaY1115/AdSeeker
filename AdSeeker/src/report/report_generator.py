'''
Time: 2025.7.15
We will upload the comments for the code as soon as possible and update the document content so that you can better understand the code.
'''

import json
import datetime
import os
from src.utils.logger import Logger


class ReportGenerator:
    def __init__(self, config_path):
        self.config = json.load(open(config_path))
        self.logger = Logger.get_logger("ReportGenerator")
        self.prompt_config = self._load_report_prompt_config()  # Load the prompt configuration for report generation
        self.report_dir = "../reports"  # Final report save directory
        self._init_report_dir()

    def _init_report_dir(self):
        """Initialize report directory"""
        if not os.path.exists(self.report_dir):
            os.makedirs(self.report_dir)
            self.logger.info(f"Create the final report table of contents: {self.report_dir}")

    def _load_report_prompt_config(self):
        """Load the report_getting configuration from the JSON file in this directory."""
        prompt_file_path = os.path.join(os.path.dirname(__file__), "prompt_config.json")
        try:
            with open(prompt_file_path, "r", encoding="utf-8") as f:
                config = json.load(f)
            return config.get("report_getting", {})
        except FileNotFoundError:
            self.logger.error(f"The prompt configuration file was not found.: {prompt_file_path}")
            raise
        except json.JSONDecodeError:
            self.logger.error(f"Report: Prompt configuration file parsing failed: {prompt_file_path}")
            raise

    def _load_local_json(self, file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except FileNotFoundError:
            self.logger.error(f"File not found: {file_path}")
            return {}
        except json.JSONDecodeError:
            self.logger.error(f"File parsing failed: {file_path}")
            return {}

    def _build_report_prompt(self, integrated_data):
        system_setup = self.prompt_config.get("1", {}).get("Template of prompt patterns", "")
        task_description = self.prompt_config.get("2", {}).get("Template of prompt patterns", "")
        nouns_interpretation = self.prompt_config.get("3", {}).get("Template of prompt patterns", "")
        output_description = self.prompt_config.get("4", {}).get("Template of prompt patterns", "")

        sdk_view = json.dumps(self._load_local_json("sdk_analysis.json"), ensure_ascii=False)
        permission_view = json.dumps(self._load_local_json("permission_analysis.json"), ensure_ascii=False)
        redirect_link_view = json.dumps(self._load_local_json("link_analysis.json"), ensure_ascii=False)
        vision_view = json.dumps(self._load_local_json("image_analysis.json"), ensure_ascii=False)

        nouns_interpretation = nouns_interpretation.replace("{SDK View Description}", "The detection results of the SDK used in advertisements, including authentication status and risk assessment.")
        nouns_interpretation = nouns_interpretation.replace("{Permission View Description}", "List of permissions requested for advertisements and their legality analysis")
        nouns_interpretation = nouns_interpretation.replace("{Redirect Link View Description}", "Redirection links in advertisements and results of security checks")
        nouns_interpretation = nouns_interpretation.replace("{Vision View Description}", "Analysis of the compliance of icons, content, and text in advertising images")

        full_prompt = f"{system_setup}\n\n{task_description}\n\n{nouns_interpretation}\n\n{output_description}"

        '''The sdk_view, permission-view, relocate_link-view, and vision-view are analysis files stored locally for the four components of the advertisement'''
        full_prompt = full_prompt.replace("{SDK View}", sdk_view)
        full_prompt = full_prompt.replace("{Permission View}", permission_view)
        full_prompt = full_prompt.replace("{Redirect Link View}", redirect_link_view)
        full_prompt = full_prompt.replace("{Vision View}", vision_view)
        full_prompt = full_prompt.replace("{Diagnostic report}", "Final diagnostic report")  # 替换报告占位符

        return full_prompt

    def integrate_results(self, sdk_result, permission_result, link_result, image_result):
        """Integrate multi-module detection results"""
        integrated_data = {
            "sdk_analysis": sdk_result,
            "permission_analysis": permission_result,
            "link_analysis": link_result,
            "image_analysis": image_result,
            "timestamp": str(datetime.datetime.now())
        }
        self.logger.info("The multi-module detection results have been integrated.")
        return integrated_data

    def generate_report(self, integrated_data):
        """Generate a detection report based on integrated data."""
        self.logger.info("Generate a detection report...")
        try:
            # Developing refined prompts
            prompt = self._build_report_prompt(integrated_data)

            # Invoke your own LLM API and KEY to generate a report
            # llm_summary = self._simulate_llm_output(prompt, integrated_data)

            # Constructing report structure
            report = {
                "summary": llm_summary,
                "details": integrated_data
            }

            # Save as a TXT format report
            self._save_report(report, integrated_data["timestamp"])
            return report
        except Exception as e:
            self.logger.error(f"The report generation failed: {str(e)}")
            raise

    def _save_report(self, report, timestamp):
        """ Save the report as a TXT format"""
        time_str = timestamp.split()[0].replace("-", "") + "_" + timestamp.split()[1].replace(":", "")
        report_filename = f"ad_diagnostic_report_{time_str}.txt"
        report_path = os.path.join(self.report_dir, report_filename)

        with open(report_path, "w", encoding="utf-8") as f:
            f.write("=== Advertising Diagnostic Report ===\n")
            f.write(f"generation time：{timestamp}\n\n")
            f.write("【Abstuct】\n")
            f.write(report["summary"] + "\n\n")
            f.write("【detailed analysis】\n")
            f.write("1. SDK analysis：\n")
            f.write(json.dumps(report["details"]["sdk_analysis"], ensure_ascii=False, indent=2) + "\n\n")
            f.write("2. permission analysis：\n")
            f.write(json.dumps(report["details"]["permission_analysis"], ensure_ascii=False, indent=2) + "\n\n")
            f.write("3. Link analysis：\n")
            f.write(json.dumps(report["details"]["link_analysis"], ensure_ascii=False, indent=2) + "\n\n")
            f.write("4. Image analysis：\n")
            f.write(json.dumps(report["details"]["image_analysis"], ensure_ascii=False, indent=2) + "\n")

        self.logger.info(f"The report has been saved to {report_path}")