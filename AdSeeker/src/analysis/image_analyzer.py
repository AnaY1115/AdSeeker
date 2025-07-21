import requests
import json
import base64
import os
import datetime
from src.utils.logger import Logger


class ImageAnalyzer:
    def __init__(self, config_path):
        self.config = json.load(open(config_path))
        self.logger = Logger.get_logger("ImageAnalyzer")
        self.report_dir = "E:\\Ad_REPORT_Set\\image_analysis_reports"
        self.prompt_config = self._load_prompt_config()
        self._init_report_dir()

    def _load_prompt_config(self):
        """Load the prompt configuration file (including mining'ad_image) from this directory"""
        prompt_path = os.path.join(os.path.dirname(__file__), "../config/prompt_template.json")
        try:
            with open(prompt_path, "r", encoding="utf-8") as f:
                config = json.load(f)
            return config.get("mining_ad_image", {})
        except FileNotFoundError:
            self.logger.error(f"Prompt configuration file not found: {prompt_path}")
            raise
        except json.JSONDecodeError:
            self.logger.error(f"Prompt configuration file parsing failed: {prompt_path}")
            raise

    def _init_report_dir(self):
        """Initialize the report directory and ensure that the directory exists"""
        if not os.path.exists(self.report_dir):
            os.makedirs(self.report_dir)
            self.logger.info(f"Create a directory for image analysis reports: {self.report_dir}")

    def _build_prompt(self):
        system_setup = self.prompt_config.get("1", {}).get("Template of prompt patterns", "")
        task_description = self.prompt_config.get("2", {}).get("Template of prompt patterns", "")
        output_description = self.prompt_config.get("3", {}).get("Template of prompt patterns", "")
        formatted_prompt = f"{system_setup}<br/><br/>{task_description}<br/><br/>{output_description}"
        formatted_prompt = formatted_prompt.replace("{Vision View}", "the analysis results")
        return formatted_prompt

    def analyze_ad_image(self, image_path):
        self.logger.info(f"Analyze images：{image_path}")
        try:
            # Read JPG image and convert it to Base64
            with open(image_path, "rb") as f:
                image_b64 = base64.b64encode(f.read()).decode()

            # Construct API requests (using structured prompts loaded from configuration files)
            payload = {
                "image": image_b64,
                "prompt": self._build_prompt()
            }

            response = requests.post(
                self.config["glm4v_endpoint"],
                headers={"Authorization": f"Bearer {self.config['glm4v_api_key']}"},
                json=payload,
                timeout=60
            )
            response.raise_for_status()  # Throwing HTTP error
            analysis_result = response.json()

            # Generate and save reports
            self._generate_and_save_report(image_path, analysis_result)
            return analysis_result

        except FileNotFoundError:
            self.logger.error(f"Image file not found: {image_path}")
            raise
        except requests.exceptions.RequestException as e:
            self.logger.error(f"API call failed: {str(e)}")
            raise
        except Exception as e:
            self.logger.error(f"Image analysis failed: {str(e)}")
            raise

    def _generate_and_save_report(self, image_path, analysis_result):
        """Generate and save analysis reports in JSON format"""
        report = {
            "report_info": {
                "image_path": image_path,
                "analysis_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "image_filename": os.path.basename(image_path),
                "prompt_used": self._build_prompt()
            },
            "analysis_result": analysis_result,
            "summary": self._extract_summary(analysis_result)
        }

        image_name = os.path.splitext(os.path.basename(image_path))[0]
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_filename = f"{image_name}_image_analysis_{timestamp}.json"
        report_path = os.path.join(self.report_dir, report_filename)

        # Save Report
        try:
            with open(report_path, "w", encoding="utf-8") as f:
                json.dump(report, f, ensure_ascii=False, indent=2)
            self.logger.info(f"The image analysis report has been saved to: {report_path}")
        except Exception as e:
            self.logger.error(f"Failed to save report: {str(e)}")

    def _extract_summary(self, analysis_result):
        """Extract key information from analysis results and summarize it"""
        # Adapt the JSON structure returned by the API and extract key fields
        summary = {
            "is_illegal_ad": analysis_result.get("is_illegal_ad", "unknown"),
            "illegal_icons_count": len(analysis_result.get("illegal_icons", [])),
            "image_risk_type": analysis_result.get("image_risk", "none"),
            "text_violations_count": len(
                analysis_result.get("text_violations", {}).get("sensitive_words", [])) if isinstance(
                analysis_result.get("text_violations"), dict) else 0
        }
        return summary