# Malicious Ad Detection System for Mobile Applications

This project is dedicated to detecting malicious ads in mobile applications. It generates detailed reports through multi-dimensional analysis (permission requests, SDK identification, image analysis, link detection) combined with large language models (LLMs). The project uses the Androzoo dataset for experiments and completes ad UI exploration and analysis on the MUMU emulator.

## Project Background

Malicious ads in mobile applications have become a major source of user privacy leaks and security risks. This system aims to provide an automated detection solution to help developers and users identify potential malicious ads.

## System Architecture

The system mainly includes the following modules:

  

-   **UI Exploration Module**: Automatically explores applications and locates ad pages on the MUMU emulator
-   **Permission Analysis Module**: Detects sensitive permissions requested by ads
-   **SDK Identification Module**: Extracts and analyzes ad SDK components
-   **Image Detection Module**: Analyzes ad image content
-   **Link Detection Module**: Checks the security of links within ads
-   **Report Generation Module**: Integrates analysis results based on LLM to generate reports

## Installation and Usage

### Environment Requirements

1.  Python
2.  Java
3.  Android SDK
4. Android device or emulator
5.  Added directory in Android SDK to `platform_tools` `PATH`
6.  Prepare your own LLM or Agent API key

### Installation Steps

1.  Install required dependencies: `pip install -r requirements.txt`
2.  Configure the MUMU emulator and ADB environment
3.  Obtain and configure the Androzoo dataset API key
4.  Obtain and configure the LLM or Agent API key

### Usage Method

1.  Prepare the APK file to be detected
2.  Complete LLM and Android UI exploration and other related configurations
3.  Run the main program: `python main.py -a /path/to/apk`
4.  View the generated detection report

## Directory Structure

The hierarchical structure of project code files is as follows:

  

plaintext

```plaintext
AdSeeker/
├── requirements.txt         # List of dependencies
├── main.py                  # Main program entry
├── config/                  # Configuration files directory
│   ├── emulator_config.json  # Emulator configuration
│   ├── detection_rules.json  # Detection rules configuration
│   └── llm_config.json      # Large language model configuration
├── src/                     # Source code directory
│   ├── emulator/            # Emulator interaction module
│   │   ├── ui_explorer.py   # UI exploration functionality
│   │   └── ad_detector.py   # Ad page localization
│   ├── analysis/            # Analysis module
│   │   ├── permission_analyzer.py  # Permission analysis
│   │   ├── sdk_analyzer.py         # SDK analysis
│   │   ├── image_analyzer.py       # Image analysis
│   │   └── link_analyzer.py        # Link analysis
│   ├── report/              # Report generation module
│   │   └── report_generator.py
│   └── utils/               # Utility functions
│       ├── apk_utils.py     # APK processing tools
│       └── logger.py        # Logging tools
├── tests/                   # Test code directory
│   ├── test_ui_explorer.py
│   ├── test_permission_analyzer.py
│   └── ...
├── datasets/                # Dataset-related files
└── reports/                 # Generated detection reports
```

## Contribution Guidelines

Contributions are welcome! Please follow these steps:

  

1.  Submit an Issue describing the problem or suggestion
2.  Create a new branch for development
3.  Submit a Pull Request and ensure all tests pass

## Known Limitations

-   The current implementation is not proficient at determining task completion status.
-   Due to the randomness of LLM Agents, differences in apps, variations in GUI styles and quality, and disparities in understanding task descriptions, results may vary across repeated experiments.

## Notes

-   We greatly appreciate the application dataset provided by Androzoo, the reference to UI exploration methods from [AutoDroid](https://github.com/MobileLLM/AutoDroid/tree/newbranch), and all developers who contribute to the open-source community.
-   Note that AdSeeker is currently for research purposes only. Users assume full responsibility for any unexpected issues arising during app exploration.
-   If you reference this project in research, papers, or other projects, please provide proper citation. Thank you for respecting and supporting the intellectual property rights of this project.
-   Some core files have been uploaded for this project, and we will continue to organize and update the complete code and documentation in the future.

  

Enjoy!
