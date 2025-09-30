# Security Camera Report Generator  

A tool that generates PDF reports based on AI detections from your security cameras, integrated with the Frigate NVR system.  

## Features  
- **Integration with Frigate NVR**: Leverages local AI object detection capabilities to analyze footage and generate detailed reports [1].  
- **PDF Reports**: Creates comprehensive PDF documents summarizing detected objects, timestamps, and camera details.  
- **Customizable Content**: Includes key information such as detected objects (e.g., persons, cars), duration of activity, and confidence scores from AI models.  

## Benefits  
- **Efficiency**: Automatically generates reports without manual intervention, saving time for security teams.  
- **Accuracy**: Relies on Frigate's advanced AI processing to reduce false positives and ensure reliable data [1].  
- **Customization**: Tailor the report format to meet specific needs, such as including camera-specific details or filtering by detection type.  

## Requirements  
- An active Frigate NVR setup with supported AI accelerators for object detection [1].  
- Cameras configured with IP addresses or RTSP streams (as supported by Frigate) [2].  
- Compatible hardware to handle local processing of AI models.  

## Installation  
1. Clone the repository: `git clone https://github.com/your-repository.git`  
2. Install dependencies: `pip install -r requirements.txt`  

## Configuration  
1. Edit the configuration file (`config.yaml`) to specify your Frigate instance details and report settings.  
2. Set up output directory for generated PDF reports.  

## Usage  
1. Run the generator script: `python generate_report.py`  
2. The tool will fetch detection data from Frigate, process it, and save a PDF report in the specified directory.  

This system streamlines the creation of security camera reports, providing valuable insights while maintaining privacy by keeping all processing local [1].
