# CTF-Recon Static Files

This directory contains static files and templates for the CTF-Recon HTML report generation system.

## Directory Structure

```
static/
├── htmltemplate/           # HTML templates for report sections
│   ├── main.html          # Main HTML structure
│   ├── header.html        # Report header template
│   ├── stats.html         # Statistics section template
│   ├── port_section.html  # Port scan results template
│   ├── services_section.html # Service enumeration template
│   ├── nuclei_section.html   # Nuclei vulnerability scan template
│   ├── whatweb_section.html  # WhatWeb analysis template
│   ├── file_structure_section.html # File viewer template
│   ├── notes_section.html    # Interactive notes template
│   ├── footer.html          # Report footer template
│   ├── file_viewer_js.html  # File viewer JavaScript
│   ├── notes_js.html        # Notes functionality JavaScript
│   └── styles.css           # Additional CSS styles
├── refresh_file_viewer.sh   # Script to refresh file viewer
└── README.md               # This file
```

## Template System

The HTML report generation now uses a modular template system:

### Templates
- **main.html**: Base HTML structure with placeholders
- **section templates**: Individual sections that can be included
- **JavaScript templates**: Interactive functionality
- **CSS**: Styling for file viewer and notes

### Placeholders
Templates use `{{PLACEHOLDER}}` syntax for dynamic content:
- `{{TARGET}}` - Target IP address
- `{{SCAN_DATE}}` - Scan timestamp
- `{{OPEN_PORTS}}` - Number of open ports
- `{{SERVICES}}` - Number of services
- `{{FINDINGS}}` - Number of findings
- `{{EXPLOITS}}` - Number of potential exploits


### Generated Files
The refresh script creates:
- `file_structure.json` - File metadata and content