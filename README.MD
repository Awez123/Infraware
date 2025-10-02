# 🛡️ InfraWare - Enterprise Infrastructure Security & Cost Platform# 🛡️ InfraWare - Enterprise Infrastructure Security & Cost Platform



[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)



**InfraWare** is an enterprise-grade Infrastructure as Code (IaC) security scanner with integrated CVE database and container security capabilities. It combines infrastructure vulnerability detection with cost analysis to provide comprehensive cloud security insights.**InfraWare** is an enterprise-grade Infrastructure as Code (IaC) security scanner with integrated CVE database and container security capabilities. It combines infrastructure vulnerability detection with cost analysis to provide comprehensive cloud security insights.



## 🚀 Key Features## 🚀 Key Features



### 🔍 Infrastructure Security### 🔍 Infrastructure Security

- **Multi-Cloud IaC Scanning**: Terraform, CloudFormation, Kubernetes YAML- **Multi-Cloud IaC Scanning**: Terraform, CloudFormation, Kubernetes YAML

- **CVE Integration**: 2,000+ vulnerabilities with real-time updates- **CVE Integration**: 2,000+ vulnerabilities with real-time updates

- **Risk Scoring**: Advanced severity assessment and scoring- **Risk Scoring**: Advanced severity assessment and scoring

- **Compliance Mapping**: CIS Controls and industry standards- **Compliance Mapping**: CIS Controls and industry standards



### 🐳 Container Security### 🐳 Container Security

- **Dockerfile Analysis**: Security best practices and vulnerability detection- **Dockerfile Analysis**: Security best practices and vulnerability detection

- **Container Image Scanning**: Layer-by-layer vulnerability analysis- **Container Image Scanning**: Layer-by-layer vulnerability analysis

- **Runtime Security**: Running container assessment- **Runtime Security**: Running container assessment

- **Secret Detection**: Hardcoded credentials and sensitive data identification- **Secret Detection**: Hardcoded credentials and sensitive data identification



### 💰 Cost Analysis### 💰 Cost Analysis

- **Multi-Cloud Cost Estimation**: AWS, Azure, GCP pricing- **Multi-Cloud Cost Estimation**: AWS, Azure, GCP pricing

- **Resource Optimization**: Cost-aware security recommendations- **Resource Optimization**: Cost-aware security recommendations

- **Regional Pricing**: Location-specific cost calculations- **Regional Pricing**: Location-specific cost calculations

- **Usage-Based Modeling**: Flexible time-based cost projections- **Usage-Based Modeling**: Flexible time-based cost projections



### 🔄 Real-Time Intelligence### 🔄 Real-Time Intelligence

- **CVE Database**: Auto-updating vulnerability intelligence from NVD and GitHub- **CVE Database**: Auto-updating vulnerability intelligence from NVD and GitHub

- **Threat Correlation**: Infrastructure resources mapped to known vulnerabilities- **Threat Correlation**: Infrastructure resources mapped to known vulnerabilities

- **Security Scoring**: Dynamic risk assessment based on current threat landscape- **Security Scoring**: Dynamic risk assessment based on current threat landscape



## 📦 Installation*(Tip: You can use a tool like [ScreenToGif](https://www.screentogif.com/) or [Peek](https://github.com/phw/peek) to create a simple GIF of your tool in action and replace the placeholder above.)*



```bash- **Security Scanning**: Detect vulnerabilities and misconfigurations in Terraform files

# Clone the repository

git clone https://github.com/ikramhyderi/Infraware.git- **Cost Analysis**: Calculate monthly costs for cloud resources with region-aware pricing## ✨ Key Features

cd Infraware

- **Multiple Format Support**: Works with Terraform (.tf), JSON, and YAML files

# Install dependencies

pip install -r requirements.txt- **Rule-Based Engine**: Extensible rules system with confidence scoring* **Accurate Plan Scanning**: Analyzes the JSON output of `terraform plan` to understand the exact state of your infrastructure, including modules and variables.



# Install InfraWare- **Professional CLI**: Clean command-line interface with detailed help* **Extensible Rule Engine**: Define security and quality checks in simple, human-readable YAML files.

pip install -e .

```* **Professional CLI**: A full-featured command-line interface with commands for scanning and rule management.



## 🎯 Quick Start## Requirements* **Interactive Rule Creation**: Use `infraware rules create` to be guided through making new rules.



### Infrastructure Scanning* **Rule Validation**: Use `infraware rules validate` to check your custom rule files for correct syntax.

```bash

# Scan Terraform plan- Python 3.8 or higher* **Ignore Findings**: Baseline your infrastructure by ignoring specific findings using simple ignore files.

infraware scan terraform-plan.json

- Terraform (for Terraform file analysis)* **Formatted Output**: Clean, color-coded console output makes it easy to spot issues.

# Scan with JSON output

infraware scan infrastructure.tf --format json

```

## Installation## 📋 Prerequisites

### Cost Analysis

```bash

# Analyze costs for AWS us-east-1

infraware cost-analysis terraform-plan.tf --region us-east-1 --hours 7201. Clone the repository:* [Python](https://www.python.org/downloads/) (version 3.8 or higher)



# Multi-cloud cost analysis```bash* [Terraform](https://developer.hashicorp.com/terraform/downloads) (version 1.0 or higher)

infraware cost-analysis multi-cloud.json --provider aws --region us-west-2

```git clone https://github.com/your-username/infraware.git



### CVE Database Operationscd infraware## 🚀 Installation

```bash

# Update CVE database```

infraware cve-update

To install and use the InfraWare CLI, follow these steps:

# Search for specific vulnerabilities

infraware cve-search "apache" --severity HIGH --limit 52. Install the package:



# View database statistics```bash1.  **Clone the Repository**:

infraware cve-stats

```pip install -e .    ```bash



### Container Security```    git clone [https://github.com/your-username/infraware.git](https://github.com/your-username/infraware.git)

```bash

# Scan Dockerfile for security issues    cd infraware

infraware dockerfile-scan Dockerfile

3. Verify installation:    ```

# Comprehensive container scan

infraware container-scan nginx:latest```bash



# Runtime container analysisinfraware --help2.  **Install the Package**:

infraware container-runtime container-id

``````    This command uses the `pyproject.toml` file to install the `infraware` command and its dependencies.



### Secret Detection    ```bash

```bash

# Scan directory for secrets## Quick Start    pip install .

infraware secrets /path/to/code

    ```

# Comprehensive security scan

infraware comprehensive terraform-plan.json### Security Scanning

```

3.  **Verify Installation**:

## 📊 Command Reference

1. Generate a Terraform plan:    Check that the command is available in your path.

| Command | Purpose | Example |

|---------|---------|---------|```bash    ```bash

| `scan` | Infrastructure vulnerability scanning | `infraware scan plan.json` |

| `cost-analysis` | Cloud cost estimation | `infraware cost-analysis plan.tf --hours 720` |terraform plan -out=tfplan.binary    infraware --help

| `cve-update` | Update CVE database | `infraware cve-update` |

| `cve-search` | Search CVE database | `infraware cve-search "kubernetes" --severity CRITICAL` |terraform show -json tfplan.binary > tfplan.json    ```

| `cve-stats` | CVE database statistics | `infraware cve-stats` |

| `container-scan` | Container image scanning | `infraware container-scan alpine:latest` |```

| `dockerfile-scan` | Dockerfile security analysis | `infraware dockerfile-scan Dockerfile` |

| `container-runtime` | Running container analysis | `infraware container-runtime web-app` |## 🔬 Usage Guide

| `secrets` | Secret detection | `infraware secrets ./src --format json` |

| `comprehensive` | Multi-faceted security scan | `infraware comprehensive infrastructure/` |2. Run security scan:



## 📈 Comparison with Trivy```bashInfraWare is designed to fit into your standard Terraform workflow.



| Feature | InfraWare | Trivy | Advantage |infraware scan tfplan.json

|---------|-----------|-------|-----------|

| **CVE Database** | 2,000+ (growing) | 180,000+ | Trivy (larger) |```### Scanning a Terraform Project

| **IaC Scanning** | Advanced Terraform/CF | Basic IaC support | InfraWare |

| **Cost Analysis** | ✅ Multi-cloud | ❌ Not available | InfraWare |

| **Container Security** | ✅ Full platform | ✅ Excellent | Tie |

| **Real-time Updates** | ✅ Auto-updating | ✅ Regular updates | Tie |### Cost Analysis1.  **Navigate to Your Terraform Project**:

| **Enterprise Features** | ✅ Cost + Security | ✅ SBOM, attestation | Tie |

    `cd` into the directory containing your `.tf` files.

## 🏗️ Architecture

1. Analyze infrastructure costs:

InfraWare uses a hybrid approach for maximum effectiveness:

```bash2.  **Initialize Terraform**:

### External Database Commands (Real-time)

- `cve-update`, `cve-search`, `cve-stats` - NVD, GitHub Security Advisoriesinfraware cost-analysis file main.tf --region us-west-2    If you haven't already, initialize Terraform to download providers and modules.

- `container-scan`, `container-runtime` - Docker APIs, package managers

```    ```bash

### Local Database Commands (Fast & Offline)

- `scan` - Local security rules (rules/*.yaml)    terraform init

- `cost-analysis` - Local pricing data (config/pricing/*.yaml)

- `dockerfile-scan`, `secrets` - Hardcoded patterns for speed2. Estimate specific resources:    ```



## 🤝 Contributing```bash



1. Fork the repositoryinfraware cost-analysis estimate aws aws_instance --type t3.medium3.  **Generate the JSON Plan**:

2. Create a feature branch (`git checkout -b feature/amazing-feature`)

3. Commit your changes (`git commit -m 'Add amazing feature'`)```    Create a binary plan file and convert it to a readable JSON format.

4. Push to the branch (`git push origin feature/amazing-feature`)

5. Open a Pull Request    ```bash



## 📄 License3. Check supported providers and regions:    terraform plan -out=tfplan.binary



This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.```bash    terraform show -json tfplan.binary > tfplan.json



## 👥 Authorsinfraware cost-analysis providers    ```



- **Awez Ahmed Khan** - *Initial work* - awezkhan786jb@gmail.com```

- **Ikram Hyderi** - *Enhanced development* - mdikramhyderi@gmail.com

4.  **Run the Scanner**:

## 🙏 Acknowledgments

## Available Commands    Now, use the `infraware` command to run the scan.

- **NIST NVD** for vulnerability data

- **GitHub Security Advisories** for threat intelligence    ```bash

- **Cloud providers** for pricing transparency

- **Open source community** for continuous improvement### Security Commands    infraware scan ./tfplan.json --rules-dir /path/to/your/rules --ignore-dir /path/to/your/ignores



---- `infraware scan` - Scan files for security vulnerabilities    ```



*InfraWare: Where Infrastructure Security Meets Cost Intelligence* 🚀- `infraware rules list` - List available security rules    **Example**:

- `infraware rules validate` - Validate rule files    ```bash

- `infraware rules create` - Create new security rules    infraware scan ./tfplan.json --rules-dir ~/dev/infraware/rules --ignore-dir ./infraware-ignores

    ```

### Cost Analysis Commands

- `infraware cost-analysis file` - Analyze costs from infrastructure files### Managing Rules

- `infraware cost-analysis estimate` - Estimate costs for specific resources

- `infraware cost-analysis providers` - List supported cloud providers and regionsInfraWare includes a full suite of commands to help you manage your rules.

- `infraware cost-analysis metadata` - Show pricing data sources

- `infraware cost-analysis confidence` - Display data quality reports#### **Listing Rules**

See all rules in a directory in a clean table format.

## File Format Support```bash

infraware rules list --rules-dir ./my-rules

### Supported File Types```

- `.tf` - Terraform configuration files

- `.json` - Terraform plan files, infrastructure JSON#### **Validating Rules**

- `.yaml/.yml` - CloudFormation templates, Kubernetes manifestsCheck a directory of rule files for correct syntax and structure.

```bash

### Supported Cloud Providersinfraware rules validate --rules-dir ./my-rules

- **AWS** - Amazon Web Services (aws_* resources)```

- **GCP** - Google Cloud Platform (google_* resources)

- **Azure** - Microsoft Azure (azurerm_* resources)#### **Creating a Rule Interactively**

Be guided through creating a new rule, which will be saved to a new YAML file.

## Cost Analysis Examples```bash

infraware rules create --rules-dir ./my-rules

### Basic File Analysis```

```bash

# Analyze Terraform file## 📄 Rule and Ignore File Formats

infraware cost-analysis file infrastructure.tf

#### **Rule File Format**

# With specific regionRules are defined in YAML files. A single file can contain a list of multiple rules.

infraware cost-analysis file main.tf --region us-east-1

*Example (`rules/aws_s3_public.yaml`):*

# Export to JSON```yaml

infraware cost-analysis file plan.json --format json- id: AWS-S3-001

  severity: HIGH

# Export to CSV  description: "S3 bucket has a public read ACL."

infraware cost-analysis file resources.tf --format csv  resource: "aws_s3_bucket"

```  attribute: "acl"

  value: "public-read"

### Resource Cost Estimation```

```bash

# AWS EC2 instance#### **Ignore File Format**

infraware cost-analysis estimate aws aws_instance --type t3.medium --region us-east-1Ignore files allow you to baseline findings. A finding is ignored if the resource's **name** matches.



# GCP compute instance*Example (`ignores/s3-exceptions.yaml`):*

infraware cost-analysis estimate gcp google_compute_instance --type e2-medium```yaml

ignore:

# Azure virtual machine  - resource_name: "my_public_website_bucket"

infraware cost-analysis estimate azure azurerm_virtual_machine --type Standard_B2s    reason: "This bucket is for a public website and is intentionally public."

```

# Storage with size

infraware cost-analysis estimate aws aws_ebs_volume --type gp3 --size 500## 🛠️ Development Setup

```

Interested in contributing to InfraWare? Here’s how to set up for development.

### Data Quality and Sources

```bash1.  **Clone the Repository**:

# Check pricing data quality    ```bash

infraware cost-analysis confidence --min-confidence 8    git clone [https://github.com/your-username/infraware.git](https://github.com/your-username/infraware.git)

    cd infraware

# View pricing metadata    ```

infraware cost-analysis metadata aws --resource aws_instance2.  **Create and Activate a Virtual Environment**:

    ```bash

# List all supported regions    python -m venv venv

infraware cost-analysis providers    source venv/bin/activate  # or .\venv\Scripts\activate on Windows

```    ```

3.  **Install in Editable Mode**:

## Configuration    Install the project in "editable" mode (`-e`). This allows you to make changes to the source code and see them reflected immediately without reinstalling.

    ```bash

### Security Rules    pip install -e .

Rules are defined in YAML files in the `rules/` directory:    ```



```yaml## 🤝 Contributing

- id: AWS-S3-001

  severity: HIGHContributions are welcome! Please feel free to open an issue to discuss a new feature or submit a pull request.

  description: "S3 bucket has public read access"

  resource: "aws_s3_bucket"## 📜 License

  attribute: "acl"

  value: "public-read"This project is licensed under the MIT License. See the `LICENSE` file for details.

```

### Cost Pricing Data
Pricing configurations are stored in `config/pricing/` directory:
- `aws_pricing.yaml` - AWS resource pricing
- `gcp_pricing.yaml` - GCP resource pricing
- `azure_pricing.yaml` - Azure resource pricing

Each pricing file includes:
- Resource pricing data
- Confidence scores (1-10 scale)
- Last verification dates
- Official documentation links
- Regional pricing multipliers

## Output Formats

### Table Format (Default)
Rich formatted tables with confidence scores and metadata.

### JSON Format
Machine-readable output for automation:
```bash
infraware cost-analysis file main.tf --format json > costs.json
```

### CSV Format
Spreadsheet-compatible output:
```bash
infraware cost-analysis file main.tf --format csv > costs.csv
```

## Regional Pricing

InfraWare supports region-aware pricing for accurate cost estimates:

```bash
# Compare costs across regions
infraware cost-analysis estimate aws aws_instance --type t3.medium --region us-east-1
infraware cost-analysis estimate aws aws_instance --type t3.medium --region eu-west-1
infraware cost-analysis estimate aws aws_instance --type t3.medium --region ap-southeast-1
```

## Data Quality Features

### Confidence Scoring
All pricing data includes confidence scores (1-10) indicating data accuracy:
- 10/10: Official provider pricing, recently verified
- 8-9: High confidence, official sources
- 6-7: Good confidence, may need verification
- 4-5: Medium confidence, estimated pricing
- 1-3: Low confidence, rough estimates

### Impact Levels
- `low`: Minimal cost impact
- `medium`: Moderate cost impact
- `high`: Significant cost impact
- `variable`: Cost depends on usage
- `fixed`: Fixed monthly cost

## Development Setup

1. Clone and enter directory:
```bash
git clone https://github.com/your-username/infraware.git
cd infraware
```

2. Create virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
```

3. Install in development mode:
```bash
pip install -e .
```

## Help and Documentation

Get help for any command:
```bash
infraware --help
infraware cost-analysis --help
infraware cost-analysis file --help
```

Detailed documentation is available in `docs/COST_ANALYSIS_GUIDE.md`.

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## License

This project is licensed under the MIT License. See the LICENSE file for details.