# InfraWare - Enterprise Infrastructure Security & Cost Platform# InfraWare - Enterprise Infrastructure Security & Cost Platform



[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

[![CLI Tool](https://img.shields.io/badge/CLI-Tool-green.svg)](https://github.com/Awez123/Infraware)[![CLI Tool](https://img.shields.io/badge/CLI-Tool-green.svg)](https://github.com/Awez123/Infraware)



> 🛡️ **Real-time infrastructure security scanning, cost analysis, and vulnerability management for multi-cloud environments**> 🛡️ **Real-time infrastructure security scanning, cost analysis, and vulnerability management for multi-cloud environments**



## 🚀 Quick Start## 🚀 Quick Start



### Installation### Installation



```bash```bash

# Install from PyPI (recommended)# Install from PyPI (recommended)

pip install infrawarepip install infraware



# Or install from source# Or install from source

git clone https://github.com/Awez123/Infraware.gitgit clone https://github.com/Awez123/Infraware.git

cd Infrawarecd Infraware

pip install -e .pip install -e .

``````



### First Scan### First Scan



```bash```bash

# Scan your Terraform plan# Scan your Terraform plan

infraware scan terraform.jsoninfraware scan terraform.json



# Analyze costs in real-time# Analyze costs in real-time

infraware cost-analysis analyze terraform.json --realtimeinfraware cost-analysis analyze terraform.json --realtime



# Check CVE database# Check CVE database

infraware cve statsinfraware cve stats

``````



## 📋 Prerequisites## 📋 Prerequisites



- **Python 3.8+**- **Python 3.8+**

- **Internet connection** (for real-time pricing and CVE updates)- **Internet connection** (for real-time pricing and CVE updates)

- **Terraform files** (.tf, .json) or **CloudFormation** (.yaml, .json)- **Terraform files** (.tf, .json) or **CloudFormation** (.yaml, .json)



## 🛠️ Installation Methods## 🛠️ Installation Methods



### Method 1: PyPI Installation (Recommended)### Method 1: PyPI Installation (Recommended)

```bash```bash

pip install infrawarepip install infraware

infraware welcome  # Verify installationinfraware welcome  # Verify installation

``````



### Method 2: Homebrew (macOS/Linux)### Method 2: Homebrew (macOS/Linux)

```bash```bash

brew tap awez123/infrawarebrew tap awez123/infraware

brew install infrawarebrew install infraware

``````



### Method 3: Binary Downloads### Method 3: Binary Downloads

Download pre-compiled binaries from [Releases](https://github.com/Awez123/Infraware/releases)Download pre-compiled binaries from [Releases](https://github.com/Awez123/Infraware/releases)



### Method 4: Docker### Method 4: Docker

```bash```bash

docker run -v $(pwd):/workspace awez123/infraware scan /workspace/terraform.jsondocker run -v $(pwd):/workspace awez123/infraware scan /workspace/terraform.json

``````



### Method 5: From Source### Method 5: From Source

```bash```bash

git clone https://github.com/Awez123/Infraware.gitgit clone https://github.com/Awez123/Infraware.git

cd Infrawarecd Infraware

pip install -e .pip install -e .

``````



## 🎯 Core Features## 🎯 Core Features



### 🛡️ Security Scanning### 🛡️ Security Scanning

```bash```bash

# Basic security scan

infraware scan infrastructure.json# Scan Terraform plan for security issues# Scan Terraform plan for security issues



# Comprehensive analysis with all checksinfraware scan terraform-plan.jsoninfraware scan terraform-plan.json

infraware scan infrastructure.json --comprehensive



# Filter by severity

infraware scan infrastructure.json --severity HIGH# Comprehensive security scan with CVE correlation# Comprehensive security scan with CVE correlation



# Custom rules directoryinfraware comprehensive ./infrastructureinfraware comprehensive ./infrastructure

infraware scan infrastructure.json --rules-dir ./custom-rules/



# JSON output for CI/CD integration

infraware scan infrastructure.json --format json# Update CVE database# Update CVE database

```

infraware cve-updateinfraware cve-update

### 💰 Cost Analysis

```bash

# Real-time cost analysis

infraware cost-analysis analyze infrastructure.json --realtime# View database statistics# View database statistics



# Regional pricinginfraware cve-statsinfraware cve-stats

infraware cost-analysis analyze infrastructure.json --region us-west-2

``````

# Cost breakdown with optimization

infraware cost-analysis analyze infrastructure.json --breakdown --optimize



# Multi-cloud comparison## 🎯 Key Features

infraware cost-analysis analyze infrastructure.json --compare

```



### 🔍 CVE Management### 🔍 Infrastructure Security## 🚀 Key Features## 🚀 Key Features

```bash

# Download CVE database- **Multi-Cloud IaC Scanning**: Terraform, CloudFormation, Kubernetes YAML

infraware cve download

- **CVE Integration**: 10,000+ vulnerabilities with real-time updates

# Check database stats

infraware cve stats- **Risk Scoring**: Advanced severity assessment and scoring



# Search for specific vulnerabilities- **Compliance Mapping**: CIS Controls and industry standards### 🔍 Infrastructure Security### 🔍 Infrastructure Security

infraware cve search "RDS encryption"

- **35+ AWS Security Rules**: Comprehensive coverage across RDS, EC2, IAM, Lambda, ELB, CloudTrail, KMS

# Research specific CVE- **Multi-Cloud IaC Scanning**: Terraform, CloudFormation, Kubernetes YAML

infraware cve research CVE-2023-12345- **CVE Integration**: 10,000+ vulnerabilities with real-time updates

```- **Risk Scoring**: Advanced severity assessment and scoring

- **Secret Detection**: Hardcoded credentials and sensitive data identification

### 🌐 Web Interface- **Compliance Mapping**: CIS Controls and industry standards

```bash

# Start web dashboard### 💰 Cost Analysis

infraware server start

- **Multi-Cloud Cost Estimation**: AWS, Azure, GCP pricing

# Custom port- **Resource Optimization**: Cost-aware security recommendations

infraware server start --port 8080- **Regional Pricing**: Location-specific cost calculations

- **Usage-Based Modeling**: Flexible time-based cost projections

# API-only mode

infraware server api### 🔄 Real-Time Intelligence

```

- **CVE Database**: Auto-updating vulnerability intelligence from NVD and GitHub

## 📁 Supported File Formats- **Threat Correlation**: Infrastructure resources mapped to known vulnerabilities

- **Security Scoring**: Dynamic risk assessment based on current threat landscape

| Format | Extension | Description |

|--------|-----------|-------------|## 📋 Command Reference

| Terraform Plans | `.json` | `terraform plan -out=plan.json && terraform show -json plan.json > plan.json` |

| Terraform Files | `.tf` | Raw Terraform configuration files |

| CloudFormation | `.yaml`, `.yml`, `.json` | AWS CloudFormation templates |

| Kubernetes | `.yaml`, `.yml` | Kubernetes manifests || Command | Description | Example |



## 🔧 Configuration|---------|-------------|---------|



### Environment Variables| `scan` | Infrastructure vulnerability scanning | `infraware scan plan.json` |### 💰 Cost Analysis### 💰 Cost Analysis

```bash

# API Keys (optional - uses free tiers by default)| `comprehensive` | Multi-faceted security scan | `infraware comprehensive ./infrastructure` |

export INFRAWARE_AWS_ACCESS_KEY=your_key

export INFRAWARE_AZURE_SUBSCRIPTION_ID=your_id| `cost-analysis` | Cloud cost estimation | `infraware cost-analysis plan.tf --region us-east-1` |- **Multi-Cloud Cost Estimation**: AWS, Azure, GCP pricing- **Multi-Cloud Cost Estimation**: AWS, Azure, GCP pricing

export INFRAWARE_GCP_PROJECT_ID=your_project

| `cve-update` | Update CVE database | `infraware cve-update` |

# Database location

export INFRAWARE_DB_PATH=~/.infraware/database.db| `cve-bulk-download` | Download enterprise CVE database | `infraware cve-bulk-download` |- **Resource Optimization**: Cost-aware security recommendations- **Resource Optimization**: Cost-aware security recommendations



# Custom rules directory| `cve-search` | Search CVE database | `infraware cve-search "kubernetes" --severity CRITICAL` |

export INFRAWARE_RULES_DIR=~/.infraware/rules/

```| `cve-stats` | CVE database statistics | `infraware cve-stats` |- **Regional Pricing**: Location-specific cost calculations- **Regional Pricing**: Location-specific cost calculations



### Configuration File| `container-scan` | Container image scanning | `infraware container-scan alpine:latest` |

Create `~/.infraware/config.yaml`:

```yaml| `dockerfile-scan` | Dockerfile security analysis | `infraware dockerfile-scan Dockerfile` |- **Usage-Based Modeling**: Flexible time-based cost projections- **Usage-Based Modeling**: Flexible time-based cost projections

# InfraWare Configuration

database:| `container-runtime` | Running container analysis | `infraware container-runtime web-app` |

  path: "~/.infraware/cve_database.db"

  auto_update: true| `secrets` | Secret detection | `infraware secrets ./src --format json` |



pricing:

  cache_ttl: 3600  # 1 hour

  fallback_enabled: true## 🔧 Detailed Usage Examples### 🔄 Real-Time Intelligence### 🔄 Real-Time Intelligence

  regions:

    - us-east-1

    - us-west-2

    - eu-west-1### Infrastructure Scanning- **CVE Database**: Auto-updating vulnerability intelligence from NVD and GitHub- **CVE Database**: Auto-updating vulnerability intelligence from NVD and GitHub



scanning:

  default_severity: "MEDIUM"

  max_files: 100#### Basic Terraform Scan- **Threat Correlation**: Infrastructure resources mapped to known vulnerabilities- **Threat Correlation**: Infrastructure resources mapped to known vulnerabilities

  timeout: 300

```bash

rules:

  custom_dir: "~/.infraware/rules/"# Generate Terraform plan and scan- **Security Scoring**: Dynamic risk assessment based on current threat landscape- **Security Scoring**: Dynamic risk assessment based on current threat landscape

  ignore_dir: "~/.infraware/ignores/"

```terraform plan -out=tfplan.binary



## 🔄 CI/CD Integrationterraform show -json tfplan.binary > tfplan.json



### GitHub Actionsinfraware scan tfplan.json

```yaml

name: InfraWare Security Scan```## 📦 Installation*(Tip: You can use a tool like [ScreenToGif](https://www.screentogif.com/) or [Peek](https://github.com/phw/peek) to create a simple GIF of your tool in action and replace the placeholder above.)*

on: [push, pull_request]



jobs:

  security-scan:#### Comprehensive AWS Security Scan

    runs-on: ubuntu-latest

    steps:```bash

      - uses: actions/checkout@v3

      - name: Setup Python# Scan with comprehensive AWS security rules (35+ rules)```bash- **Security Scanning**: Detect vulnerabilities and misconfigurations in Terraform files

        uses: actions/setup-python@v4

        with:infraware scan comprehensive_aws_test.json

          python-version: '3.9'

      # Clone the repository

      - name: Install InfraWare

        run: pip install infraware# Expected output: Detection of 27 vulnerabilities across:

      

      - name: Generate Terraform Plan# - RDS instances (encryption, public access, backups)git clone https://github.com/ikramhyderi/Infraware.git- **Cost Analysis**: Calculate monthly costs for cloud resources with region-aware pricing## ✨ Key Features

        run: |

          terraform init# - EC2 instances (monitoring, IMDSv2, encryption)

          terraform plan -out=plan.out

          terraform show -json plan.out > plan.json# - IAM policies (admin access, overprivileged users)cd Infraware

      

      - name: Security Scan# - Lambda functions (DLQ, roles, VPC, encryption)

        run: infraware scan plan.json --format json --severity HIGH

      # - ALB/ELB (HTTPS, logging, redirects)- **Multiple Format Support**: Works with Terraform (.tf), JSON, and YAML files

      - name: Cost Analysis

        run: infraware cost-analysis analyze plan.json --realtime# - CloudTrail (logging, encryption, validation)

```

# - KMS/Secrets (rotation, encryption)# Install dependencies

### GitLab CI

```yaml```

infraware_scan:

  stage: securitypip install -r requirements.txt- **Rule-Based Engine**: Extensible rules system with confidence scoring* **Accurate Plan Scanning**: Analyzes the JSON output of `terraform plan` to understand the exact state of your infrastructure, including modules and variables.

  image: python:3.9

  script:#### Multi-Format Support

    - pip install infraware

    - terraform plan -out=plan.out```bash

    - terraform show -json plan.out > plan.json

    - infraware scan plan.json --format json# Terraform JSON

  artifacts:

    reports:infraware scan infrastructure.json# Install InfraWare- **Professional CLI**: Clean command-line interface with detailed help* **Extensible Rule Engine**: Define security and quality checks in simple, human-readable YAML files.

      junit: infraware-results.xml

```



### Jenkins Pipeline# CloudFormation YAMLpip install -e .

```groovy

pipeline {infraware scan cloudformation-template.yaml

    agent any

    stages {```* **Professional CLI**: A full-featured command-line interface with commands for scanning and rule management.

        stage('InfraWare Scan') {

            steps {# Kubernetes YAML

                sh 'pip install infraware'

                sh 'terraform plan -out=plan.out'infraware scan k8s-deployment.yaml

                sh 'terraform show -json plan.out > plan.json'

                sh 'infraware scan plan.json --format json > scan-results.json'```

                archiveArtifacts artifacts: 'scan-results.json'

            }## 🎯 Quick Start## Requirements* **Interactive Rule Creation**: Use `infraware rules create` to be guided through making new rules.

        }

    }### CVE Database Operations

}

```



## 🧪 Examples#### Update Database



### Scanning AWS Infrastructure```bash### Infrastructure Scanning* **Rule Validation**: Use `infraware rules validate` to check your custom rule files for correct syntax.

```bash

# Generate Terraform plan# Quick update (recent CVEs)

terraform plan -out=aws-plan.out

terraform show -json aws-plan.out > aws-plan.jsoninfraware cve-update```bash



# Scan for security issues

infraware scan aws-plan.json --comprehensive

# Force update# Scan Terraform plan- Python 3.8 or higher* **Ignore Findings**: Baseline your infrastructure by ignoring specific findings using simple ignore files.

# Analyze costs

infraware cost-analysis analyze aws-plan.json --region us-east-1 --breakdowninfraware cve-update --force

```

infraware scan terraform-plan.json

### Multi-Cloud Cost Comparison

```bash# Enterprise download (100K+ CVEs, 3 years)

# Scan multi-cloud infrastructure

infraware cost-analysis analyze multi-cloud-plan.json --compare --optimizeinfraware cve-bulk-download- Terraform (for Terraform file analysis)* **Formatted Output**: Clean, color-coded console output makes it easy to spot issues.



# Output with cost breakdown```

infraware cost-analysis analyze multi-cloud-plan.json --format json --breakdown

```# Scan with JSON output



### Custom Security Rules#### Search and Statistics

```bash

# Create custom rules directory```bashinfraware scan infrastructure.tf --format json

mkdir -p ~/.infraware/rules/

# Search for specific vulnerabilities

# Add custom rule file

cat > ~/.infraware/rules/custom-s3.yaml << EOFinfraware cve-search "apache" --severity HIGH --limit 10```

rules:

  - id: CUSTOM-S3-001

    title: "S3 Bucket Custom Policy"

    severity: HIGH# Search by technology## Installation## 📋 Prerequisites

    resource_type: aws_s3_bucket

    condition: bucket_policy_missinginfraware cve-search "kubernetes" --severity CRITICAL

EOF

### Cost Analysis

# Scan with custom rules

infraware scan terraform.json --rules-dir ~/.infraware/rules/# View database statistics

```

infraware cve-stats```bash

## 🐛 Troubleshooting



### Common Issues

# Expected output:# Analyze costs for AWS us-east-1

#### Installation Problems

```bash# Total CVEs: 12,547

# Update pip first

pip install --upgrade pip# Recent CVEs (30 days): 234infraware cost-analysis terraform-plan.tf --region us-east-1 --hours 7201. Clone the repository:* [Python](https://www.python.org/downloads/) (version 3.8 or higher)



# Install with user flag# Database Size: 45.2 MB

pip install --user infraware

# Severity Distribution: Critical(15%), High(25%), Medium(45%), Low(15%)

# Force reinstall

pip install --force-reinstall infraware```

```

# Multi-cloud cost analysis```bash* [Terraform](https://developer.hashicorp.com/terraform/downloads) (version 1.0 or higher)

#### Permission Issues

```bash### Container Security

# Linux/macOS

sudo chown -R $USER ~/.infraware/infraware cost-analysis multi-cloud.json --provider aws --region us-west-2



# Windows#### Container Image Scanning

icacls "%USERPROFILE%\.infraware" /grant "%USERNAME%":F /T

``````bash```git clone https://github.com/your-username/infraware.git



#### Network Issues# Scan Docker image

```bash

# Check connectivityinfraware container-scan nginx:latest

infraware cve download --debug



# Use offline mode

infraware scan terraform.json --offline# Scan with layer analysis### CVE Database Operationscd infraware## 🚀 Installation

```

infraware container-scan ubuntu:20.04 --layers

### Debug Mode

```bash```bash

# Enable verbose logging

infraware --debug scan terraform.json# Output to JSON



# Check configurationinfraware container-scan alpine:3.14 --format json# Update CVE database```

infraware config validate

```

# Database diagnostics

infraware cve stats --verboseinfraware cve-update

```

#### Dockerfile Analysis

## 🤝 Contributing

```bashTo install and use the InfraWare CLI, follow these steps:

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

# Scan Dockerfile for security issues

### Development Setup

```bashinfraware dockerfile-scan Dockerfile# Search for specific vulnerabilities

git clone https://github.com/Awez123/Infraware.git

cd Infraware

python -m venv venv

source venv/bin/activate  # Linux/macOS# Common findings:infraware cve-search "apache" --severity HIGH --limit 52. Install the package:

# or

venv\Scripts\activate  # Windows# - Running as root user

pip install -e ".[dev]"

pre-commit install# - Using ADD instead of COPY

```

# - No health check defined

### Running Tests

```bash# - Hardcoded secrets# View database statistics```bash1.  **Clone the Repository**:

pytest tests/

pytest tests/ --cov=infraware```

```

infraware cve-stats

## 📜 License

#### Runtime Container Security

MIT License - see [LICENSE](LICENSE) file for details.

```bash```pip install -e .    ```bash

## 🔗 Links

# Scan running container

- **Documentation**: [https://infraware.readthedocs.io](https://infraware.readthedocs.io)

- **Issues**: [https://github.com/Awez123/Infraware/issues](https://github.com/Awez123/Infraware/issues)infraware container-runtime container-name

- **Discussions**: [https://github.com/Awez123/Infraware/discussions](https://github.com/Awez123/Infraware/discussions)

- **Security**: [SECURITY.md](SECURITY.md)



## ⭐ Star History# Scan by container ID### Container Security```    git clone [https://github.com/your-username/infraware.git](https://github.com/your-username/infraware.git)



[![Star History Chart](https://api.star-history.com/svg?repos=Awez123/Infraware&type=Date)](https://star-history.com/#Awez123/Infraware&Date)infraware container-runtime abc123def456



---``````bash



**Made with ❤️ by the InfraWare Team**

### Secret Detection# Scan Dockerfile for security issues    cd infraware



```bashinfraware dockerfile-scan Dockerfile

# Scan directory for secrets

infraware secrets ./src3. Verify installation:    ```



# Scan specific file# Comprehensive container scan

infraware secrets config.py

infraware container-scan nginx:latest```bash

# Output to JSON

infraware secrets ./app --format json



# Common findings:# Runtime container analysisinfraware --help2.  **Install the Package**:

# - API keys in configuration files

# - Database passwords in source codeinfraware container-runtime container-id

# - OAuth tokens in environment files

# - SSH keys in repositories``````    This command uses the `pyproject.toml` file to install the `infraware` command and its dependencies.

```



### Cost Analysis

### Secret Detection    ```bash

```bash

# Analyze Terraform file costs```bash

infraware cost-analysis file main.tf --region us-east-1

# Scan directory for secrets## Quick Start    pip install .

# Estimate specific resource costs

infraware cost-analysis estimate aws aws_instance --type t3.medium --region us-west-2infraware secrets /path/to/code



# Multi-cloud cost comparison    ```

infraware cost-analysis estimate gcp google_compute_instance --type e2-medium

infraware cost-analysis estimate azure azurerm_virtual_machine --type Standard_B2s# Comprehensive security scan



# Export cost analysisinfraware comprehensive terraform-plan.json### Security Scanning

infraware cost-analysis file infrastructure.tf --format json > costs.json

infraware cost-analysis file infrastructure.tf --format csv > costs.csv```

```

3.  **Verify Installation**:

### Comprehensive Security Scanning

## 📊 Command Reference

```bash

# Complete security assessment1. Generate a Terraform plan:    Check that the command is available in your path.

infraware comprehensive ./infrastructure

| Command | Purpose | Example |

# Includes:

# - Infrastructure vulnerability scanning|---------|---------|---------|```bash    ```bash

# - Secret detection

# - CVE correlation| `scan` | Infrastructure vulnerability scanning | `infraware scan plan.json` |

# - Security scoring

# - Recommendations| `cost-analysis` | Cloud cost estimation | `infraware cost-analysis plan.tf --hours 720` |terraform plan -out=tfplan.binary    infraware --help



# Output to JSON for automation| `cve-update` | Update CVE database | `infraware cve-update` |

infraware comprehensive ./project --format json

```| `cve-search` | Search CVE database | `infraware cve-search "kubernetes" --severity CRITICAL` |terraform show -json tfplan.binary > tfplan.json    ```



## 🛡️ AWS Security Coverage| `cve-stats` | CVE database statistics | `infraware cve-stats` |



InfraWare provides comprehensive AWS security scanning with **35+ security rules** across major services:| `container-scan` | Container image scanning | `infraware container-scan alpine:latest` |```



### RDS Security (5 rules)| `dockerfile-scan` | Dockerfile security analysis | `infraware dockerfile-scan Dockerfile` |

- ✅ Database encryption at rest

- ✅ Public accessibility checks| `container-runtime` | Running container analysis | `infraware container-runtime web-app` |## 🔬 Usage Guide

- ✅ Backup retention validation

- ✅ Multi-AZ deployment| `secrets` | Secret detection | `infraware secrets ./src --format json` |

- ✅ Default port usage

| `comprehensive` | Multi-faceted security scan | `infraware comprehensive infrastructure/` |2. Run security scan:

### EC2 Security (4 rules)

- ✅ Detailed monitoring

- ✅ IMDSv2 enforcement

- ✅ Root volume encryption## 📈 Comparison with Trivy```bashInfraWare is designed to fit into your standard Terraform workflow.

- ✅ Public IP assignment



### IAM Security (5 rules)

- ✅ Admin access detection| Feature | InfraWare | Trivy | Advantage |infraware scan tfplan.json

- ✅ Wildcard permissions

- ✅ External ID validation|---------|-----------|-------|-----------|

- ✅ Programmatic access keys

- ✅ Unused credentials| **CVE Database** | 2,000+ (growing) | 180,000+ | Trivy (larger) |```### Scanning a Terraform Project



### Lambda Security (5 rules)| **IaC Scanning** | Advanced Terraform/CF | Basic IaC support | InfraWare |

- ✅ Dead letter queue configuration

- ✅ Role permissions review| **Cost Analysis** | ✅ Multi-cloud | ❌ Not available | InfraWare |

- ✅ VPC configuration

- ✅ Environment variable encryption| **Container Security** | ✅ Full platform | ✅ Excellent | Tie |

- ✅ Memory allocation optimization

| **Real-time Updates** | ✅ Auto-updating | ✅ Regular updates | Tie |### Cost Analysis1.  **Navigate to Your Terraform Project**:

### ELB/ALB Security (5 rules)

- ✅ HTTPS listener enforcement| **Enterprise Features** | ✅ Cost + Security | ✅ SBOM, attestation | Tie |

- ✅ Access logging

- ✅ HTTP to HTTPS redirects    `cd` into the directory containing your `.tf` files.

- ✅ Security group configuration

- ✅ SSL/TLS policy validation## 🏗️ Architecture



### Logging Security (5 rules)1. Analyze infrastructure costs:

- ✅ CloudTrail enablement

- ✅ Log encryptionInfraWare uses a hybrid approach for maximum effectiveness:

- ✅ Log file validation

- ✅ CloudWatch retention```bash2.  **Initialize Terraform**:

- ✅ Monitoring configuration

### External Database Commands (Real-time)

### KMS/Secrets Security (4 rules)

- ✅ Key rotation policies- `cve-update`, `cve-search`, `cve-stats` - NVD, GitHub Security Advisoriesinfraware cost-analysis file main.tf --region us-west-2    If you haven't already, initialize Terraform to download providers and modules.

- ✅ Secret rotation

- ✅ Encryption configuration- `container-scan`, `container-runtime` - Docker APIs, package managers

- ✅ Access policies

```    ```bash

## 📊 Output Examples

### Local Database Commands (Fast & Offline)

### Security Scan Results

```- `scan` - Local security rules (rules/*.yaml)    terraform init

🛡️ Security Scan Summary

Total Vulnerabilities: 27- `cost-analysis` - Local pricing data (config/pricing/*.yaml)

Risk Score: 5.0/10.0

- `dockerfile-scan`, `secrets` - Hardcoded patterns for speed2. Estimate specific resources:    ```

Severity Distribution:

  🔴 Critical: 2

  🟠 High: 5

  🟡 Medium: 16## 🤝 Contributing```bash

  🔵 Low: 4



🚨 CRITICAL VULNERABILITIES:

- AWS-IAM-001: IAM User With Full Admin Access1. Fork the repositoryinfraware cost-analysis estimate aws aws_instance --type t3.medium3.  **Generate the JSON Plan**:

- AWS-RDS-002: RDS Instance Publicly Accessible

```2. Create a feature branch (`git checkout -b feature/amazing-feature`)



### CVE Database Statistics3. Commit your changes (`git commit -m 'Add amazing feature'`)```    Create a binary plan file and convert it to a readable JSON format.

```

📊 CVE Database Statistics4. Push to the branch (`git push origin feature/amazing-feature`)

Total CVEs: 12,547

Recent CVEs (30 days): 2345. Open a Pull Request    ```bash

Database Size: 45.2 MB

Last Update: 2025-10-03 14:30:15



Severity Distribution:## 📄 License3. Check supported providers and regions:    terraform plan -out=tfplan.binary

Critical: 1,854 (15%)

High: 3,137 (25%)

Medium: 5,646 (45%)

Low: 1,910 (15%)This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.```bash    terraform show -json tfplan.binary > tfplan.json

```



## 🔧 Getting Help

## 👥 Authorsinfraware cost-analysis providers    ```

Every command has detailed help available:



```bash

# General help- **Awez Ahmed Khan** - *Initial work* - awezkhan786jb@gmail.com```

infraware --help

- **Ikram Hyderi** - *Enhanced development* - mdikramhyderi@gmail.com

# Command-specific help

infraware scan --help4.  **Run the Scanner**:

infraware cve-update --help

infraware cost-analysis --help## 🙏 Acknowledgments

infraware comprehensive --help

```## Available Commands    Now, use the `infraware` command to run the scan.



## 📁 File Format Support- **NIST NVD** for vulnerability data



### Supported Infrastructure Files- **GitHub Security Advisories** for threat intelligence    ```bash

- `.tf` - Terraform configuration files

- `.json` - Terraform plan files, infrastructure JSON- **Cloud providers** for pricing transparency

- `.yaml/.yml` - CloudFormation templates, Kubernetes manifests

- **Open source community** for continuous improvement### Security Commands    infraware scan ./tfplan.json --rules-dir /path/to/your/rules --ignore-dir /path/to/your/ignores

### Supported Cloud Providers

- **AWS** - Amazon Web Services (aws_* resources)

- **GCP** - Google Cloud Platform (google_* resources) 

- **Azure** - Microsoft Azure (azurerm_* resources)---- `infraware scan` - Scan files for security vulnerabilities    ```



## 🤝 Contributing



1. Fork the repository*InfraWare: Where Infrastructure Security Meets Cost Intelligence* 🚀- `infraware rules list` - List available security rules    **Example**:

2. Create a feature branch (`git checkout -b feature/amazing-feature`)

3. Commit your changes (`git commit -m 'Add amazing feature'`)- `infraware rules validate` - Validate rule files    ```bash

4. Push to the branch (`git push origin feature/amazing-feature`)

5. Open a Pull Request- `infraware rules create` - Create new security rules    infraware scan ./tfplan.json --rules-dir ~/dev/infraware/rules --ignore-dir ./infraware-ignores



## 📄 License    ```



This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.### Cost Analysis Commands



## 👥 Authors- `infraware cost-analysis file` - Analyze costs from infrastructure files### Managing Rules



- **Awez Ahmed Khan** - *Initial work* - awezkhan786jb@gmail.com- `infraware cost-analysis estimate` - Estimate costs for specific resources

- **Ikram Hyderi** - *Enhanced development* - mdikramhyderi@gmail.com

- `infraware cost-analysis providers` - List supported cloud providers and regionsInfraWare includes a full suite of commands to help you manage your rules.

## 🙏 Acknowledgments

- `infraware cost-analysis metadata` - Show pricing data sources

- **NIST NVD** for vulnerability data

- **GitHub Security Advisories** for threat intelligence- `infraware cost-analysis confidence` - Display data quality reports#### **Listing Rules**

- **Cloud providers** for pricing transparency

- **Open source community** for continuous improvementSee all rules in a directory in a clean table format.



---## File Format Support```bash



*InfraWare: Where Infrastructure Security Meets Cost Intelligence* 🚀infraware rules list --rules-dir ./my-rules

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