# InfraWare - Infrastructure Security and Cost Analysis Tool# <img src="assets/InfraWare.png" alt="InfraWare Logo" width="full"> InfraWare 🛡️ - Your IaC Security and Quality Scanner



InfraWare is a command-line tool for analyzing Infrastructure as Code (IaC) files. It provides security vulnerability scanning and comprehensive cost analysis for AWS, GCP, and Azure resources.InfraWare is a powerful, rule-based command-line tool designed to scan Infrastructure as Code (IaC) for security vulnerabilities, misconfigurations, and code quality issues. It analyzes Terraform plan files to provide the most accurate assessment of your planned infrastructure changes.



## What InfraWare Does![InfraWare Demo](https-placeholder-for-your-demo-gif.gif)

*(Tip: You can use a tool like [ScreenToGif](https://www.screentogif.com/) or [Peek](https://github.com/phw/peek) to create a simple GIF of your tool in action and replace the placeholder above.)*

- **Security Scanning**: Detect vulnerabilities and misconfigurations in Terraform files

- **Cost Analysis**: Calculate monthly costs for cloud resources with region-aware pricing## ✨ Key Features

- **Multiple Format Support**: Works with Terraform (.tf), JSON, and YAML files

- **Rule-Based Engine**: Extensible rules system with confidence scoring* **Accurate Plan Scanning**: Analyzes the JSON output of `terraform plan` to understand the exact state of your infrastructure, including modules and variables.

- **Professional CLI**: Clean command-line interface with detailed help* **Extensible Rule Engine**: Define security and quality checks in simple, human-readable YAML files.

* **Professional CLI**: A full-featured command-line interface with commands for scanning and rule management.

## Requirements* **Interactive Rule Creation**: Use `infraware rules create` to be guided through making new rules.

* **Rule Validation**: Use `infraware rules validate` to check your custom rule files for correct syntax.

- Python 3.8 or higher* **Ignore Findings**: Baseline your infrastructure by ignoring specific findings using simple ignore files.

- Terraform (for Terraform file analysis)* **Formatted Output**: Clean, color-coded console output makes it easy to spot issues.



## Installation## 📋 Prerequisites



1. Clone the repository:* [Python](https://www.python.org/downloads/) (version 3.8 or higher)

```bash* [Terraform](https://developer.hashicorp.com/terraform/downloads) (version 1.0 or higher)

git clone https://github.com/your-username/infraware.git

cd infraware## 🚀 Installation

```

To install and use the InfraWare CLI, follow these steps:

2. Install the package:

```bash1.  **Clone the Repository**:

pip install -e .    ```bash

```    git clone [https://github.com/your-username/infraware.git](https://github.com/your-username/infraware.git)

    cd infraware

3. Verify installation:    ```

```bash

infraware --help2.  **Install the Package**:

```    This command uses the `pyproject.toml` file to install the `infraware` command and its dependencies.

    ```bash

## Quick Start    pip install .

    ```

### Security Scanning

3.  **Verify Installation**:

1. Generate a Terraform plan:    Check that the command is available in your path.

```bash    ```bash

terraform plan -out=tfplan.binary    infraware --help

terraform show -json tfplan.binary > tfplan.json    ```

```

## 🔬 Usage Guide

2. Run security scan:

```bashInfraWare is designed to fit into your standard Terraform workflow.

infraware scan tfplan.json

```### Scanning a Terraform Project



### Cost Analysis1.  **Navigate to Your Terraform Project**:

    `cd` into the directory containing your `.tf` files.

1. Analyze infrastructure costs:

```bash2.  **Initialize Terraform**:

infraware cost-analysis file main.tf --region us-west-2    If you haven't already, initialize Terraform to download providers and modules.

```    ```bash

    terraform init

2. Estimate specific resources:    ```

```bash

infraware cost-analysis estimate aws aws_instance --type t3.medium3.  **Generate the JSON Plan**:

```    Create a binary plan file and convert it to a readable JSON format.

    ```bash

3. Check supported providers and regions:    terraform plan -out=tfplan.binary

```bash    terraform show -json tfplan.binary > tfplan.json

infraware cost-analysis providers    ```

```

4.  **Run the Scanner**:

## Available Commands    Now, use the `infraware` command to run the scan.

    ```bash

### Security Commands    infraware scan ./tfplan.json --rules-dir /path/to/your/rules --ignore-dir /path/to/your/ignores

- `infraware scan` - Scan files for security vulnerabilities    ```

- `infraware rules list` - List available security rules    **Example**:

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