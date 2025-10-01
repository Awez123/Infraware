# InfraWare Cost Analysis - Complete Command Reference

## 🚀 Overview

InfraWare Cost Analysis provides comprehensive cloud resource cost analysis with region-aware pricing, confidence scores, and metadata tracking for AWS, GCP, and Azure resources.

## 📋 Quick Reference

### Main Commands
- `infraware cost-analysis file` - Analyze infrastructure files
- `infraware cost-analysis providers` - List supported providers/regions  
- `infraware cost-analysis estimate` - Estimate specific resource costs
- `infraware cost-analysis metadata` - Show pricing metadata & sources
- `infraware cost-analysis confidence` - Display data quality reports

### Get Help
```bash
infraware cost-analysis --help              # Main help
infraware cost-analysis COMMAND --help     # Command-specific help
```

## 📁 Supported File Formats

| Extension | Description | Examples |
|-----------|-------------|----------|
| `.tf` | Terraform configuration files | `main.tf`, `variables.tf` |
| `.json` | Terraform plan JSON, infrastructure JSON | `tfplan.json`, `infrastructure.json` |
| `.yaml/.yml` | CloudFormation, Kubernetes, custom YAML | `template.yaml`, `deployment.yml` |

## ☁️ Supported Cloud Providers

### AWS (Amazon Web Services)
- **Resource Prefix**: `aws_*`
- **Common Resources**: `aws_instance`, `aws_ebs_volume`, `aws_s3_bucket`, `aws_db_instance`
- **Regions**: `us-east-1`, `us-west-2`, `eu-west-1`, `ap-southeast-1`, `ap-northeast-1`

### GCP (Google Cloud Platform)  
- **Resource Prefix**: `google_*`
- **Common Resources**: `google_compute_instance`, `google_compute_disk`, `google_storage_bucket`
- **Regions**: `us-central1`, `us-east1`, `europe-west1`, `asia-southeast1`, `asia-northeast1`

### Azure (Microsoft Azure)
- **Resource Prefix**: `azurerm_*`
- **Common Resources**: `azurerm_virtual_machine`, `azurerm_managed_disk`, `azurerm_storage_account`
- **Regions**: `eastus`, `westus2`, `westeurope`, `southeastasia`, `japaneast`

## 🗂️ File Analysis Commands

### Basic Analysis
```bash
# Analyze any infrastructure file
infraware cost-analysis file infrastructure.tf
infraware cost-analysis file terraform.tfplan.json
infraware cost-analysis file cloudformation.yaml
```

### Regional Pricing
```bash
# Specify target region for accurate pricing
infraware cost-analysis file main.tf --region us-west-2
infraware cost-analysis file plan.json --region eu-west-1
infraware cost-analysis file template.yaml --region ap-southeast-1
```

### Custom Usage Patterns
```bash
# Custom monthly usage hours (default: 730)
infraware cost-analysis file resources.tf --hours 500    # Part-time usage
infraware cost-analysis file production.tf --hours 730   # Full-time usage
infraware cost-analysis file dev.tf --hours 200          # Development usage
```

### Output Formats
```bash
# Table format (default) - Rich formatting with confidence scores
infraware cost-analysis file infrastructure.tf

# JSON format - For automation and scripting
infraware cost-analysis file infrastructure.tf --format json > costs.json

# CSV format - For spreadsheet analysis
infraware cost-analysis file infrastructure.tf --format csv > costs.csv
```

## 💰 Resource Estimation Commands

### AWS Examples
```bash
# EC2 instances
infraware cost-analysis estimate aws aws_instance --type t3.micro --region us-east-1
infraware cost-analysis estimate aws aws_instance --type t3.medium --region us-west-2
infraware cost-analysis estimate aws aws_instance --type m5.large --region eu-west-1

# EBS volumes
infraware cost-analysis estimate aws aws_ebs_volume --type gp3 --size 500 --region us-east-1
infraware cost-analysis estimate aws aws_ebs_volume --type io2 --size 1000 --region us-west-2

# RDS databases
infraware cost-analysis estimate aws aws_db_instance --type db.t3.micro --region us-east-1
infraware cost-analysis estimate aws aws_db_instance --type db.r5.large --region eu-west-1
```

### GCP Examples
```bash
# Compute instances
infraware cost-analysis estimate gcp google_compute_instance --type e2-micro --region us-central1
infraware cost-analysis estimate gcp google_compute_instance --type e2-medium --region europe-west1
infraware cost-analysis estimate gcp google_compute_instance --type n1-standard-1 --region asia-southeast1

# Persistent disks
infraware cost-analysis estimate gcp google_compute_disk --type pd-standard --size 500 --region us-central1
infraware cost-analysis estimate gcp google_compute_disk --type pd-ssd --size 1000 --region europe-west1
```

### Azure Examples
```bash
# Virtual machines
infraware cost-analysis estimate azure azurerm_virtual_machine --type Standard_B1s --region eastus
infraware cost-analysis estimate azure azurerm_virtual_machine --type Standard_B2s --region westus2
infraware cost-analysis estimate azure azurerm_virtual_machine --type Standard_D2s_v3 --region westeurope

# Managed disks
infraware cost-analysis estimate azure azurerm_managed_disk --type standard_lrs --size 500 --region eastus
infraware cost-analysis estimate azure azurerm_managed_disk --type premium_lrs --size 1000 --region westus2
```

### Custom Usage Hours
```bash
# Development environment (8 hours/day, 22 days/month = ~176 hours)
infraware cost-analysis estimate aws aws_instance --type t3.micro --hours 176

# Production environment (24/7 = 730 hours/month)  
infraware cost-analysis estimate aws aws_instance --type m5.large --hours 730

# Batch processing (12 hours/day, 30 days = 360 hours)
infraware cost-analysis estimate aws aws_instance --type c5.xlarge --hours 360
```

## 🌍 Provider and Region Commands

### List All Providers and Regions
```bash
infraware cost-analysis providers
```

This displays:
- All supported cloud providers
- Available regions for each provider  
- Region names and pricing multipliers

## 📊 Metadata and Quality Commands

### Provider Metadata
```bash
# Show provider-level metadata
infraware cost-analysis metadata aws
infraware cost-analysis metadata gcp  
infraware cost-analysis metadata azure
```

Displays:
- Last updated date
- Data source information
- Reference URLs
- Currency and confidence scale

### Resource-Specific Metadata
```bash
# Show metadata for specific resources
infraware cost-analysis metadata aws --resource aws_instance
infraware cost-analysis metadata gcp --resource google_compute_instance
infraware cost-analysis metadata azure --resource azurerm_virtual_machine
```

Displays:
- Resource category and billing model
- Confidence scores and impact levels
- Last verification date
- Tags and official documentation links

### Confidence Reports
```bash
# Show all confidence data
infraware cost-analysis confidence

# Filter by provider
infraware cost-analysis confidence --provider aws
infraware cost-analysis confidence --provider gcp

# Show only high-confidence data (9+ out of 10)
infraware cost-analysis confidence --min-confidence 9

# Show medium+ confidence (7+ out of 10)
infraware cost-analysis confidence --min-confidence 7
```

## 🎯 Confidence Score Scale

| Score | Description | Color |
|-------|-------------|-------|
| 10/10 | Official provider pricing, recently verified | 🟢 Green |
| 8-9   | High confidence, based on official sources | 🟢 Green |
| 6-7   | Good confidence, may need verification | 🟡 Yellow |
| 4-5   | Medium confidence, estimated pricing | 🟡 Yellow |
| 1-3   | Low confidence, rough estimates | 🔴 Red |

## 📈 Impact Levels

| Level | Description |
|-------|-------------|
| `low` | Minimal cost impact |
| `medium` | Moderate cost impact |
| `high` | Significant cost impact |
| `variable` | Cost depends on usage patterns |
| `fixed` | Fixed monthly cost |
| `none` | No cost (free resources) |

## 🔄 Regional Cost Comparison

Compare costs across different regions:

```bash
# Compare AWS instance costs across regions
infraware cost-analysis estimate aws aws_instance --type t3.medium --region us-east-1
infraware cost-analysis estimate aws aws_instance --type t3.medium --region us-west-2  
infraware cost-analysis estimate aws aws_instance --type t3.medium --region eu-west-1
infraware cost-analysis estimate aws aws_instance --type t3.medium --region ap-southeast-1

# Compare GCP costs
infraware cost-analysis estimate gcp google_compute_instance --type e2-medium --region us-central1
infraware cost-analysis estimate gcp google_compute_instance --type e2-medium --region europe-west1
infraware cost-analysis estimate gcp google_compute_instance --type e2-medium --region asia-southeast1
```

## 📤 Export and Automation

### JSON Export for Automation
```bash
# Export to JSON for further processing
infraware cost-analysis file infrastructure.tf --format json > costs.json

# Use in CI/CD pipelines
infraware cost-analysis file terraform.tfplan.json --format json | jq '.total_monthly_cost'
```

### CSV Export for Analysis
```bash
# Export to CSV for spreadsheet analysis
infraware cost-analysis file infrastructure.tf --format csv > monthly_costs.csv

# Import into Excel, Google Sheets, etc.
infraware cost-analysis file production.tf --region us-west-2 --format csv > prod_costs.csv
```

## 🏷️ Common Use Cases

### Infrastructure Planning
```bash
# Estimate costs before deployment
infraware cost-analysis file planned_infrastructure.tf --region target-region

# Compare different configurations
infraware cost-analysis estimate aws aws_instance --type t3.medium
infraware cost-analysis estimate aws aws_instance --type m5.large
```

### Cost Optimization
```bash
# Analyze current infrastructure costs
infraware cost-analysis file current_state.tf --region current-region

# Compare with optimized configurations
infraware cost-analysis file optimized_plan.tf --region target-region
```

### Budget Planning
```bash
# Generate monthly cost reports
infraware cost-analysis file infrastructure.tf --format csv > budget_planning.csv

# Estimate for different usage patterns
infraware cost-analysis file infrastructure.tf --hours 500  # Reduced usage
infraware cost-analysis file infrastructure.tf --hours 730  # Standard usage
```

### Data Quality Audits
```bash
# Check pricing data quality
infraware cost-analysis confidence --min-confidence 8

# Verify data sources
infraware cost-analysis metadata aws --resource aws_instance
```

## 🛠️ Configuration and Customization

The cost analysis system uses YAML configuration files located in `config/pricing/`:

- `aws_pricing.yaml` - AWS resource pricing and metadata
- `gcp_pricing.yaml` - GCP resource pricing and metadata  
- `azure_pricing.yaml` - Azure resource pricing and metadata

These files can be customized to:
- Update pricing to match your specific agreements
- Add new resource types
- Modify confidence scores and metadata
- Update reference URLs and documentation links

## 🚨 Legacy Commands (Deprecated)

These commands still work but show deprecation warnings:

```bash
infraware cost-analysis aws      # Use: infraware cost-analysis providers
infraware cost-analysis gcp      # Use: infraware cost-analysis providers  
infraware cost-analysis azure    # Use: infraware cost-analysis providers
infraware cost-analysis tf --file test.tf        # Use: infraware cost-analysis file test.tf
infraware cost-analysis plan --file plan.json    # Use: infraware cost-analysis file plan.json
```

## 💡 Tips and Best Practices

1. **Always specify regions** for accurate pricing
2. **Use confidence reports** to verify data quality
3. **Export to JSON/CSV** for automated processing
4. **Compare across regions** to optimize costs
5. **Check metadata** to understand data sources
6. **Update pricing configs** regularly for accuracy
7. **Use custom usage hours** for accurate estimates

For more help, use `infraware cost-analysis COMMAND --help` for any specific command.