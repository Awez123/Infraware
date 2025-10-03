# 🚀 InfraWare Quick Start Guide

## 📥 **Getting Started with CVE Database**

When you first clone InfraWare, you'll start with an empty CVE database. Here's how to get enterprise-grade vulnerability intelligence:

### ⚡ **Quick Setup (30 seconds)**
```bash
# Install dependencies
pip install -r requirements.txt

# Install InfraWare
pip install -e .

# Test with current CVEs (small download)
infraware cve-update
```

### 🔥 **Enterprise Setup (15-20 minutes)**
```bash
# Download full enterprise database (100K+ CVEs)
infraware cve-bulk-download

# Verify enterprise database
infraware cve-stats
```

### 📊 **Expected Results:**

| Setup Type | CVEs | Database Size | Time | Use Case |
|------------|------|---------------|------|----------|
| **Quick** | ~2-5K | 3-5 MB | 30 sec | Testing, demos |
| **Enterprise** | ~100K+ | 135+ MB | 15-20 min | Production, comprehensive |

### 🛡️ **Verify Installation:**
```bash
# Check database status
infraware cve-stats

# Test vulnerability search
infraware cve-search "kubernetes" --limit 5

# Test infrastructure scanning
infraware scan test_terraform_code/tfplan.json
```

### 💡 **Pro Tips:**
- Run `infraware welcome` to see all available commands
- Use `infraware cve-update` for regular updates (daily/weekly)
- The database updates automatically from NVD, GitHub Security, and MITRE
- No internet required for scanning once database is downloaded

### 🔄 **Regular Updates:**
```bash
# Update with latest CVEs (recommended weekly)
infraware cve-update --force
```

---

🎉 **You're ready to scan infrastructure with enterprise-grade vulnerability intelligence!**