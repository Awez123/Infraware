# InfraWare Docker Images

## Official Images

### Latest Release
```bash
docker pull awez123/infraware:latest
docker pull awez123/infraware:2.0.0
```

### Alpine (Lightweight)
```bash
docker pull awez123/infraware:alpine
docker pull awez123/infraware:2.0.0-alpine
```

## Usage

### Quick Scan
```bash
# Scan a local file
docker run --rm -v $(pwd):/workspace awez123/infraware:latest scan /workspace/terraform.json

# With custom rules
docker run --rm -v $(pwd):/workspace -v $(pwd)/rules:/rules awez123/infraware:latest scan /workspace/terraform.json --rules-dir /rules
```

### Cost Analysis
```bash
# Analyze costs
docker run --rm -v $(pwd):/workspace awez123/infraware:latest cost-analysis analyze /workspace/terraform.json --realtime

# Export results
docker run --rm -v $(pwd):/workspace awez123/infraware:latest cost-analysis analyze /workspace/terraform.json --format json > costs.json
```

### Interactive Mode
```bash
# Start interactive shell
docker run -it --rm -v $(pwd):/workspace awez123/infraware:latest /bin/bash

# Inside container
infraware scan /workspace/terraform.json
infraware cost-analysis analyze /workspace/terraform.json
```

### Web Interface
```bash
# Start web server
docker run -d -p 8080:8080 -v $(pwd):/workspace awez123/infraware:latest server start --port 8080

# Access at http://localhost:8080
```

## Docker Compose

```yaml
version: '3.8'
services:
  infraware:
    image: awez123/infraware:latest
    volumes:
      - ./infrastructure:/workspace
      - ./rules:/rules
      - ./ignores:/ignores
    ports:
      - "8080:8080"
    command: server start --port 8080
    environment:
      - INFRAWARE_RULES_DIR=/rules
      - INFRAWARE_IGNORE_DIR=/ignores
```

## Building Custom Images

### From Source
```bash
git clone https://github.com/Awez123/Infraware.git
cd Infraware
docker build -t my-infraware .
```

### With Custom Rules
```dockerfile
FROM awez123/infraware:latest
COPY custom-rules/ /opt/infraware/rules/
ENV INFRAWARE_RULES_DIR=/opt/infraware/rules/
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `INFRAWARE_DB_PATH` | CVE database location | `/tmp/cve_database.db` |
| `INFRAWARE_RULES_DIR` | Custom rules directory | `/opt/infraware/rules` |
| `INFRAWARE_IGNORE_DIR` | Ignore patterns directory | `/opt/infraware/ignores` |
| `INFRAWARE_CACHE_DIR` | Cache directory | `/tmp/infraware-cache` |

## CI/CD Integration

### GitHub Actions
```yaml
- name: InfraWare Security Scan
  run: |
    docker run --rm -v ${{ github.workspace }}:/workspace \
      awez123/infraware:latest scan /workspace/terraform.json --format json
```

### GitLab CI
```yaml
infraware:
  image: awez123/infraware:latest
  script:
    - infraware scan terraform.json --format json
  artifacts:
    reports:
      junit: infraware-results.xml
```

## Troubleshooting

### Permission Issues
```bash
# Fix file permissions
docker run --rm -v $(pwd):/workspace --user $(id -u):$(id -g) awez123/infraware:latest scan /workspace/terraform.json
```

### Network Issues
```bash
# Use host network
docker run --rm --network host -v $(pwd):/workspace awez123/infraware:latest scan /workspace/terraform.json
```

### Debugging
```bash
# Enable debug mode
docker run --rm -v $(pwd):/workspace awez123/infraware:latest --debug scan /workspace/terraform.json

# Check container logs
docker logs <container-id>
```