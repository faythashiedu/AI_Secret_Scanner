# 🛡️ EnvGuard

**Never commit API keys again.**

Secrets Security scanner for AI/ML projects. Detects exposed OpenAI, Anthropic, HuggingFace, AWS, and 10+ other API keys before they reach your repository.


## How to Use

### Install

```bash
pip install aisecretscanner
```

### Scan

```bash
aisecretscanner
```

That's it. **Zero configuration required.**

---

## 🎯 Why AI Secret Scanner?

Every developer has done this at least once:

```python
# ❌ Committed to GitHub
OPENAI_API_KEY = "sk-proj-abc123..."
```

One mistake = **$10,000 bill** from scrapers. This product prevents this.

### The Problem

- Exposed API keys cost developers **$500M+ annually**
- AI API keys are particularly valuable (OpenAI, Anthropic, etc.)
- Generic scanners miss AI-specific patterns
- Detection happens **after** the damage is done

### The Solution

```bash
$ aisecretscanner

╔═══════════════════════════════════════════════════════════╗
║     EnvGuard - AI API Key Security Scanner                ║
║      Never commit API keys again                          ║
╚═══════════════════════════════════════════════════════════╝

🔍 Scanning project...

 Found 3 exposed secret(s)!

[CRITICAL] OpenAI API Key
File: app.py:5
Key: sk-pr...DEF
Fix: Move this key to .env file and add to .gitignore
```

**Result:** Keys secured in 30 seconds, Dollars saved.

---

##  Features

### AI API Keys Detection

Catches **12+ AI/ML API key types** that other scanners miss:

- **OpenAI** - GPT-4, GPT-3.5, DALL-E
- **Anthropic** - Claude (all models)
- **HuggingFace** - Models & Datasets
- **AWS** - Access keys & secrets
- **Azure** - OpenAI Service keys
- **Google AI** - Gemini, PaLM, Vertex
- **Replicate** - Model deployment
- **Pinecone** - Vector databases
- **Cohere** - Text generation
- **GitHub** - Personal access tokens
- **Slack** - Bot tokens
- ...and more to come soon

### Lightning Fast

- Scans **1,000 files in <1 second**
- Smart file filtering (ignores node_modules, venv, etc.)
- Zero dependencies = instant startup

###  Result Output

- Color-coded severity levels
- Exact file locations
- Redacted key previews (secure logging)
- Actionable remediation steps
- Summary statistics

### Secure by Design

- **Never logs actual keys** (shows only redacted previews)
- Runs entirely locally (no data leaves your machine)
- Read-only operations
- No network calls
- No telemetry

---

## Installation Methods

### Method 1: pip (Recommended)

```bash
pip install aisecretscanner
```

### Method 2: Direct Download

```bash
curl -O https://raw.githubusercontent.com/faythashiedu/AI_Secret_Scanner/main/aiEnvGuard.py
python aiEnvGuard.py
```

### Method 3: GitHub Action

```yaml
# .github/workflows/security.yml
name: Security Scan

on: [push, pull_request]

jobs:
  envguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: faythashiedu/aisecretscanner@v1
```

### Method 4: Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/faythashiedu/AI_Secret_Scanner
    rev: v1.0.0
    hooks:
      - id: aisecretscanner
```

---

## 🎮 Usage

### Basic Scan

```bash
# Scan current directory
aisecretscanner

# Scan specific path
aisecretscanner /path/to/project

# Exit code 0 = safe, 1 = secrets found
```

### CI/CD Integration

```bash
# GitHub Actions, GitLab CI, etc.
aisecretscanner || exit 1  # Fail build if secrets found
```

### Pre-commit Hook

```bash
# Install pre-commit
pip install pre-commit

# Add EnvGuard hook (see .pre-commit-config.yaml)
pre-commit install

# Now runs automatically on git commit
```

---

## What It Detects

### OpenAI Keys

```python
# ❌ Will be detected
OPENAI_API_KEY = "sk-proj-abcd1234..."
openai.api_key = "sk-abc123..."
```

###  Safe Patterns

```python
# Will NOT be flagged
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
load_dotenv() 
api_key = "your_api_key_here"  
```
---

## CI/CD Examples

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Run AI_Secret_Scanner
        run: |
          pip install aisecretscanner
          aisecretscanner
```

### GitLab CI

```yaml
security-scan:
  stage: test
  script:
    - pip install aisecretscanner
    - aisecretscanner
  only:
    - merge_requests
    - main
```

### Pre-commit

```yaml
repos:
  - repo: https://github.com/faythashiedu/AI_Secret_Scanner
    rev: v1.0.0
    hooks:
      - id: aiEnvGuard
        stages: [commit]
```

---


### Adding New Patterns

Edit `PATTERNS` dict in `aiEnvguard.py`:

```python
PATTERNS = {
    'your_service': {
        'pattern': r'your-regex-pattern',
        'name': 'Your Service API Key',
        'severity': Severity.HIGH,
        'docs': 'https://docs.yourservice.com/api-keys'
    }
}
```


## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

---


## ⭐ Star History

If EnvGuard saved you from a $10k OpenAI bill, consider giving it a star! ⭐

---


**EnvGuard** - Because one leaked key is one too many. 🛡️
