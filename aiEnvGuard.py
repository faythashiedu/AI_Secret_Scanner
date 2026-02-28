#!/usr/bin/env python3
"""
EnvGuard - AI API Key Security Scanner
Never commit API keys again.
"""

import re
import os
import sys
from pathlib import Path
from typing import List, Dict
from dataclasses import dataclass
from enum import Enum


class Severity(Enum):
    """Security issue severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class Finding:
    """Represents a security finding"""
    severity: Severity
    service: str
    file_path: str
    line_number: int
    line_content: str
    key_preview: str 
    recommendation: str


class EnvGuard:
    """
    Elite API key scanner for AI/ML projects
    
    Detects exposed secrets in:
    - Python files (.py)
    - JavaScript files (.js, .ts)
    - Config files (.yaml, .json, .toml)
    - Notebooks (.ipynb)
    - Shell scripts (.sh)
    """
    
    # Comprehensive AI/ML API key patterns
    PATTERNS = {
        'openai': {
            'pattern': r'sk-[A-Za-z0-9]{48}',
            'name': 'OpenAI API Key',
            'severity': Severity.CRITICAL,
            'docs': 'https://platform.openai.com/api-keys'
        },
        'anthropic': {
            'pattern': r'sk-ant-[A-Za-z0-9-_]{95,}',
            'name': 'Anthropic API Key',
            'severity': Severity.CRITICAL,
            'docs': 'https://console.anthropic.com/settings/keys'
        },
        'huggingface': {
            'pattern': r'hf_[A-Za-z0-9]{34}',
            'name': 'HuggingFace Token',
            'severity': Severity.HIGH,
            'docs': 'https://huggingface.co/settings/tokens'
        },
        'openai_org': {
            'pattern': r'org-[A-Za-z0-9]{24}',
            'name': 'OpenAI Organization ID',
            'severity': Severity.MEDIUM,
            'docs': 'https://platform.openai.com/account/organization'
        },
        'cohere': {
            'pattern': r'[A-Za-z0-9]{40}',  # More specific context needed
            'name': 'Cohere API Key',
            'severity': Severity.HIGH,
            'context': ['cohere', 'COHERE'],
            'docs': 'https://dashboard.cohere.ai/api-keys'
        },
        'replicate': {
            'pattern': r'r8_[A-Za-z0-9]{40}',
            'name': 'Replicate API Token',
            'severity': Severity.HIGH,
            'docs': 'https://replicate.com/account/api-tokens'
        },
        'pinecone': {
            'pattern': r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}',
            'name': 'Pinecone API Key',
            'severity': Severity.HIGH,
            'context': ['pinecone', 'PINECONE'],
            'docs': 'https://app.pinecone.io/organizations/*/projects/*'
        },
        'aws_access_key': {
            'pattern': r'AKIA[0-9A-Z]{16}',
            'name': 'AWS Access Key',
            'severity': Severity.CRITICAL,
            'docs': 'https://aws.amazon.com/iam/'
        },
        'aws_secret': {
            'pattern': r'aws_secret_access_key\s*=\s*[\'"][A-Za-z0-9/+=]{40}[\'"]',
            'name': 'AWS Secret Key',
            'severity': Severity.CRITICAL,
            'docs': 'https://aws.amazon.com/iam/'
        },
        'google_api': {
            'pattern': r'AIza[0-9A-Za-z\\-_]{35}',
            'name': 'Google API Key',
            'severity': Severity.HIGH,
            'docs': 'https://console.cloud.google.com/apis/credentials'
        },
        'github_token': {
            'pattern': r'gh[pousr]_[A-Za-z0-9]{36}',
            'name': 'GitHub Token',
            'severity': Severity.HIGH,
            'docs': 'https://github.com/settings/tokens'
        },
        'slack_token': {
            'pattern': r'xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[A-Za-z0-9]{24,32}',
            'name': 'Slack Token',
            'severity': Severity.HIGH,
            'docs': 'https://api.slack.com/authentication/token-types'
        },
    }
    
    # Files/directories to always ignore
    IGNORE_PATTERNS = {
        '.git', '.svn', '.hg',
        'node_modules', '__pycache__', '.pytest_cache',
        'venv', 'env', '.venv', '.env',
        'dist', 'build', '.eggs',
        '.tox', '.coverage',
        'htmlcov', '.mypy_cache',
        '.idea', '.vscode',
        '*.pyc', '*.pyo', '*.so',
        '*.egg-info',
    }
    
    # File extensions to scan
    SCANNABLE_EXTENSIONS = {
        '.py', '.js', '.ts', '.jsx', '.tsx',
        '.yaml', '.yml', '.json', '.toml',
        '.sh', '.bash', '.zsh',
        '.ipynb', '.md', '.txt',
        '.env.example', '.env.sample' 
    }
    
    def __init__(self, root_path: str = "."):
        self.root_path = Path(root_path).resolve()
        self.findings: List[Finding] = []
        self.files_scanned = 0
        self.lines_scanned = 0
    
    def should_ignore(self, path: Path) -> bool:
        """Check if path should be ignored"""
        
        # Check if any parent directory matches ignore patterns
        for part in path.parts:
            if any(pattern.strip('*') in part for pattern in self.IGNORE_PATTERNS):
                return True
        
        # Check if it's a .env file (should be in .gitignore, not scanned)
        if path.name == '.env':
            return True
        
        return False
    
    def is_scannable(self, path: Path) -> bool:
        """Check if file should be scanned"""
        
        # Check extension
        if path.suffix not in self.SCANNABLE_EXTENSIONS:
            return False
        
        # Check if file is too large (>1MB)
        try:
            if path.stat().st_size > 1_000_000:
                return False
        except:
            return False
        
        return True
    
    def redact_key(self, key: str) -> str:
        """Safely redact API key for display"""
        if len(key) <= 8:
            return "***"
        return f"{key[:4]}...{key[-4:]}"
    
    def check_context(self, content: str, match_pos: int, context_keywords: List[str]) -> bool:
        """Check if match is in relevant context (for ambiguous patterns)"""
        # Get surrounding 200 characters
        start = max(0, match_pos - 100)
        end = min(len(content), match_pos + 100)
        context = content[start:end].lower()
        
        return any(keyword.lower() in context for keyword in context_keywords)
    
    def scan_file(self, file_path: Path) -> List[Finding]:
        """Scan a single file for exposed secrets"""
        
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
                
                self.lines_scanned += len(lines)
                
                # Check each pattern
                for key, config in self.PATTERNS.items():
                    pattern = config['pattern']
                    
                    # Find all matches
                    for match in re.finditer(pattern, content):
                        matched_text = match.group(0)
                        
                        # For patterns that need context, verify context
                        if 'context' in config:
                            if not self.check_context(content, match.start(), config['context']):
                                continue
                        
                        # Find line number
                        line_num = content[:match.start()].count('\n') + 1
                        line_content = lines[line_num - 1].strip()
                        
                        # Skip if it's a comment explaining the pattern
                        if line_content.startswith('#') and 'example' in line_content.lower():
                            continue
                        
                        # Skip if it's in a documentation string
                        if 'your_api_key_here' in line_content.lower():
                            continue
                        
                        # Skip if it's a placeholder
                        placeholders = ['xxx', '000', 'test', 'dummy', 'fake', 'sample']
                        if any(p in matched_text.lower() for p in placeholders):
                            continue
                        
                        # Create finding
                        finding = Finding(
                            severity=config['severity'],
                            service=config['name'],
                            file_path=str(file_path.relative_to(self.root_path)),
                            line_number=line_num,
                            line_content=line_content[:100],  # Truncate long lines
                            key_preview=self.redact_key(matched_text),
                            recommendation=f"Move this key to .env file and add to .gitignore. See: {config['docs']}"
                        )
                        
                        findings.append(finding)
        
        except Exception as e:
            # Silently skip files that can't be read
            pass
        
        return findings
    
    def scan(self) -> List[Finding]:
        """Scan all files in project"""
        
        print(f"🔍 Scanning {self.root_path}...\n")
        
        # Walk through directory
        for root, dirs, files in os.walk(self.root_path):
            root_path = Path(root)
            
            # Filter out ignored directories
            dirs[:] = [d for d in dirs if not self.should_ignore(root_path / d)]
            
            for file in files:
                file_path = root_path / file
                
                # Skip ignored files
                if self.should_ignore(file_path):
                    continue
                
                # Check if scannable
                if not self.is_scannable(file_path):
                    continue
                
                self.files_scanned += 1
                
                # Scan file
                file_findings = self.scan_file(file_path)
                self.findings.extend(file_findings)
        
        return self.findings
    
    def check_gitignore(self) -> bool:
        """Check if .env is in .gitignore"""
        gitignore_path = self.root_path / '.gitignore'
        
        if not gitignore_path.exists():
            return False
        
        try:
            with open(gitignore_path, 'r') as f:
                content = f.read()
                return '.env' in content
        except:
            return False
    
    def get_summary(self) -> Dict:
        """Get scan summary statistics"""
        
        severity_counts = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 0,
            Severity.MEDIUM: 0,
            Severity.LOW: 0
        }
        
        for finding in self.findings:
            severity_counts[finding.severity] += 1
        
        return {
            'total_findings': len(self.findings),
            'files_scanned': self.files_scanned,
            'lines_scanned': self.lines_scanned,
            'critical': severity_counts[Severity.CRITICAL],
            'high': severity_counts[Severity.HIGH],
            'medium': severity_counts[Severity.MEDIUM],
            'low': severity_counts[Severity.LOW],
            'env_in_gitignore': self.check_gitignore()
        }


def print_banner():
    """Print EnvGuard banner"""
    banner = """
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║     AIEnvGuard - AI API Key Security Scanner              ║
║          Never commit API keys again                      ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
    """
    print(banner)


def print_finding(finding: Finding, index: int):
    """Print a single finding with beautiful formatting"""
    
    colors = {
        Severity.CRITICAL: '\033[91m',  # Red
        Severity.HIGH: '\033[93m',      # Yellow
        Severity.MEDIUM: '\033[94m',    # Blue
        Severity.LOW: '\033[92m',       # Green
    }
    reset = '\033[0m'
    bold = '\033[1m'
    
    color = colors.get(finding.severity, reset)
    
    print(f"\n{bold}Finding #{index + 1}{reset}")
    print(f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print(f"{color}{bold}[{finding.severity.value}]{reset} {finding.service}")
    print(f"File: {finding.file_path}:{finding.line_number}")
    print(f"Key: {finding.key_preview}")
    print(f"Line Number: {finding.line_number}")
    print(f"Fix It: {finding.recommendation}")


def print_summary(summary: Dict):
    """Print scan summary"""
    
    print("\n" + "="*60)
    print("SCAN SUMMARY")
    print("="*60)
    
    print(f"\n Statistics:")
    print(f"  • Files scanned: {summary['files_scanned']}")
    print(f"  • Lines scanned: {summary['lines_scanned']:,}")
    print(f"  • Total findings: {summary['total_findings']}")
    
    print(f"\n By Severity:")
    if summary['critical'] > 0:
        print(f"  • CRITICAL: {summary['critical']}")
    if summary['high'] > 0:
        print(f"  • HIGH: {summary['high']}")
    if summary['medium'] > 0:
        print(f"  • MEDIUM: {summary['medium']}")
    if summary['low'] > 0:
        print(f"  • LOW: {summary['low']}")
    
    print(f"\n Security Checks:")
    if summary['env_in_gitignore']:
        print(" .env is in .gitignore")
    else:
        print(" .env is NOT in .gitignore (add it!)")
    
    print()


def main():
    """Main entry point"""
    
    # Get target directory from args or use current
    target_dir = sys.argv[1] if len(sys.argv) > 1 else "."
    
    # Print banner
    print_banner()
    
    # Create scanner
    scanner = EnvGuard(target_dir)
    
    # Run scan
    findings = scanner.scan()
    
    # Print findings
    if findings:
        print(f"\n Found {len(findings)} exposed secret(s)!\n")
        
        for i, finding in enumerate(findings):
            print_finding(finding, i)
        
        # Print summary
        summary = scanner.get_summary()
        print_summary(summary)
        
        print("\n  CRITICAL: Remove these secrets before committing!")
        print(" Tip: Add them to a .env file and update .gitignore\n")
        
        # Exit with error code for CI/CD
        sys.exit(1)
    
    else:
        print(f" No exposed secrets found!")
        summary = scanner.get_summary()
        print(f"\n Scanned {summary['files_scanned']} files ({summary['lines_scanned']:,} lines)")
        
        if not summary['env_in_gitignore']:
            print("\n Tip: Add .env to your .gitignore file")
        
        print()
        sys.exit(0)


if __name__ == "__main__":
    main()