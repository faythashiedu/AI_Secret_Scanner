from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="envguard",
    version="1.0.0",
    author="Damilola Faith Ashiedu",
    author_email="faithashiedu9@gmail.com",
    description="Never commit API keys again - Secret scanner for AI/ML projects",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/faythashiedu/AI_Secret_Scanner",
    py_modules=["aiEnvGuard"],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.8",
    install_requires=[],  # No dependencies!
    entry_points={
        "console_scripts": [
            "envguard=envguard:main",
        ],
    },
    keywords="security api-keys secrets scanner ai ml openai anthropic claude slack aws github",
)