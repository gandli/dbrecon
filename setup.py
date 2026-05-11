from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="dbrecon",
    version="0.1.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="Database reconnaissance tool for penetration testing",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
    ],
    python_requires=">=3.8",
    install_requires=[
        "click>=8.0.0",
        "mysql-connector-python>=8.0.0",
        "rich>=10.0.0",
        "PyYAML>=6.0",
        "pydantic>=1.8.0",
    ],
    entry_points={
        "console_scripts": [
            "dbrecon=dbrecon.cli:main",
        ],
    },
)