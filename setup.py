"""
Setup configuration for WebSecScanner
"""
from setuptools import setup, find_packages

setup(
    name="websecscanner",
    version="1.0.0",
    author="Franco",
    description="Advanced Web Application Security Scanner",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        "fastapi>=0.104.0",
        "uvicorn>=0.24.0",
        "requests>=2.31.0",
        "beautifulsoup4>=4.12.0",
        "sqlalchemy>=2.0.0",
        "pyjwt>=2.8.0",
        "bcrypt>=4.1.0",
        "python-multipart>=0.0.6",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
            "pytest-asyncio>=0.21.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "pylint>=2.17.0",
            "mypy>=1.5.0",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
)
