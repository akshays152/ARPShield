from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="arpShield-detection",
    version="1.0.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="Rule-based ARP spoofing detection module",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/ARPShield-Detection",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.7",
    install_requires=[
        "dataclasses>=0.6",
        "python-dateutil>=2.8.2",
    ],
)