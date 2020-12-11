import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

requires = [
    'dnspython',
    'whois',
    'boto3',
    'botocore'
]

setuptools.setup(
    name="heyjack53",
    version="1.0.0",
    author="Bruno Cestari",
    author_email="brunobcestari@protonmail.com",
    description="Script to hijack domains using route53",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/brunobcestari/heyjack53",
    scripts=['bin/heyjack53'],
    packages=setuptools.find_packages(exclude=['tests*']),
    install_requires=requires,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: GPL-3.0 License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)