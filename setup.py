from setuptools import setup, find_packages
import os

long_description = '''
Tenable -> CEF Ingester
For usage documentation, please refer to the github repository at
https://github.com/tenable/integrations-cef
'''

setup(
    name='tenable-cef',
    version='1.0.0',
    description='',
    author='Tenable, Inc.',
    long_description=long_description,
    author_email='smcgrath@tenable.com',
    url='https://github.com/tenable/integrations-cef',
    license='MIT',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Information Technology',
        'Topic :: System :: Networking',
        'Topic :: Other/Nonlisted Topic',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
    ],
    keywords='tenable tenable_io cef',
    packages=find_packages(exclude=['tests']),
    install_requires=[
        'pytenable>=0.3.28',
        'restfly>=1.1.0',
        'arrow>=0.13.0',
        'Click>=7.0'
    ],
    entry_points={
        'console_scripts': [
            'tenable-cef=tenable_cef.cli:cli',
        ],
    },
)