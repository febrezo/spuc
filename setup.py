from setuptools import find_packages, setup
import spuc


with open("requirements.txt") as iF:
    requirements = iF.read().splitlines()


setup(
    author='Félix Brezo (@febrezo)',
    description='STIX2 Pattern Universal Conversor: A Python 3.6+ package for translating STIX2 Patterns onto several query languages.',
    name='spuc',
    packages=find_packages(),
    install_requires=requirements,
    license='GNU AGPLv3+',
    version=spuc.__version__,
    entry_points={
        'console_scripts': [
            'spuc-cli=spuc.cli:main',
        ],
    },
    url='https://github.com/febrezo/spuc',
)