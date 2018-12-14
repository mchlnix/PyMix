from distutils.core import setup

setup(
    name="PyMix",
    version="0.9",
    description="MixChain implementation in Python",
    python_requires='>=3',
    install_requires=[
        'petlib',
        'pycryptodome',
        'sphinxmix',
    ]
)
