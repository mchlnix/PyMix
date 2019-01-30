from distutils.core import setup

setup(
    name="PyMix",
    version="0.9",
    description="MixChain implementation in Python",
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: No Input/Output (Daemon)',
        'Framework :: Flake8',
        'Framework :: Pytest',
        'Intended Audience :: Developers',
        'Intended Audience :: Education',
        'Intended Audience :: Information Technology',
        'Intended Audience :: Science/Research',
        'Natural Language :: English',
        # Operating System :: MacOS :: MacOS X
        # Operating System :: Microsoft :: Windows :: Windows 10
        # Operating System :: Microsoft :: Windows :: Windows 7
        # Operating System :: Microsoft :: Windows :: Windows 8
        # Operating System :: Microsoft :: Windows :: Windows 8.1
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: Implementation :: CPython',
        'Topic :: Communications',
        'Topic :: Communications :: Telephony',
        'Topic :: Internet',
        'Topic :: Internet :: Proxy Servers',
        'Topic :: Security',
        'Topic :: Security :: Cryptography',
    ],
    install_requires=[
        'petlib',
        'pycryptodome',
        'sphinxmix', 
        'pytest', 'coverage'
    ]
)
