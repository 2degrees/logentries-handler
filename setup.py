##############################################################################
#
# Copyright (c) 2015, 2degrees Limited.
# All Rights Reserved.
#
# This file is part of logentries-handler
# <https://github.com/2degrees/logentries-handler/>, which is subject to the
# provisions of the BSD at
# <http://dev.2degreesnetwork.com/p/2degrees-license.html>. A copy of the
# license should accompany this distribution. THIS SOFTWARE IS PROVIDED "AS IS"
# AND ANY AND ALL EXPRESS OR IMPLIED WARRANTIES ARE DISCLAIMED, INCLUDING, BUT
# NOT LIMITED TO, THE IMPLIED WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST
# INFRINGEMENT, AND FITNESS FOR A PARTICULAR PURPOSE.
#
##############################################################################

from os import path

from setuptools import setup

_HERE = path.abspath(path.dirname(__file__))
_VERSION = open(path.join(_HERE, 'VERSION.txt')).readline().rstrip()
_README = open(path.join(_HERE, 'README.rst')).read().strip()
_CHANGELOG = open(path.join(_HERE, 'CHANGELOG.txt')).read().strip()
_LONG_DESCRIPTION = '\n\n'.join((_README, _CHANGELOG))


setup(
    name='logentries-handler',
    version=_VERSION,
    description='Python Logging Handler for Logentries.com',
    long_description=_LONG_DESCRIPTION,
    url='https://pypi.python.org/pypi/logentries-handler',
    author='2degrees Limited',
    author_email='2degrees-floss@googlegroups.com',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Natural Language :: English',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Software Development :: Libraries',
        ],
    keywords='logentries logging logs handler',
    license='BSD (http://dev.2degreesnetwork.com/p/2degrees-license.html)',
    include_package_data=True,
    exclude_package_data={'': ['README.rst', 'CHANGELOG.txt']},
    py_modules=['logentries_handler'],
    install_requires=['certifi'],
    )
