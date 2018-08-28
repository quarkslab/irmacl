# Copyright (c) 2013-2018 Quarkslab.
# This file is part of IRMA project.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License in the top-level directory
# of this distribution and at:
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# No part of the project, including this file, may be copied,
# modified, propagated, or distributed except according to the
# terms contained in the LICENSE file.


from setuptools import setup


def readme():
    with open('README.rst') as f:
        return f.read()


setup(name='irmacl',
      version='2.0.6',
      description='Irma command line tool for API v2',
      long_description=readme(),
      url='https://github.com/quarkslab/irma-cli',
      author='irma-dev',
      author_email='irma-dev@quarkslab.com',
      license='ApacheV2',
      packages=['irmacl'],
      install_requires=[
          'requests',
          'marshmallow',
      ],
      include_package_data=True,
      test_suite='nose.collector',
      tests_require=['nose'],
      zip_safe=False)
