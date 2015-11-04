from setuptools import setup


def readme():
    with open('README.rst') as f:
        return f.read()

setup(name='irma',
      version='1.0.0',
      description='Irma command line tool for API v1',
      long_description=readme(),
      url='http://github.com/quarkslab/irma-cli',
      author='Quarkslab',
      author_email='irma-dev@quarkslab.com',
      license='ApacheV2',
      packages=['irma'],
      install_requires=[
          'requests',
          'marshmallow',
      ],
      include_package_data=True,
      test_suite='nose.collector',
      tests_require=['nose'],
      zip_safe=False)
