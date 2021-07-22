from setuptools import setup

setup(name='tlstest',
      version='210722.1',
      url='http://www.dafnet.se',
      author='David Stenwall',
      author_email='david@dafnet.se',
      packages=['tlstest', 'tlstest.cli', 'tlstest.webapp'],
      include_package_data=True,
      zip_safe=False,
      install_requires=['cryptography', 'flask', 'flask_json', 'flask_wtf',
                        'paramiko', 'dnspython', 'PyOpenSSL', 'email_validator']
      )
