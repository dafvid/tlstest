from setuptools import setup

setup(name='tlstest',
      version='191022.1',
      url='http://www.dafnet.se',
      author='David Wahlund',
      author_email='david@dafnet.se',
      packages=['tlstest'],
      include_package_data=True,
      zip_safe=False,
      install_requires=['cryptography', 'flask', 'flask_json', 'flask_wtf',
                        'paramiko', 'dnspython', 'PyOpenSSL']
      )
