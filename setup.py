from setuptools import setup

setup(name='ssltest',
      version='171129.3',
      url='http://www.dafnet.se',
      author='David Wahlund',
      author_email='david@dafnet.se',
      packages=['ssltest'],
      include_package_data=True,
      zip_safe=False,
      install_requires=['flask', 'flask_json', 'flask_wtf', 'paramiko', 'dnspython', 'PyOpenSSL']
      )
