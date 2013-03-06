from setuptools import setup, find_packages
import os

version = __import__('djangocms_accounts').__version__

setup(
    name = "djangocms-accounts",
    version = __import__('djangocms_accounts').__version__,
    url = 'http://github.com/divio/djangocms-accounts',
    license = 'BSD',
    platforms=['OS Independent'],
    description = "A registration and authentication app for django CMS Cloud.",
    author = 'Divio AG',
    author_email = 'developers@divio.ch',
    packages=find_packages(),
    install_requires = (
#        'Django>=1.3,<1.5',
        'django-social-auth',
        'django-class-based-auth-views',
        'django-password-reset',
        'django-standard-form',
        'django-absolute',
        'django-classy-tags',
        'django-sekizai',
        'django-appconf',
        'dj.chain',
    ),
    include_package_data=True,
    zip_safe=False,
    classifiers = [
        'Development Status :: 4 - Beta',
        'Framework :: Django',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Internet :: WWW/HTTP',
    ],
)
