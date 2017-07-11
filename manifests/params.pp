# == Class: mandrill::params
#
# Manages parameters for the mandrill module.
#
# === Authors
#
# David McNicol <david@mcnicks.org>
#
# === Copyright
#
# Copyright 2014 David McNicol
#

class mandrill::params () {

  # Set mail domain to FQDN by default.

  $mail_domain = $::fqdn

  # Set the mailer and mailer service based on the OS.

  case $::osfamily {

    'Debian': {

      $required_packages = [
        'sasl2-bin',
        'libsasl2-2',
        'libsasl2-modules'
      ]

      case $::operatingsystem {

        'Debian': {
          $mailer = 'exim'
        }

        'Ubuntu': {
          $mailer = 'postfix'
        }

        default: {
          $mailer = 'none'
        }
      }
    }

    'RedHat': {

      $required_packages = [
        'cyrus-sasl',
        'cyrus-sasl-plain',
        'cyrus-sasl-md5'
      ]

      $mailer = 'postfix'
    }

    default: {
      $mailer = 'none'
    }
  }
}
