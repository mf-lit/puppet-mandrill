# == Class: mandrill::config
#
# Manages configuration tasks for the mandrill module. This class defers 
# actual configuration to mailer-specific classes based on the $mailer
# parameter.
#
# === Authors
#
# David McNicol <david@mcnicks.org>
#
# === Copyright
#
# Copyright 2014 David McNicol
#

class mandrill::config (
  $mailer,
  $mail_domain,
  $required_packages,
  $username,
  $apikey
) {

  # Work out whether we have a specific configuration that works for
  # the given mailer and operating system.

  case $mailer {

    'postfix': {
      $mailer_config = 'postfix'
    }

    'exim': {

      case $::osfamily {

        'Debian': {
          $mailer_config = 'exim_debian'
        }

        default: {
          fail("${mailer} on ${::osfamily} not supported")
        }

      }

    }

    'sendmail': {

      case $::osfamily {

        'Debian': {
          $mailer_config = 'sendmail_debian'
        }

        'RedHat': {
          $mailer_config = 'sendmail_redhat'
        }

        default: {
          fail("${mailer} on ${::osfamily} not supported")
        }

      }

    }

    default: {
      fail("${mailer} on ${::osfamily} not supported")
    }

  }

  # Apply the configuration if one has been found.

  if $mailer_config {

    class { "mandrill::config::${mailer_config}":
      mail_domain => $mail_domain,
      username    => $username,
      apikey      => $apikey
    }

  }

}
