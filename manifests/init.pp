# == Class: mandrill
#
# Configures mail service to use Mandrill as a smarthost.
#
# === Parameters
#
# [*mailer*]
#   The name of the mail software installed on the host. This module will try
#   to make a sensible guess for this based on operating system.
#
# [*mail_domain*]
#   The mail domain that the host should use for sender addresses. Defaults
#   to the host FQDN.
#
# [*username*]
#   (Required) Mandrill username.
#
# [*apikey*]
#   (Required) Mandrill API key created inside your Mandrill account.
#
# [*required_packages*]
#   List of required packages, set by params.pp if any additional packages
#   are required for the smarthost functionality to work.
#   
# === Supported Platforms
#
# * Debian
# * Ubuntu
# * RedHat Enterprise Linux, CentOS, Scientific Linux
#
# === Examples
#
#  class { "mandrill":
#    username => "registered@email.address",
#    apikey => "7vk6YiOxfzVdTmtRQShR3"
#  }
#
# === Authors
#
# David McNicol <david@mcnicks.org>
#
# === Copyright
#
# Copyright 2014 David McNicol
#

class mandrill (
  $mailer = $mandrill::params::mailer,
  $mail_domain = $mandrill::params::mail_domain,
  $required_packages = $mandrill::params::required_packages,
  $username,
  $apikey
) inherits mandrill::params {

  if $required_packages {
    package { $required_packages:
      ensure => 'installed',
      before => Class['mandrill::config']
    }
  }

  class { 'mandrill::config':
    mailer            => $mailer,
    mail_domain       => $mail_domain,
    required_packages => $required_packages,
    username          => $username,
    apikey            => $apikey
  }
}
