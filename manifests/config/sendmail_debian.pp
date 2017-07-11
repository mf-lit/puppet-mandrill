# == Class: mandrill::config::sendmail_debian
#
# Configures sendmail to use mandrill as a smarthost on Debian type nodes.
#
# === Authors
#
# David McNicol <david@mcnicks.org>
#
# === Copyright
#
# Copyright 2014 David McNicol
#

class mandrill::config::sendmail_debian (
  $mail_domain,
  $username,
  $apikey
) {

  package { 'sendmail':
    ensure => 'present'
  } ->

  file { 'authinfo':
    ensure  => 'present',
    path    => '/etc/mail/authinfo',
    owner   => 'smmta',
    group   => 'smmsp',
    mode    => '0640',
    content => template('mandrill/sendmail/authinfo.erb')
  } ->

  exec { 'update_db':
    path    => [ '/bin/', '/sbin/' , '/usr/bin/', '/usr/sbin/' ],
    command => '/usr/share/sendmail/update_db',
    returns => [0, 1],
    notify  => Service['sendmail']
  }

  file { 'sendmail.mc':
    ensure  => 'present',
    path    => '/etc/mail/sendmail.mc',
    owner   => 'root',
    group   => 'smmsp',
    mode    => '0644',
    content => template('mandrill/sendmail/sendmail_debian.mc.erb')
  } ->

  exec { 'update_mc':
    path    => [ '/bin/', '/sbin/' , '/usr/bin/', '/usr/sbin/' ],
    command => '/usr/share/sendmail/update_mc',
    returns => [0, 1],
    notify  => Service['sendmail']
  }

  service { 'sendmail':
    ensure => 'running'
  }
}
