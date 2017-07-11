# == Class: mandrill::config::sendmail_redhat
#
# Configures sendmail to use mandrill as a smarthost on RedHat type nodes.
#
# === Authors
#
# David McNicol <david@mcnicks.org>
#
# === Copyright
#
# Copyright 2014 David McNicol
#

class mandrill::config::sendmail_redhat (
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
    mode    => '0600',
    content => template('mandrill/sendmail/authinfo.erb')
  } ->

  file { 'sendmail.mc':
    ensure  => 'present',
    path    => '/etc/mail/sendmail.mc',
    owner   => 'root',
    group   => 'smmsp',
    mode    => '0644',
    content => template('mandrill/sendmail/sendmail_redhat.mc.erb')
  } ->

  exec { 'make':
    path    => [ '/bin/', '/sbin/' , '/usr/bin/', '/usr/sbin/' ],
    command => 'make',
    cwd     => '/etc/mail',
  } ~>

  service { 'sendmail':
    ensure => 'running'
  }
}
