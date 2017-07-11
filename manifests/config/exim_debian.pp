# == Class: mandrill::config::exim_debian
#
# Configures exim to use mandrill as a smarthost on debian type hosts.
#
# === Authors
#
# David McNicol <david@mcnicks.org>
#
# === Copyright
#
# Copyright 2014 David McNicol
#

class mandrill::config::exim_debian (
  $mail_domain,
  $username,
  $apikey
) {
  
  package { 'exim4':
    ensure => 'present'
  } ->

  file { 'mailname':
    ensure  => 'present',
    path    => '/etc/mailname',
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
    content => $mail_domain
  } ->

  file { 'update-exim4.conf.conf':
    ensure  => 'present',
    path    => '/etc/exim4/update-exim4.conf.conf',
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
    content => template('mandrill/exim/update-exim4.conf.conf.erb')
  } ->

  file { 'passwd.client':
    ensure  => 'present',
    path    => '/etc/exim4/passwd.client',
    owner   => 'root',
    group   => 'Debian-exim',
    mode    => '0640',
    content => template('mandrill/exim/passwd.client.erb'),
  } ~>

  service { 'exim4':
    ensure => 'running'
  }

}
