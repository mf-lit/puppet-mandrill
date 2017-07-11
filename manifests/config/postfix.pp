# == Class: mandrill::config::postfix
#
# Configures postfix to use mandrill as a smarthost.
#
# === Authors
#
# David McNicol <david@mcnicks.org>
# Marc Flannery
# === Copyright
#
# Copyright 2014 David McNicol
# modified by Marc Flannery - July 2017

class mandrill::config::postfix (
  $mail_domain,
  $username,
  $apikey
) {

  $sasl_passwd = 'hash:/etc/postfix/sasl_passwd'
  $ca_certificates = '/etc/ssl/certs/ca-certificates.crt'

  package { 'postfix':
    ensure => 'present'
  }

  $postfix_setup = {
    'inet_interfaces' => {
      command => "postconf -e 'inet_interfaces = 127.0.0.1'",
      onlyif  => "test $(grep -c 'inet_interfaces = 127.0.0.1' /etc/postfix/main.cf) -lt 1",
    },
    'myhostname' => {
      command => "postconf -e 'myhostname = ${mail_domain}'",
      onlyif  => "test $(grep -c 'myhostname = ${mail_domain}' /etc/postfix/main.cf) -lt 1"
    },
    'mydestination' => {
      command => "postconf -e 'mydestination = localhost'",
      onlyif  => "test $(grep -c 'mydestination = localhost' /etc/postfix/main.cf) -lt 1",
    },
    'relayhost' => {
      command => "postconf -e 'relayhost = [smtp.mandrillapp.com]'",
      onlyif  => "test $(grep -Fc 'relayhost = [smtp.mandrillapp.com]' /etc/postfix/main.cf) -lt 1",
    },
    'smtp_sasl_auth_enable' => {
      command => "postconf -e 'smtp_sasl_auth_enable = yes'",
      onlyif  => "test $(grep -c 'smtp_sasl_auth_enable = yes' /etc/postfix/main.cf) -lt 1",
    },
    'smtp_sasl_password_maps' => {
      command => "postconf -e 'smtp_sasl_password_maps = ${sasl_passwd}'",
      onlyif  => "test $(grep -c 'smtp_sasl_password_maps = ${sasl_passwd}' /etc/postfix/main.cf) -lt 1",
    },
    'smtp_sasl_security_options' => {
      command => "postconf -e 'smtp_sasl_security_options = noanonymous'",
      onlyif  => "test $(grep -c 'smtp_sasl_security_options = noanonymous' /etc/postfix/main.cf) -lt 1",
    },
    'smtp_use_tls' => {
      command => "postconf -e 'smtp_use_tls = yes'",
      onlyif  => "test $(grep -c 'smtp_use_tls = yes' /etc/postfix/main.cf) -lt 1",
    },
    'smtp_tls_CAfile' => {
      command => "postconf -e 'smtp_tls_CAfile = ${ca_certificates}'",
      onlyif  => "test $(grep -c 'smtp_tls_CAfile = ${ca_certificates}' /etc/postfix/main.cf) -lt 1",
    },
  }

  $postfix_setup_defaults = {
    path    => [ '/bin/', '/sbin/' , '/usr/bin/', '/usr/sbin/' ],
    notify  => Service['postfix'],
    require => Package['postfix']
  }

  create_resources(exec, $postfix_setup, $postfix_setup_defaults)

  service { 'postfix':
    ensure  => 'running',
    restart => '/bin/systemctl reload postfix'
  }

  file { 'sasl_passwd':
    ensure  => 'present',
    path    => '/etc/postfix/sasl_passwd',
    content => template('mandrill/postfix/sasl_passwd.erb'),
    notify  => Exec['sasl_passwd.db'],
    require => Package['postfix']
  }

  exec { 'sasl_passwd.db':
    path        => [ '/bin/', '/sbin/' , '/usr/bin/', '/usr/sbin/' ],
    command     => 'postmap /etc/postfix/sasl_passwd',
    refreshonly => true,
    notify      => Service['postfix'],
    require     => Package['postfix']
  }
}
