# mandrill

#### Taken from https://forge.puppet.com/dmcnicks/mandrill

#### Table of Contents

1. [Overview](#overview)
2. [Module Description - What the module does and why it is useful](#module-description)
3. [Setup - The basics of getting started with mandrill](#setup)
    * [What mandrill affects](#what-mandrill-affects)
    * [Setup requirements](#setup-requirements)
    * [Beginning with mandrill](#beginning-with-mandrill)
4. [Usage - Configuration options and additional functionality](#usage)
5. [Reference - An under-the-hood peek at what the module is doing and how](#reference)
5. [Limitations - OS compatibility, etc.](#limitations)
6. [Development - Guide for contributing to the module](#development)

## Overview

Configures an existing mail service on a node to use Mandrill as a smarthost.

## Module Description

Mandrill is a cloud-based email infrastructure service that can be used to
deliver outgoing email from servers. This module configures the mailer
software on nodes to use Mandrill as a smarthost. It makes a reasonable guess
about the currently installed mailer based on operating system defaults, but a
specific mailer can be set as a parameter.


*Note that this module does not install a mail service.*

## Setup

### What mandrill affects

* Configuration files associated with the specified / guessed mailer.
* Restarts the specified / guessed mailer.

### Beginning with mandrill

Before you can use this module you will have to register with Mandrill. Free
accounts support up to 250 emails per hour and 12000 emails per month.
You will also need to generate an API key in Settings > API Keys > New API Key.

The most basic class declaration requires a username and API key.

```puppet
    class { "mandrill":
        username => "registered@email.address",
        apikey => "7vk6YiOxfzVdTmtRQShR3"
    }
```

This will guess which mailer to configure based on the operating system of the
node and configure the mail domain of the node to be the node FQDN. You can
specify a mail domain:

```puppet
    class { "mandrill":
        username => "registered@email.address",
        apikey => "7vk6YiOxfzVdTmtRQShR3",
        mail_domain => "mydomain.org"
    }
```

And you can specify a mailer if you know what is running on the node:

```puppet
    class { "mandrill":
        username => "registered@email.address",
        apikey => "7vk6YiOxfzVdTmtRQShR3",
        mail_domain => "mydomain.org",
        mailer => "sendmail",
    }
```

## Usage

####Class: `mandrill`

The module's primary class.

**Parameters within `mandrill`:**

#####`username`

(Required) Mandrill username.

#####`apikey`

(Required) Mandrill API key.

#####`mail_domain`

The mail domain that the host should use for sender addresses. Defaults
to the host FQDN.

#####`mailer`

The name of the mail software installed on the host. The module will
try to make a sensible guess for this parameter based on operating
system.

## Limitations

This module supports exim, postfix and sendmail mailers and will guess
which mailer to use for Debian, Ubuntu and RedHat derivatives. If you
know the mailer you are using, specify it in the mandrill class
definition.

This module has been tested with:

* Exim, Postfix and Sendmail on Debian and Ubuntu.
* Postfix and Sendmail on CentOS.

There may be incompatibilities with other OS versions, packages and
configurations.

## Development

I am happy to receive pull requests.
