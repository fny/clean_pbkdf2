# Clean PBKDF2 :closed_lock_with_key:

[![Gem Version](https://badge.fury.io/rb/clean_pbkdf2.svg)](http://badge.fury.io/rb/clean_pbkdf2)
[![Build Status](https://travis-ci.org/fny/clean_pbkdf2.svg?branch=master)](https://travis-ci.org/fny/clean_pbkdf2)
[![Test Coverage](https://codeclimate.com/github/fny/clean_pbkdf2/badges/coverage.svg)](https://codeclimate.com/github/fny/clean_pbkdf2)
[![Code Climate](https://codeclimate.com/github/fny/clean_pbkdf2/badges/gpa.svg)](https://codeclimate.com/github/fny/clean_pbkdf2)
[![Inline docs](http://inch-ci.org/github/fny/clean_pbkdf2.svg?branch=master)](http://inch-ci.org/github/fny/clean_pbkdf2)

A dead-simple, RFC-compliant PBKDF2 implementation using HMAC-AnyOpenSSLDigest as the PRF.

 - No monkey patching
 - Simple API
 - [Fast XORs on any platform](https://github.com/fny/xorcist)
 - Works on any rubies that support keyword arguments

## Usage

```ruby
require 'pbkdf2'

PBKDF2.hash_password(
  password: 'yOurSPecialSecret❤❤❤',
  salt: 'AtLeast64BitsIsKosher',
  iterations: 100000,
  # Default: 'sha256'. Accepts whatever `OpenSSL::Digest` does.
  hash_function: 'sha256',
  # Optional. Defaults to the length of the hash_function output.
  key_length: 32
) # => \xA4\xBF\x10\x91\x1C,\xEB}9lD2\xBAp'T>#m$v\xAE\xF0\x0FX\xB9\xCF_\x82\x91\x9C\xA4"
```

Use `PBKDF2.hash_password_hex` for the hexadecimal output.

Want to keep a singleton around can use for hashing passwords?

```ruby
engine = PBKDF2::Engine.new(
  iterations: 100000,
  # Default: 'sha256', accepts whatever `OpenSSL::Digest` does
  hash_function: 'sha256',
  # Optional. Defaults to the length of the hash_function output.
  key_length: 32
)
engine.hash_password('yOurSPecialSecret❤❤❤!!!', 'ShakeItLikeASaltShaker')
# => "\xDB\x84a\x12\xFC\xC1\xC2\x92s\r\x97@\x83\x95|\xA0\x9DZ\xF9\xC6\x80{\x9Bi\xA5\xBD\x03\x1D\xF4m\x87H"
```

Use `PBKDF2::Engine#hash_password_hex` for the hexadecimal output.

### How many iterations should I use?

From ["Recommended # of iterations when using PKBDF2-SHA256?"](http://security.stackexchange.com/questions/3959/recommended-of-iterations-when-using-pkbdf2-sha256) on the Information Security Stack Exchange:

> You should use the maximum number of rounds which is tolerable, performance-wise, in your application. The number of rounds is a slowdown factor, which you use on the basis that under normal usage conditions, such a slowdown has negligible impact for you (the user will not see it, the extra CPU cost does not imply buying a bigger server, and so on). This heavily depends on the operational context: what machines are involved, how many user authentications per second... so there is no one-size-fits-all response.

[OSWAP's password storage cheat sheet](https://web.archive.org/web/20130115191143/https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet) used to recommend 64,000 iterations as of 2012 doubling every two years (i.e. 90,510 in 2013).

## Standards Compliance

This implementation conforms to [RFC 2898](https://www.ietf.org/rfc/rfc2898.txt), and has been tested using the test vectors in Appendix B of [RFC 3962](https://www.ietf.org/rfc/rfc3962.txt) and [RFC 6070](https://www.ietf.org/rfc/rfc6070.txt).

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'clean_pbkdf2'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install clean_pbkdf2

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/fny/clean_pbkdf2. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [Contributor Covenant](http://contributor-covenant.org) code of conduct.

## License

The gem is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).

