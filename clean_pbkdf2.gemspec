# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'pbkdf2/version'

Gem::Specification.new do |spec|
  spec.name          = 'clean_pbkdf2'
  spec.version       = PBKDF2::VERSION
  spec.authors       = ["Faraz Yashar"]
  spec.email         = ["faraz.yashar@gmail.com"]

  spec.summary       = "Dead-simple, RFC-compliant PBKDF2 implementation."
  spec.description   = "A dead-simple, RFC-compliant PBKDF2 implementation using HMAC-AnyOpenSSLDigest as the PRF."
  spec.homepage      = "https://github.com/fny/clean_pbkdf2"
  spec.license       = "MIT"

  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.require_paths = ['lib']

  spec.required_ruby_version = '>= 2.0'
  spec.add_dependency 'xorcist', '~> 1.0.0'
  spec.add_development_dependency 'bundler', '~> 1.10'
  spec.add_development_dependency 'rake', '~> 10.0'
  spec.add_development_dependency 'minitest', '~> 5.7.0'
end
