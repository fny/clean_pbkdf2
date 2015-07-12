require 'openssl'
require 'xorcist'
require 'pbkdf2/engine'
require 'pbkdf2/version'

module PBKDF2
  DEFAULT_HASH_FUNCTION = 'sha256'

  # Raised when the desired key length is invalid for the given hash function.
  InvalidKeyLengthError = Class.new(ArgumentError)

  # Returns the hashed password.
  #
  # :password - password to encrypt
  # :salt - salt to use; note the standard recommends at least 64 bits
  # :iterations - number of times to run the PRF per calculated block
  # :hash_function - long name or short name of `OpenSSL::Digest` algorithm to use
  # :key_length - desired length of the derived key in bytes, defaults to the hash function's output size
  def self.hash_password(password:, salt:, iterations:, hash_function: DEFAULT_HASH_FUNCTION, key_length: nil)
    engine = Engine.new(hash_function: hash_function, iterations: iterations, key_length: key_length)
    engine.hash_password(password, salt)
  end

  # Returns the hashed password as a hexadecimal value.
  #
  # Takes the same arguments as `hash_password`
  def self.hash_password_hex(password:, salt:, iterations:, hash_function: DEFAULT_HASH_FUNCTION, key_length: nil)
    engine = Engine.new(hash_function: hash_function, iterations: iterations, key_length: key_length)
    engine.hash_password_hex(password, salt)
  end
end
