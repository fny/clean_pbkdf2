if ENV['CODECLIMATE_REPO_TOKEN']
  require 'codeclimate-test-reporter'
  CodeClimate::TestReporter.start
end

$LOAD_PATH.unshift File.expand_path('../../lib', __FILE__)
require 'pbkdf2'

require 'minitest'
require 'minitest/autorun'
require 'minitest/pride'

def hex2bin(s)
  s.scan(/../).map { |x| x.hex }.pack('c*')
end

def assert_rfc_case(expected_hex, password, salt, iterations, key_length)
  hashed_password_hex = rfc_hash_password_hex(password, salt, iterations, key_length)
  assert_equal(expected_hex.tr(' ', ''), hashed_password_hex)
end

def rfc_hash_password_hex(password, salt, iterations, key_length)
  PBKDF2.hash_password_hex(
    password: password,
    salt: salt,
    iterations: iterations,
    key_length: key_length,
    # All test vectors in RFCs use SHA-1
    hash_function: 'sha1'
  )
end
