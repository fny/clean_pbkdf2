require 'test_helper'

class PBKDF2Test < Minitest::Test
  def test_hash_password
    expected_bin = hex2bin('cdedb5281b')
    assert_equal expected_bin, PBKDF2::hash_password(hash_password_args)
  end

  def test_hash_password_hex
    assert_equal 'cdedb5281b', PBKDF2::hash_password_hex(hash_password_args)
  end

  private

  def hash_password_args
    {
      password: 'password',
      salt: 'ATHENA.MIT.EDUraeburn',
      iterations: 1,
      hash_function: 'sha1',
      key_length: 5
    }
  end
end
