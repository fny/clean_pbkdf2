require 'test_helper'


class EngineTest < Minitest::Test
  def test_hash_password
    engine = short_engine
    expected_bin = hex2bin('cdedb5281b')

    assert_equal(expected_bin, engine.hash_password('password', 'ATHENA.MIT.EDUraeburn'))
  end

  def test_hash_password_hex
    engine = short_engine
    expected_hex = 'cdedb5281b'

    assert_equal(expected_hex, engine.hash_password_hex('password', 'ATHENA.MIT.EDUraeburn'))
  end

  def test_too_short_key_length
    assert_raises PBKDF2::InvalidKeyLengthError do
      PBKDF2::Engine.new(
        iterations: 1,
        hash_function: 'sha1',
        key_length: 0
      )
    end
  end

  def test_too_long_key_length
    assert_raises PBKDF2::InvalidKeyLengthError do
      PBKDF2::Engine.new(
        iterations: 1,
        hash_function: 'sha1',
        key_length: (2**32 - 1) * 32 + 1
      )
    end
  end

  def test_defaults
    engine = PBKDF2::Engine.new(iterations: 1)

    assert_equal OpenSSL::Digest.new('sha256'), engine.send(:hash_function)
    assert_equal 32, engine.send(:key_length)
  end

  # Values taken from Discourse's PBKDF2 spec:
  # https://github.com/discourse/discourse/blob/0fd98b56d897e79f4f10b41da7d406ec32f81805/spec/components/pbkdf2_spec.rb
  def test_sha256_default
    assert_equal '0313a6aca54dd4c5d82a699a8a0f0ffb0191b4ef62414b8d9dbc11c0c5ac04da',
      PBKDF2.hash_password_hex(password: 'test', salt: 'abcd', iterations: 100)
    assert_equal 'c7a7b2891bf8e6f82d08cf8d83824edcf6c7c6bacb6a741f38e21fc7977bd20f',
      PBKDF2.hash_password_hex(password: 'test', salt: 'abcd', iterations: 101)
  end

  private

  def short_engine
    PBKDF2::Engine.new(iterations: 1, hash_function: 'sha1', key_length: 5)
  end
end
