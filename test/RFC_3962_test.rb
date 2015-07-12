require 'test_helper'

# These tests are based on the test vectors in Appendix B of RFC 3962: "Advanced
# Encryption Standard (AES) Encryption for Kerberos 5". Note the pseudorandom
# function used by PBKDF2 in this RFC is "the SHA-1 HMAC of the passphrase and
# salt."
#
# See https://www.ietf.org/rfc/rfc3962.txt for details.
class RFC3962Test < Minitest::Test
  TEST_CASES = [
    # Test 1
    #
    # Iteration count = 1
    # Pass phrase = "password"
    # Salt = "ATHENA.MIT.EDUraeburn"
    # 128-bit PBKDF2 output:
    #    cd ed b5 28 1b b2 f8 01 56 5a 11 22 b2 56 35 15
    # 256-bit PBKDF2 output:
    #    cd ed b5 28 1b b2 f8 01 56 5a 11 22 b2 56 35 15
    #    0a d1 f7 a0 4b b9 f3 a3 33 ec c0 e2 e1 f7 08 37
    {
      iterations: 1,
      password: 'password',
      salt: 'ATHENA.MIT.EDUraeburn',
      output_128: 'cd ed b5 28 1b b2 f8 01 56 5a 11 22 b2 56 35 15',
      output_256: '0a d1 f7 a0 4b b9 f3 a3 33 ec c0 e2 e1 f7 08 37'
    },
    # Test 2
    #
    # Iteration count = 2
    # Pass phrase = "password"
    # Salt="ATHENA.MIT.EDUraeburn"
    # 128-bit PBKDF2 output:
    #    01 db ee 7f 4a 9e 24 3e 98 8b 62 c7 3c da 93 5d
    # 256-bit PBKDF2 output:
    #    01 db ee 7f 4a 9e 24 3e 98 8b 62 c7 3c da 93 5d
    #    a0 53 78 b9 32 44 ec 8f 48 a9 9e 61 ad 79 9d 86
    {
      iterations: 2,
      password: 'password',
      salt: 'ATHENA.MIT.EDUraeburn',
      output_128: '01 db ee 7f 4a 9e 24 3e 98 8b 62 c7 3c da 93 5d',
      output_256: 'a0 53 78 b9 32 44 ec 8f 48 a9 9e 61 ad 79 9d 86'
    },
    # Test 3
    #
    # Iteration count = 1200
    # Pass phrase = "password"
    # Salt = "ATHENA.MIT.EDUraeburn"
    # 128-bit PBKDF2 output:
    #    5c 08 eb 61 fd f7 1e 4e 4e c3 cf 6b a1 f5 51 2b
    # 256-bit PBKDF2 output:
    #    5c 08 eb 61 fd f7 1e 4e 4e c3 cf 6b a1 f5 51 2b
    #    a7 e5 2d db c5 e5 14 2f 70 8a 31 e2 e6 2b 1e 13
    {
      iterations: 1200,
      password: 'password',
      salt: 'ATHENA.MIT.EDUraeburn',
      output_128: '5c 08 eb 61 fd f7 1e 4e 4e c3 cf 6b a1 f5 51 2b',
      output_256: 'a7 e5 2d db c5 e5 14 2f 70 8a 31 e2 e6 2b 1e 13'
    },
    # Test 4
    #
    # Iteration count = 5
    # Pass phrase = "password"
    # Salt=0x1234567878563412
    # 128-bit PBKDF2 output:
    #    d1 da a7 86 15 f2 87 e6 a1 c8 b1 20 d7 06 2a 49
    # 256-bit PBKDF2 output:
    #    d1 da a7 86 15 f2 87 e6 a1 c8 b1 20 d7 06 2a 49
    #    3f 98 d2 03 e6 be 49 a6 ad f4 fa 57 4b 6e 64 ee
    {
      iterations: 5,
      password: 'password',
      salt: [0x1234567878563412].pack('Q'),
      output_128: 'd1 da a7 86 15 f2 87 e6 a1 c8 b1 20 d7 06 2a 49',
      output_256: '3f 98 d2 03 e6 be 49 a6 ad f4 fa 57 4b 6e 64 ee'
    },
    # Test 5
    #
    # Iteration count = 1200
    # Pass phrase = (64 characters)
    #  "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
    # Salt="pass phrase equals block size"
    # 128-bit PBKDF2 output:
    #    13 9c 30 c0 96 6b c3 2b a5 5f db f2 12 53 0a c9
    # 256-bit PBKDF2 output:
    #    13 9c 30 c0 96 6b c3 2b a5 5f db f2 12 53 0a c9
    #    c5 ec 59 f1 a4 52 f5 cc 9a d9 40 fe a0 59 8e d1
    {
      iterations: 1200,
      password: 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX',
      salt: 'pass phrase equals block size',
      output_128: '13 9c 30 c0 96 6b c3 2b a5 5f db f2 12 53 0a c9',
      output_256: 'c5 ec 59 f1 a4 52 f5 cc 9a d9 40 fe a0 59 8e d1'
    },
    # Test 6
    #
    # Iteration count = 1200
    # Pass phrase = (65 characters)
    #  "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
    # Salt = "pass phrase exceeds block size"
    # 128-bit PBKDF2 output:
    #    9c ca d6 d4 68 77 0c d5 1b 10 e6 a6 87 21 be 61
    # 256-bit PBKDF2 output:
    #    9c ca d6 d4 68 77 0c d5 1b 10 e6 a6 87 21 be 61
    #    1a 8b 4d 28 26 01 db 3b 36 be 92 46 91 5e c8 2a
    {
      iterations: 1200,
      password: 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX',
      salt: 'pass phrase exceeds block size',
      output_128: '9c ca d6 d4 68 77 0c d5 1b 10 e6 a6 87 21 be 61',
      output_256: '1a 8b 4d 28 26 01 db 3b 36 be 92 46 91 5e c8 2a'
    },
    # Test 7
    #
    # Iteration count = 50
    # Pass phrase = g-clef (0xf09d849e)
    # Salt = "EXAMPLE.COMpianist"
    # 128-bit PBKDF2 output:
    #    6b 9c f2 6d 45 45 5a 43 a5 b8 bb 27 6a 40 3b 39
    # 256-bit PBKDF2 output:
    #    6b 9c f2 6d 45 45 5a 43 a5 b8 bb 27 6a 40 3b 39
    #    e7 fe 37 a0 c4 1e 02 c2 81 ff 30 69 e1 e9 4f 52
    {
      iterations: 50,
      password: [0xf09d849e].pack('N'), # 𝄞
      salt: 'EXAMPLE.COMpianist',
      output_128: '6b 9c f2 6d 45 45 5a 43 a5 b8 bb 27 6a 40 3b 39',
      output_256: 'e7 fe 37 a0 c4 1e 02 c2 81 ff 30 69 e1 e9 4f 52'
    }
  ]

  TEST_CASES.each_with_index do |h, i|
    test_case_num = i + 1
    define_method("test_appendix_b_#{test_case_num}_128") do
      assert_rfc_case(
        h[:output_128],
        h[:password],
        h[:salt],
        h[:iterations],
        128
      )
    end

    define_method("test_appendix_b_#{test_case_num}_256") do
      assert_rfc_case(
        h[:output_128] + h[:output_256],
        h[:password],
        h[:salt],
        h[:iterations],
        256
      )
    end
  end

  private

  def assert_rfc_case(expected_hex, password, salt, iterations, key_length_in_bits)
    hashed_password_hex = hash_password_hex(password, salt, iterations, key_length_in_bits / 8)
    assert_equal(expected_hex.tr(' ', ''), hashed_password_hex)
  end

  def hash_password_hex(password, salt, iterations, key_length)
    PBKDF2.hash_password_hex(
      password: password,
      salt: salt,
      iterations: iterations,
      key_length: key_length,
      # As mentioned above, all the examples in RFC 3962 use SHA-1
      hash_function: 'sha1'
    )
  end
end
