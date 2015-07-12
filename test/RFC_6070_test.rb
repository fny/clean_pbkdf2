require 'test_helper'
# These tests are based on the test vectors in RFC 6070: "PKCS #5:
# Password-Based Key Derivation Function 2 (PBKDF2) Test Vectors".
# "This document contains test vectors for the Public-Key Cryptography
# Standards (PKCS) #5 Password-Based Key Derivation Function 2 (PBKDF2
# with the Hash-based Message Authentication Code (HMAC) Secure Hash
# Algorithm (SHA-1) pseudorandom function."
#
# See https://www.ietf.org/rfc/rfc6070.txt for details.
class RFC6070Test < Minitest::Test
  TEST_CASES = [
    # Test 1
    #
    # Input:
    #   P = "password" (8 octets)
    #   S = "salt" (4 octets)
    #   c = 1
    #   dkLen = 20
    #
    # Output:
    #   DK = 0c 60 c8 0f 96 1f 0e 71
    #        f3 a9 b5 24 af 60 12 06
    #        2f e0 37 a6             (20 octets)
    {
      password: 'password',
      salt: 'salt',
      iterations: 1,
      key_length: 20,
      output: '0c 60 c8 0f 96 1f 0e 71' \
              'f3 a9 b5 24 af 60 12 06' \
              '2f e0 37 a6'
    },
    # Test 2
    #
    # Input:
    #  P = "password" (8 octets)
    #  S = "salt" (4 octets)
    #  c = 2
    #  dkLen = 20
    #
    # Output:
    #  DK = ea 6c 01 4d c7 2d 6f 8c
    #       cd 1e d9 2a ce 1d 41 f0
    #       d8 de 89 57             (20 octets)
    {
      password: 'password',
      salt: 'salt',
      iterations: 2,
      key_length: 20,
      output: 'ea 6c 01 4d c7 2d 6f 8c' \
              'cd 1e d9 2a ce 1d 41 f0' \
              'd8 de 89 57'
    },
    # Test 3
    #
    # Input:
    #  P = "password" (8 octets)
    #  S = "salt" (4 octets)
    #  c = 4096
    #  dkLen = 20
    #
    # Output:
    #  DK = 4b 00 79 01 b7 65 48 9a
    #       be ad 49 d9 26 f7 21 d0
    #       65 a4 29 c1             (20 octets)
    {
      password: 'password',
      salt: 'salt',
      iterations: 4096,
      key_length: 20,
      output: '4b 00 79 01 b7 65 48 9a' \
              'be ad 49 d9 26 f7 21 d0' \
              '65 a4 29 c1'
    },
    # Test 4
    #
    # Input:
    #   P = "password" (8 octets)
    #   S = "salt" (4 octets)
    #   c = 16777216
    #   dkLen = 20
    #
    # Output:
    #   DK = ee fe 3d 61 cd 4d a4 e4
    #        e9 94 5b 3d 6b a2 15 8c
    #        26 34 e9 84             (20 octets)
    {
      password: 'password',
      salt: 'salt',
      iterations: 16777216,
      key_length: 20,
      output: 'ee fe 3d 61 cd 4d a4 e4' \
              'e9 94 5b 3d 6b a2 15 8c' \
              '26 34 e9 84'
    },
    # Test 5
    #
    # Input:
    #   P = "passwordPASSWORDpassword" (24 octets)
    #   S = "saltSALTsaltSALTsaltSALTsaltSALTsalt" (36 octets)
    #   c = 4096
    #   dkLen = 25
    #
    # Output:
    #   DK = 3d 2e ec 4f e4 1c 84 9b
    #        80 c8 d8 36 62 c0 e4 4a
    #        8b 29 1a 96 4c f2 f0 70
    #        38                      (25 octets)
    {
      password: 'passwordPASSWORDpassword',
      salt: 'saltSALTsaltSALTsaltSALTsaltSALTsalt',
      iterations: 4096,
      key_length: 25,
      output: '3d 2e ec 4f e4 1c 84 9b' \
              '80 c8 d8 36 62 c0 e4 4a' \
              '8b 29 1a 96 4c f2 f0 70' \
              '38'
    },
    # Test 6
    #
    # Input:
    #   P = "pass\0word" (9 octets)
    #   S = "sa\0lt" (5 octets)
    #   c = 4096
    #   dkLen = 16
    #
    # Output:
    #   DK = 56 fa 6a a7 55 48 09 9d
    #        cc 37 d7 f0 34 25 e0 c3 (16 octets)
    {
      password: "pass\0word", # The sequence "\0" (without quotation marks) means a literal ASCII NUL
      salt: "sa\0lt",
      iterations: 4096,
      key_length: 16,
      output: '56 fa 6a a7 55 48 09 9d' \
              'cc 37 d7 f0 34 25 e0 c3'
    },
  ]

  TEST_CASES.each_with_index do |h, i|
    test_case_num = i + 1
    define_method("test_#{test_case_num}") do
      assert_rfc_case(
        h[:output],
        h[:password],
        h[:salt],
        h[:iterations],
        h[:key_length]
      )
    end
  end
end
