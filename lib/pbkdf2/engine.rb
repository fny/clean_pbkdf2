module PBKDF2
  class Engine
    # :iterations - number of times to run the PRF per calculated block
    # :hash_function - long name or short name of `OpenSSL::Digest` algorithm to use
    # :key_length - desired length of the derived key in bytes, defaults to the hash function's output size
    def initialize(iterations:, hash_function: PBKDF2::DEFAULT_HASH_FUNCTION, key_length: nil)
      @hash_function = OpenSSL::Digest.new(hash_function)
      @iterations = iterations
      @key_length = checked_key_length(key_length)
    end

    # Returns the hashed password.
    #
    # password - password to encrypt
    # salt - salt to use; note the standard recommends at least 64 bits
    def hash_password(password, salt)
      value = ''
      1.upto(blocks_needed) do |block_num|
        value << calculate_block(password, salt, block_num)
      end
      value[0, key_length]
    end

    # Returns the hashed password as a hexadecimal value.
    #
    # Takes the same arguments as `hash_password`.
    def hash_password_hex(password, salt)
      hash_password(password, salt).unpack('H*').first
    end

    private

    # OpenSSL::Digest algorithm with which to compute the HMAC
    attr_reader :hash_function
    attr_reader :iterations
    attr_reader :key_length

    # Number of blocks needed to satisfy the desired key length
    def blocks_needed
      (key_length.to_f / hash_function.digest_length).ceil
    end

    def checked_key_length(desired_length)
      return hash_function.digest_length unless desired_length
      fail PBKDF2::InvalidKeyLengthError, "Key is too short." if desired_length < 1
      fail PBKDF2::InvalidKeyLengthError, "Key is too long." if desired_length > ((2**32 - 1) * hash_function.digest_length)
      desired_length
    end

    # F(Password, Salt, c, i) = U1 ^ U2 ^ ... ^ Uc
    def calculate_block(password, salt, block_num)
      # U1: PRF(password, salt + INT_32_BE(i))
      u = prf(password, salt + [block_num].pack('N'))
      return_value = u
      # U2 through Uc:
      2.upto(iterations) do
        # calculate Un: PRF(Password, Un-1)
        u = prf(password, u)
        # xor it with the previous results
        Xorcist.xor!(return_value, u)
      end
      return_value
    end

    def prf(password, data)
      OpenSSL::HMAC.digest(hash_function, password, data)
    end
  end
end
