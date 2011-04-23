require 'rbkb'

module YaraUtils
  module ClassMethods
    # Generates a yara hex signature based on a set of samples.
    # The samples are compared and differing nibbles and bytes are
    # masked out as needed with the yara wildcard '?'.
    #
    # Note, if samples have differing lengths, the first sample
    # will always dictate the length of the signature.
    #
    # @param [Array] samples
    #   An array of strings to use as the basis for the signature.
    def masked_hex_sig(samples)
      samples = samples.dup
      sig = samples.shift.hexify(:delim => ' ').bytes.to_a
      samples.each do |s|
        nsig = s.hexify(:delim => ' ').bytes.to_a
        sig.each_with_index do |c,i|
          next if c == 0x20 # ' '
          sig[i]=0x3f if(nsig[i] != c) # ?
        end
      end
      sig.pack("C*").sub(/( \?\?)+$/, '')
    end
  end

  extend ClassMethods
end
