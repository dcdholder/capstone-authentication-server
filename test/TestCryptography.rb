require 'test/unit'
require_relative '../lib/Cryptography.rb'

class TestCryptography < Test::Unit::TestCase
	TEST_USER_ID  = "sensfan69"
	TEST_PASSWORD = "password123"
	TEST_PHRASE_A = "Hello World!"
	TEST_PHRASE_B = "Goodbye World!"
	TEST_SALT     = OpenSSL::Random.random_bytes(16)

	#test if identical inputs produce identical outputs
	def testDigestSameInSameOut
		testDigest     = Cryptography.digestStringWithSalt(TEST_PHRASE_A,TEST_SALT)
		testDigestCopy = Cryptography.digestStringWithSalt(TEST_PHRASE_A,TEST_SALT)
		
		assert(testDigest==testDigestCopy,"Identical inputs do not produce identical outputs")
	end

	#test if different inputs produce different outputs
	def testDigestDifferentInDifferentOut
		testDigest    = Cryptography.digestStringWithSalt(TEST_PHRASE_A,TEST_SALT)
		testDigestNeg = Cryptography.digestStringWithSalt(TEST_PHRASE_B,TEST_SALT)

		assert(testDigest!=testDigestNeg,"Different inputs do not produce different outputs")
	end

	def testPassphraseEncryptionDecryption
		#create key pair and encrypt data
		publicKey, encryptedPrivateKey = Cryptography.generateEncryptedPems(TEST_USER_ID,TEST_PASSWORD,TEST_SALT)
		encryptedData = Cryptography.encryptWithPublicKeyPem(TEST_PHRASE_A, publicKey)

		#show that the encrypted data is not the same as the sample data
		assert(encryptedData!=TEST_PHRASE_A,"Data encrypted using public key matched the initial data")

		#decrpyt data
		decryptedData = Cryptography.decryptDataWithCredentials(TEST_USER_ID,TEST_PASSWORD,TEST_SALT,encryptedData,encryptedPrivateKey)
	
		#compare decrypted data with initial data
		assert(decryptedData==TEST_PHRASE_A,"Data decrypted using passphrase-encrypted private key did not match initial data")
	end
end
