require 'test/unit'
require_relative '../lib/Cryptography.rb'

class TestCryptography < Test::Unit::TestCase
	TEST_USER_ID  = "sensfan69"
	TEST_PASSWORD = "password123"
	TEST_PHRASE_A = "Hello World!"
	TEST_PHRASE_B = "Goodbye World!"
	TEST_SALT     = 

	#essentially this is just testing if the hashing process is deterministic and stateless
	#i.e. it produces the same outputs for the same inputs, regardless of previous inputs
	def testHashingDeterministic
		testHashA     = hashString(TEST_PHRASE_A,TEST_SALT)
		testHashB     = hashString(TEST_PHRASE_B,TEST_SALT)
		testHashCopyA = hashString(TEST_PHRASE_A,TEST_SALT)
		testHashCopyB = hashString(TEST_PHRASE_B,TEST_SALT)
	
		assert(testHashA==testHashCopyA,"Later digest of phrase A did not match the first digest")
		assert(testHashB==testHashCopyB,"Later digest of phrase B did not match the first digest")
	end

	#test if different inputs produce different outputs
	def testHashingDifferentInDifferentOut
		testHash    = hashString(TEST_PHRASE_A,TEST_SALT)
		testHashNeg = hashString(TEST_PHRASE_B,TEST_SALT)

		assert(testHash!=testHashNeg,"Different inputs do not produce different outputs")
	end

	def testPassphraseEncryption
		#create key pair and encrypt data
		publicKey, encryptedPrivateKey = createPassphraseKeyPair(TEST_USER_ID,TEST_PASSWORD,TEST_SALT)
		encryptDataWithPublicKey(TEST_PHRASE_A, publicKey)

		#decrpyt data
		decryptedData = decryptDataWithCredentials(TEST_USER_ID,TEST_PASSWORD,TEST_SALT)
	
		#compare decrypted data with initial data
		assert(decryptedData==TEST_PHRASE_A,"Data decrypted using passphrase-encrypted private key did not match initial data")
	end
end
