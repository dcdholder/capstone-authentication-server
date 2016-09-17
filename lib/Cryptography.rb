require 'openssl'

class Cryptography
	#TODO: change references to cryptographic hashes to "digests"

	NUM_PBKDF_ITERATIONS = 10000
	SALT_BYTE_LENGTH     = 16
	AES_TYPE             = "AES-128-CBC"
	RSA_BIT_LENGTH       = 4096

	#no two passphrases should be alike
	def genPassPhrase(userId,password)
		return "#{userId} #{password}"
	end

	def hashString(string,salt)
		#TODO: fill this in
	end

	def hashBytes(bytes,salt)
		#TODO: fill this in
	end

	#does not use an initialization vector - assume that the username / password combo is unique
	def encryptUserPrivateKey(userId,password,salt,privateKey)
		privateKeyCipher = OpenSSL::PKey::Cipher.new(AES_TYPE)
		privateKeyCipher.encrypt

		privateKeyKeyPassPhrase = genPassphrase(userId,password)

		privateKeyCipher.pkcs5_keyivgen(privateKeyKeyPassword,salt)
	
		privateKeyEncrypted = privateKeyCipher.update(privateKey)
		privateKeyEncrypted << privateKeyCipher.final
	end

	def decryptUserPrivateKey(userId,password,salt,privateKeyEncrypted)
		privateKeyCipher = OpenSSL::PKey::Cipher.new(AES_TYPE)
		privateKeyCipher.decrypt

		privateKeyKeyPassPhrase = genPassphrase(userId,password)
	
		privateKeyCipher.pkcs5_keyivgen(privateKeyKeyPassword,salt)
	
		privateKey = privateKeyCipher.update(privateKeyEncrypted)
		privateKey << privateKeyCipher.final
	end

	def decryptDataWithCredentials(userId,password,salt,privateKeyEncrpyted)
		decryptUserPrivateKey(userId,password,salt,privateKeyEncrypted)
		decryptDataWithPrivateKey(privateKeyDecrypted)
	end

	def encryptDataWithPublicKey
		#TODO: fill this in
	end

	def decryptDataWithPrivateKey
		#TODO: fill this in
	end

	def createRsaKeys
		OpenSSL::PKey::RSA.new(RSA_BIT_LENGTH)
		#TODO: now how do I return the byte stream?
	end

	def createPassphraseKeyPair(userId,password,salt)
		publicKey, unencryptedPrivateKey = createRsaKeys

		return publicKey, encryptPrivateKey(userId,password,salt,unencryptedPrivateKey)
	end
end
