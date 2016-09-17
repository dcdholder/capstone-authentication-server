require 'openssl'

#TODO: make methods public and private, as appropriate
class Cryptography

	NUM_PBKDF_ITERATIONS = 100000 #tailor this to performance requirements
	SALT_BYTE_LENGTH     = 16
	AES_TYPE             = "AES-128-CBC"
	SHA_TYPE             = "SHA512"
	AES_BYTE_LENGTH      = 16
	RSA_BIT_LENGTH       = 4096

	#no two passphrases should be alike
	def self.genUserPassPhrase(userId,password)
		"#{userId} #{password}"
	end

	def self.genSaltedString(string,salt)
		"#{string}#{salt}" #no extra space in the middle (in order to reduce predictability)
	end

	def self.digestStringWithSalt(string,salt)
		OpenSSL::Digest.digest(SHA_TYPE,genSaltedString(string,salt))
	end

	#does not use an initialization vector - assume that the username / password combo is unique
	#uses PKCS to make life harder for dictionary attackers
	def self.generateEncryptedPems(userId,password,salt)
		privateKeyCipher     = OpenSSL::Cipher.new(AES_TYPE)
		privateKeyPassphrase = OpenSSL::PKCS5.pbkdf2_hmac_sha1(genUserPassPhrase(userId,password), salt, NUM_PBKDF_ITERATIONS, AES_BYTE_LENGTH)
		rsa                  = OpenSSL::PKey::RSA.new(RSA_BIT_LENGTH)
		
		publicKeyPem           = rsa.public_key.to_pem
		privateKeyEncryptedPem = rsa.to_pem(privateKeyCipher,privateKeyPassphrase)
		
		return publicKeyPem, privateKeyEncryptedPem #these are both simply pem-encoded strings
	end

	def self.decryptPrivateKeyPem(userId,password,salt,privateKeyPem)
		privateKeyCipher     = OpenSSL::Cipher.new(AES_TYPE)
		privateKeyPassphrase = OpenSSL::PKCS5.pbkdf2_hmac_sha1(genUserPassPhrase(userId,password), salt, NUM_PBKDF_ITERATIONS, AES_BYTE_LENGTH)
		rsa                  = OpenSSL::PKey::RSA.new(privateKeyPem,privateKeyPassphrase)
		
		privateKeyDecryptedPem = rsa.to_pem
	end

	def self.encryptWithPublicKeyPem(data,publicKeyPem)
		rsa = OpenSSL::PKey::RSA.new(publicKeyPem)
		rsa.public_encrypt(data)
	end

	def self.decryptWithPrivateKeyPem(encryptedData,privateKeyPem)
		rsa = OpenSSL::PKey::RSA.new(privateKeyPem)
		rsa.private_decrypt(encryptedData)
	end

	def self.decryptDataWithCredentials(userId,password,salt,encryptedData,encryptedPrivateKeyPem)
		privateKeyPem = decryptPrivateKeyPem(userId,password,salt,encryptedPrivateKeyPem)
		decryptWithPrivateKeyPem(encryptedData,privateKeyPem)
	end
	
end
