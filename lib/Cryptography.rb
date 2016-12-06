require 'openssl'
require 'base64'

#TODO: make methods public and private, as appropriate
class Cryptography

	NUM_PBKDF_ITERATIONS = 10000 #tailor this to performance requirements

	AES_TYPE = "AES-128-CBC"
	SHA_TYPE = "SHA512"

	SALT_BYTE_LENGTH = 16
	AES_BYTE_LENGTH  = 16 #TODO: decide whether we can use this for all digests
	RSA_BIT_LENGTH   = 4096

	#no two passphrases should be alike
	def self.genUserPassPhrase(userId,password)
		"#{userId} #{password}"
	end

	def self.genSaltedString(string,salt) #note that the salt is in fact a string
		"#{string}#{salt}" #no extra space in the middle (in order to reduce predictability)
	end

	def self.digestStringWithSalt(string,salt)
		OpenSSL::Digest.digest(SHA_TYPE,genSaltedString(string,salt)).unpack('C*').join(" ")
	end

	def self.digestSensitiveStringWithSalt(string,salt)
		OpenSSL::PKCS5.pbkdf2_hmac_sha1(string,salt,NUM_PBKDF_ITERATIONS,AES_BYTE_LENGTH).unpack('C*').join(" ")
	end
	
	def self.digestUserCredentialsWithSalt(userId,password,salt)
		digestSensitiveStringWithSalt(genUserPassPhrase(userId,password),salt)
	end

	#does not use an initialization vector - assume that the username / password combo is unique
	#uses PKCS to make life harder for dictionary attackers
	def self.generateEncryptedPems(userId,password,salt)
		privateKeyCipher     = OpenSSL::Cipher.new(AES_TYPE)
		privateKeyPassphrase = digestUserCredentialsWithSalt(userId,password,salt)
		rsa                  = OpenSSL::PKey::RSA.new(RSA_BIT_LENGTH)
		
		publicKeyPem           = rsa.public_key.to_pem
		privateKeyEncryptedPem = rsa.to_pem(privateKeyCipher,privateKeyPassphrase)
		
		return publicKeyPem, privateKeyEncryptedPem #these are both simply pem-encoded strings
	end

	def self.decryptPrivateKeyPem(userId,password,salt,privateKeyPem)
		privateKeyCipher     = OpenSSL::Cipher.new(AES_TYPE)
		privateKeyPassphrase = digestUserCredentialsWithSalt(userId,password,salt)
		rsa                  = OpenSSL::PKey::RSA.new(privateKeyPem,privateKeyPassphrase)
		
		privateKeyDecryptedPem = rsa.to_pem
	end

	def self.encryptWithPublicKeyPem(data,publicKeyPem)
		rsa = OpenSSL::PKey::RSA.new(publicKeyPem)
		Base64.encode64(rsa.public_encrypt(data))
	end

	def self.decryptWithPrivateKeyPem(encryptedData,privateKeyPem)
		rsa = OpenSSL::PKey::RSA.new(privateKeyPem)
		rsa.private_decrypt(Base64.decode64(encryptedData))
	end

	def self.decryptDataWithCredentials(userId,password,salt,encryptedData,encryptedPrivateKeyPem)
		privateKeyPem = decryptPrivateKeyPem(userId,password,salt,encryptedPrivateKeyPem)
		decryptWithPrivateKeyPem(encryptedData,privateKeyPem)
	end
	
end
