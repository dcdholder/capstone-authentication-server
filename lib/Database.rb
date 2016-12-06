require 'mysql2'

require_relative './Cryptography.rb'

class Database
	MIN_USERNAME_LENGTH = 4
	MAX_USERNAME_LENGTH = 100

	MIN_PASSWORD_LENGTH = 8
	MAX_PASSWORD_LENGTH = 100

	USER_SALT   = "\x00" * 32 #TODO: should not be hardcoded
	DEVICE_SALT = "\x00" * 32 #TODO: should not be hardcoded

	SQL = Mysql2::Client.new(:host => "localhost", :username => "admin", :password => nil)

	#initialization
	def self.burnEverything()
		SQL.select_db("bleDevice")
		SQL.query("TRUNCATE table deviceOwnership")
		SQL.query("TRUNCATE table deviceUsership")
		SQL.query("TRUNCATE table admins")
		SQL.query("TRUNCATE table users")
		SQL.query("TRUNCATE table devices")
	end

	#initialization
	#def initDb
		#SQL.query("INSERT INTO globalSalts (fieldName,salt) VALUES(user,#{USER_SALT})")
		#SQL.query("INSERT INTO globalSalts (fieldName,salt) VALUES(device,#{DEVICE_SALT})")
	#end

	#encryption stuff
	def self.getPublicPem(username)
		usernameHash = userIdHashFromUserId(username)
		SQL.query("SELECT publicKey FROM users WHERE userIdHash=\'#{usernameHash}\'").each do |publicPemResult|
			return publicPemResult["publicKey"]
		end
	end
	
	def self.getPrivatePem(username,password)
		confirmUserCredentials(username,password)
		usernameHash = userIdHashFromUserId(username)
	
		SQL.query("SELECT privateKeyCipher FROM users WHERE userIdHash=\'#{usernameHash}\'").each do |encryptedPemResult|
			return Cryptography.decryptPrivateKeyPem(username,password,USER_SALT,encryptedPemResult["privateKeyCipher"])
		end
	end
	
	def self.decryptString(user,password,encryptedData)
		privatePem = getPrivatePem(user,password)
		return Cryptography.decryptWithPrivateKeyPem(encryptedData,privatePem)
	end

	def self.encryptString(user,tag)
		publicPem  = getPublicPem(user)
		encryptedString = Cryptography.encryptWithPublicKeyPem(tag,publicPem)
		
		return Cryptography.encryptWithPublicKeyPem(tag,publicPem)
	end

	#not in use - salts are currently hard-coded to allow for frequent restarts
	def self.newSalt()
		return OpenSSL::Random.random_bytes(Cryptography::SALT_BYTE_LENGTH).unpack('C*').join(" ")
	end

	#password stuff
	def self.adminPasswordCorrect?(adminId,password)
		adminIdHash = adminIdHashFromAdminId(adminId)
	
		SQL.query("SELECT passwordHash,passwordSalt FROM admins WHERE adminIdHash=\'#{adminIdHash}\'").each do |passwordHashAndSaltResult|
			passwordHash = passwordHashAndSaltResult["passwordHash"]
			passwordSalt = passwordHashAndSaltResult["passwordSalt"]
			
			if passwordHash==Cryptography.digestStringWithSalt(password,passwordSalt)
				return true
			else
				return false
			end
		end
		
		return false
	end

	def self.userPasswordCorrect?(userId,password)
		userIdHash = userIdHashFromUserId(userId)
	
		passwordHashAndSaltResult = SQL.query("SELECT passwordHash,passwordSalt FROM users WHERE userIdHash=\'#{userIdHash}\'").each do |passwordHashAndSaltResult|
			passwordHash = passwordHashAndSaltResult["passwordHash"]
			passwordSalt = passwordHashAndSaltResult["passwordSalt"]
			
			if passwordHash==Cryptography.digestStringWithSalt(password,passwordSalt)
				return true
			else
				return false
			end
		end
	end

	def self.confirmIdFormatCorrect(userId)
		#enforce a minimum and maximum username length
		if userId.length<MIN_USERNAME_LENGTH
			raise "Username must be at least #{MIN_USERNAME_LENGTH} characters"
		elsif userId.length>MAX_USERNAME_LENGTH
			raise "Username must be at most #{MAX_USERNAME_LENGTH} characters"
		end
	
		#enforce a certain character set - underscores and alphanumerics
		if !(userId =~ /^[a-zA-Z0-9_]+$/)
			raise "Cannot use username with invalid characters"
		end
	end

	def self.confirmPasswordFormatCorrect(password)
		#enforce a minimum and maximum password length
		if password.length<MIN_PASSWORD_LENGTH
			raise "Password must be at least #{MIN_PASSWORD_LENGTH} characters"
		elsif password.length>MAX_PASSWORD_LENGTH
			raise "Password must be at most #{MAX_PASSWORD_LENGTH} characters"
		end
	
		#enforce a certain character set - same as userId for now
		if !(password =~ /^[a-zA-Z0-9_]+$/) #TODO: increase the size of allowed character set
			raise "Cannot use password with invalid characters"
		end
	end

	#permissions
	def self.deviceOwned?(deviceId)
		deviceIdHash = deviceIdHashFromDeviceId(deviceId)
	
		SQL.query("SELECT COUNT(*) FROM deviceOwnership WHERE deviceIdHash=\'#{deviceIdHash}\'").each do |numDeviceOwnersResult|
			if numDeviceOwnersResult["COUNT(*)"]==0
				return false
			elsif numDeviceOwnersResult["COUNT(*)"]==1
				return true
			end
		end
	end

	def self.userOwnsDevice?(userId,deviceId)
		userIdHash   = userIdHashFromUserId(userId)
		deviceIdHash = deviceIdHashFromDeviceId(deviceId)
	
		SQL.query("SELECT COUNT(*) FROM deviceOwnership WHERE ownerIdHash=\'#{userIdHash}\' AND deviceIdHash=\'#{deviceIdHash}\'").each do |numMatchingDeviceOwnershipsResults|
			if numMatchingDeviceOwnershipsResults["COUNT(*)"]==0
				return false
			elsif numMatchingDeviceOwnershipsResults["COUNT(*)"]==1
				return true
			end
		end
	end

	def self.userCanAccessDevice?(userId,deviceId)
		userIdHash   = userIdHashFromUserId(userId)
		deviceIdHash = deviceIdHashFromDeviceId(deviceId)
	
		SQL.query("SELECT COUNT(*) FROM deviceUsership WHERE userIdHash=\'#{userIdHash}\' AND deviceIdHash=\'#{deviceIdHash}\'").each do |numMatchingDeviceUsershipsResults|
			if numMatchingDeviceUsershipsResults["COUNT(*)"]==0
				return false
			elsif numMatchingDeviceUsershipsResults["COUNT(*)"]==1
				return true
			end
		end
	end

	#existence
	def self.adminExists?(adminId)
		begin
			adminIdHash = adminIdHashFromAdminId(adminId)
		rescue
			return false
		end
	
		numMatchingAdminsResult = SQL.query("SELECT COUNT(*) FROM admins WHERE adminIdHash=\'#{adminIdHash}\'")
		numMatchingAdminsResult.each do |row| 
			if row["COUNT(*)"]==0
				return false
			elsif row["COUNT(*)"]==1
				return true
			end
		end
	end

	def self.userExists?(userId)
		userIdHash = userIdHashFromUserId(userId)
	
		numMatchingUsersResult = SQL.query("SELECT COUNT(*) FROM users WHERE userIdHash=\'#{userIdHash}\'")
		numMatchingUsersResult.each do |row|
			if row["COUNT(*)"]==0
				return false
			elsif row["COUNT(*)"]==1
				return true
			end
		end
	end

	def self.deviceExists?(deviceId)
		deviceIdHash = deviceIdHashFromDeviceId(deviceId)
	
		numMatchingDevicesResult = SQL.query("SELECT COUNT(*) FROM devices WHERE deviceIdHash=\'#{deviceIdHash}\'")
		numMatchingDevicesResult.each do |row|
			if row["COUNT(*)"]==0
				return false
			elsif row["COUNT(*)"]==1
				return true
			end
		end
	end

	#heavier db logic - we assume that any poisonous input has already been filtered out
	def self.addAdminToDb(adminId,password)
		adminIdSalt  = newSalt()
		adminIdHash  = Cryptography.digestStringWithSalt(adminId,adminIdSalt)
		passwordSalt = newSalt()
		passwordHash = Cryptography.digestStringWithSalt(password,passwordSalt)
	
		SQL.query("INSERT INTO admins (adminIdHash,adminIdSalt,passwordHash,passwordSalt) VALUES(\'#{adminIdHash}\',\'#{adminIdSalt}\',\'#{passwordHash}\',\'#{passwordSalt}\')")
	end

	def self.addUserToDb(userId,password)
		userIdHash   = userIdHashFromUserId(userId)
		passwordSalt = newSalt()
		passwordHash = Cryptography.digestStringWithSalt(password,passwordSalt)
		publicPem,privatePem = Cryptography.generateEncryptedPems(userId,password,USER_SALT)
	
		SQL.query("INSERT INTO users (userIdHash,passwordHash,passwordSalt,publicKey,privateKeyCipher) VALUES(\'#{userIdHash}\',\'#{passwordHash}\',\'#{passwordSalt}\',\'#{publicPem}\',\'#{privatePem}\')")
	end

	def self.addDeviceToDb(deviceId)
		deviceIdHash = deviceIdHashFromDeviceId(deviceId)

		SQL.query("INSERT INTO devices (deviceIdHash) VALUES(\'#{deviceIdHash}\')")
	end

	def self.setOwnershipInDb(ownerId,password,deviceId)
		ownerIdHash  = userIdHashFromUserId(ownerId)
		deviceIdHash = deviceIdHashFromDeviceId(deviceId)
	
		SQL.query("INSERT INTO deviceOwnership (deviceIdHash,ownerIdHash) VALUES(\'#{deviceIdHash}\',\'#{ownerIdHash}\')")
		setUsershipInDb(ownerId,password,ownerId,deviceId,true) #owner is also a user, naturally
		#SQL.query("INSERT INTO deviceUsership (deviceIdHash,userIdHash,ownerIdHash) VALUES(\'#{deviceIdHash}\',\'#{ownerIdHash}\',\'#{ownerIdHash}\')")
	end

	def self.setUsershipInDb(owner,password,userId,deviceId,initialSetting=false)
		userIdHash   = userIdHashFromUserId(userId)
		ownerIdHash  = userIdHashFromUserId(owner)
		deviceIdHash = deviceIdHashFromDeviceId(deviceId)
		
		deviceTag = deviceId
		if !initialSetting
			deviceIdMap  = getAllOwnedDevicesFromDb(owner,password)
			deviceTag    = deviceIdMap[deviceId]
		end
		
		deviceIdCipher  = encryptString(userId,deviceId)
		deviceTagCipher = encryptString(userId,deviceTag) #device name is initially the device tag if bool is set
		userIdCipher    = encryptString(owner,userId)
		
		SQL.query("INSERT INTO deviceUsership (deviceIdHash,userIdHash,ownerIdHash,deviceIdCipher,deviceTagCipher,userIdCipher) VALUES(\'#{deviceIdHash}\',\'#{userIdHash}\',\'#{ownerIdHash}\',\'#{deviceIdCipher}\',\'#{deviceTagCipher}\',\'#{userIdCipher}\')")
	end

	def self.revokeUsershipInDb(userId,deviceId)
		userIdHash   = userIdHashFromUserId(userId)
		deviceIdHash = deviceIdHashFromDeviceId(deviceId)
	
		SQL.query("DELETE FROM deviceUsership  WHERE deviceIdHash=\'#{deviceIdHash}\' AND userIdHash=\'#{userIdHash}\'")
	end

	def self.revokeOwnershipInDb(ownerId,deviceId)
		ownerIdHash  = userIdHashFromUserId(userId)
		deviceIdHash = deviceIdHashFromDeviceId(ownerId,deviceId)

		SQL.query("DELETE FROM deviceOwnership WHERE deviceIdHash=\'#{deviceIdHash}\' AND ownerIdHash=\'#{ownerIdHash}\'")
		SQL.query("DELETE FROM deviceUsership  WHERE deviceIdHash=\'#{deviceIdHash}\' AND userIdHash=\'#{ownerIdHash}\'")
	end

	def self.getAllUserHashesFromDb()
		userHashes = Array.new()
		result = SQL.query("SELECT userIdHash FROM users")
		result.each do |row|
			userHashes << row["userIdHash"]
		end
		
		return userHashes
	end
	
	def self.getAllDeviceHashesFromDb()
		deviceHashes = Array.new()
		result = SQL.query("SELECT deviceIdHash FROM devices")
		result.each do |row|
			deviceHashes << row[0]
		end
		
		return deviceHashes
	end

	def self.getAllOwnedDevicesFromDb(ownerId,password)
		ownerIdHash = userIdHashFromUserId(ownerId)
		
		queryResult = SQL.query("SELECT deviceIdCipher,deviceTagCipher FROM deviceUsership WHERE userIdHash=\'#{ownerIdHash}\' AND ownerIdHash=\'#{ownerIdHash}\'")
		ownedDeviceMapping = Hash.new
		queryResult.each do |idTagCipherPair|
			#map the decrypted device tags by decrypted device IDs
			ownedDeviceMapping[decryptString(ownerId,password,idTagCipherPair["deviceIdCipher"])] = decryptString(ownerId,password,idTagCipherPair["deviceTagCipher"])
		end
		
		return ownedDeviceMapping
	end
	
	def self.mapOwnedDeviceUsersFromDb(ownerId,password)
		ownerIdHash = userIdHashFromUserId(ownerId)
		
		queryResult = SQL.query("SELECT deviceIdHash,userIdHash,deviceIdCipher,userIdCipher FROM deviceUsership WHERE ownerIdHash=\'#{ownerIdHash}\'")
		
		ownedDeviceHashMapping = Hash.new
		queryResult.each do |deviceUserCipherPair|
			if deviceUserCipherPair["userIdHash"]==ownerIdHash
				ownedDeviceHashMapping[deviceUserCipherPair["deviceIdHash"]] = decryptString(ownerId,password,deviceUserCipherPair["deviceIdCipher"])
			end
		end

		ownedDeviceUserMapping = Hash.new
		queryResult.each do |deviceUserCipherPair|
			#map the decrypted user IDs by decrypted device IDs
			
			if ownedDeviceHashMapping.has_key?(deviceUserCipherPair["deviceIdHash"])
				if !ownedDeviceUserMapping.has_key?(ownedDeviceHashMapping[deviceUserCipherPair["deviceIdHash"]])
					ownedDeviceUserMapping[ownedDeviceHashMapping[deviceUserCipherPair["deviceIdHash"]]] = Array.new
				end
				
				ownedDeviceUserMapping[ownedDeviceHashMapping[deviceUserCipherPair["deviceIdHash"]]] << decryptString(ownerId,password,deviceUserCipherPair["userIdCipher"])
			end
		end
		
		return ownedDeviceUserMapping
	end
	
	def self.getAllUsableDevicesFromDb(userId,password)
		userIdHash = userIdHashFromUserId(userId)
		
		queryResult = SQL.query("SELECT deviceIdCipher,deviceTagCipher FROM deviceUsership WHERE userIdHash=\'#{userIdHash}\'")
		usableDeviceMapping = Hash.new
		queryResult.each do |idTagCipherPair|
			#map the decrypted device tags by decrypted device IDs
			usableDeviceMapping[decryptString(userId,password,idTagCipherPair["deviceIdCipher"])] = decryptString(userId,password,idTagCipherPair["deviceTagCipher"])
		end
		
		return usableDeviceMapping
	end

	def self.setTagInDb(userId,password,deviceId,tag)
		ownerIdHash  = userIdHashFromUserId(userId)
		deviceIdHash = deviceIdHashFromDeviceId(deviceId)
	
		#collect all user hashes		
		SQL.query("SELECT userIdHash FROM deviceUsership WHERE deviceIdHash=\'#{deviceIdHash}\'").each do |userIdHashRow|
			userIdHash = userIdHashRow["userIdHash"]
			tagCipher  = encryptString(userId,tag) #encrypt with user's public key
			
			SQL.query("UPDATE deviceUsership SET deviceTagCipher=\'#{tagCipher}\' WHERE userIdHash=\'#{userIdHash}\' AND deviceIdHash=\'#{deviceIdHash}\'")
		end
	end

	def self.getTagFromDb(userId,password,deviceId)
		deviceIdHash = deviceIdHashFromDeviceId(deviceId)

		SQL.query("SELECT deviceTagCipher FROM deviceUsership WHERE deviceIdHash=\'#{deviceIdHash}\'").each do |tagNullResult|
			if tagNullResult["deviceTagCipher"]==nil
				raise "No tag set for this device"
			end
		end

		SQL.query("SELECT deviceTagCipher FROM deviceUsership WHERE deviceIdHash=\'#{deviceIdHash}\'").each do |tagCipherResult|
			return decryptString(userId,password,tagCipherResult["deviceTagCipher"])
		end
	end

	def self.adminIdHashFromAdminId(adminId)
		adminIdHashAndSaltResults = SQL.query("SELECT adminIdHash,adminIdSalt FROM admins")
		adminIdHashAndSaltResults.each do |adminIdHashAndSaltResult|
			adminIdHash = adminIdHashAndSaltResult["adminIdHash"]
			adminIdSalt = adminIdHashAndSaltResult["adminIdSalt"]
		
			if Cryptography.digestStringWithSalt(adminId,adminIdSalt)==adminIdHash
				return adminIdHash
			end
		end

		raise "Admin not found"
	end

	def self.userIdHashFromUserId(userId)
		#userIdSaltResult = SQL.query("SELECT salt FROM globalSalts WHERE fieldName='userId'")
		userIdHash = Cryptography.digestStringWithSalt(userId,USER_SALT)
	
		return userIdHash
	end

	def self.deviceIdHashFromDeviceId(deviceId)
		#deviceIdSaltResult = SQL.query("SELECT salt FROM globalSalts WHERE fieldName='deviceId'")
		deviceIdHash = Cryptography.digestStringWithSalt(deviceId,DEVICE_SALT)
	
		return deviceIdHash
	end

	#exception-throwing filters
	def self.confirmAdminCredentials(adminId,adminPassword)
		if !adminExists?(adminId)
			raise "Unknown admin"
		elsif !adminPasswordCorrect?(adminId,adminPassword)
			raise "Incorrect password"
		end
	end

	def self.confirmUserCredentials(userId,password)
		if !userExists?(userId)
			raise "Unknown user"
		elsif !userPasswordCorrect?(userId,password)
			raise "Incorrect password"
		end
	end

	def self.confirmDeviceOwnership(username,deviceId)
		if !deviceExists?(deviceId)
			raise "Device does not exist"
		elsif !userOwnsDevice?(username,deviceId)
			raise "User does not own device"
		end
	end

	def self.confirmDeviceUsership(userId,deviceId)
		if !deviceExists?(deviceId)
			raise "Device does not exist"
		elsif !userCanAccessDevice?(userId,deviceId)
			raise "User cannot access device"
		end
	end

	#must verify credentials before returning any meaningful information
	def self.addAdmin(adminId,password)
		if adminExists?(adminId)
			raise "Admin already exists"
		end
	
		confirmIdFormatCorrect(adminId)
		confirmPasswordFormatCorrect(password)

		addAdminToDb(adminId,password)
	end

	def self.addUser(userId,password)
		if userExists?(userId)
			raise "User already exists"
		end
	
		confirmIdFormatCorrect(userId)
		confirmPasswordFormatCorrect(password)

		addUserToDb(userId,password)
	end

	def self.addDevice(adminId,adminPassword,deviceId)
		confirmAdminCredentials(adminId,adminPassword)
	
		if deviceExists?(deviceId)
			raise "Cannot create device - device already exists"
		end
	
		addDeviceToDb(deviceId)
	end

	def self.setOwnership(ownerId,ownerPassword,deviceId)
		confirmUserCredentials(ownerId,ownerPassword)
	
		if !deviceExists?(deviceId)
			raise "Device does not exist"
		elsif userOwnsDevice?(ownerId,deviceId)
			raise "Registering user has already registered this device"
		elsif deviceOwned?(deviceId)
			raise "Another user has registered this device"
		end
	
		setOwnershipInDb(ownerId,ownerPassword,deviceId)
	end

	def self.setUsership(ownerId,ownerPassword,userId,deviceId)
		confirmUserCredentials(ownerId,ownerPassword)
		confirmDeviceOwnership(ownerId,deviceId)

		if !userExists?(userId)
			raise "Cannot assign usership - unknown user"
		end
	
		setUsershipInDb(ownerId,ownerPassword,userId,deviceId)
	end

	def self.isDeviceOwner?(ownerId,password,deviceId)
		confirmUserCredentials(ownerId,password)

		begin
			confirmDeviceOwnership(ownerID,deviceId)
		rescue
			return false
		end
	
		return true
	end

	def self.isDeviceUser?(userId,password,deviceId)
		confirmUserCredentials(userId,password)

		begin
			confirmDeviceUsership(userID,deviceId)
		rescue
			return false
		end
	
		return true
	end

	def self.revokeUsership(ownerId,ownerPassword,userId,deviceId)
		confirmUserCredentials(ownerId,ownerPassword)
		confirmDeviceOwnership(ownerId,deviceId)
	
		if !userExists?(userId)
			raise "Cannot revoke usership - unknown user"
		elsif !userCanAccessDevice?(userId,deviceId)
			raise "User did not have usership rights"
		end
	
		revokeUsershipInDb(userId,deviceId)
	end

	def self.revokeOwnership(adminId,adminPassword,ownerId,deviceId)
		confirmAdminCredentials(adminId,adminPassword)
		confirmDeviceOwnership(ownerId,deviceId)

		revokeOwnershipInDb(ownerId,deviceId)
	end

	def self.getAllUserHashes(adminId,password)
		confirmAdminCredentials(adminId,password)
		
		getAllUserHashesFromDb()
	end
	
	def self.getAllDeviceHashes(adminId,password)
		confirmAdminCredentials(adminId,password)
		
		getAllDeviceHashesFromDb()
	end

	def self.getAllOwnedDevices(ownerId,password)
		confirmUserCredentials(ownerId,password)
		
		getAllOwnedDevicesFromDb(ownerId,password)
	end
	
	def self.mapOwnedDeviceUsers(ownerId,password)
		confirmUserCredentials(ownerId,password)
		
		mapOwnedDeviceUsersFromDb(ownerId,password)
	end
	
	def self.getAllUsableDevices(userId,password)
		confirmUserCredentials(userId,password)
		
		getAllUsableDevicesFromDb(userId,password)
	end

	def self.setTag(ownerId,password,deviceId,deviceTag)
		confirmUserCredentials(ownerId,password)
		confirmDeviceOwnership(ownerId,deviceId)
		
		setTagInDb(ownerId,password,deviceId,deviceTag)
	end

	def self.getTag(userId,password,deviceId)
		confirmUserCredentials(userId,password)
		confirmDeviceUsership(userId,deviceId)

		getTagFromDb(userId,password,deviceId)
	end	
end
