require mysql2

class Database
	#TODO: get all this shit to work in a RESTful way (ugh)
	#TODO: decide whether to use Rails' ActiveRecord instead of SQL statements

	MIN_USERNAME_LENGTH = 4
	MAX_USERNAME_LENGTH = 100

	MIN_PASSWORD_LENGTH = 8
	MAX_PASSWORD_LENGTH = 100

	#TODO: decide whether any of this can stay
	JSON_KEYS = {
		"Add Admin"        => ["Request Type", "Admin ID", "Admin Password"],
		"Add User"         => ["Request Type", "User ID", "User Password"],
		"Add Device"       => ["Request Type", "Device ID"],
		"Set Ownership"    => [],
		"Set Usership"     => [],
		"Verify Usership"  => [],
		"Verify Ownership" => [],
		"Revoke Usership"  => [],
		"Revoke Ownership" => [],
		"Get Tag"          => []
	}

	#TODO: device whether any of this can stay
	#JSON reader
	def readJsonRequest(jsonRequest)
		if !jsonRequest.has_key?("Request Type")
			raise "No 'Request Type' field in JSON request"
		elsif !JSON_KEYS.has_key?(jsonRequest["Request Type"])
			raise "Invalid 'Request Type' field contents"
		elsif JSON_KEYS[jsonRequest["Request Type"]].sort != jsonRequest.keys.sort
			raise "Incorrect set of hash keys in JSON request" #TODO: should specify which ones are incorrect
		end
	
		#TODO: fill the rest of the cases in
		case jsonRequest["Request Type"]
		when "Add Admin"
			addAdmin(jsonRequest["Admin ID"],jsonRequest["Admin Password"])
		when "Add User"
			addUser(jsonRequest["User ID"],jsonRequest["User Password"])
		when "Add Device"
			addDevice(jsonRequest["Admin ID"], jsonRequest["Admin Password"], jsonRequest["Device ID"])
		when "Set Usership"
		
		when "Set Ownership"
	
		when "Verify Usership"

		when "Verify Ownership"

		when "Revoke Usership"

		when "Revoke Ownership"

		end
	end

	=begin

	#encryption stuff
	def encryptTag(tag)
		#TODO: fill this in
	end

	def decryptTag(encryptedTag)
		#TODO: fill this in
	end

	def newSalt()
		#TODO: fill this in
	end

	=end

	#password stuff
	def adminPasswordCorrect?(adminId,password)
		adminIdHash = adminIdHashFromAdminId(adminId)
	
		passwordHashAndSaltResult = sql.query("SELECT passwordHash,passwordSalt FROM admins WHERE adminIdHash=#{adminIdHash}")
		passwordHash = passwordHashAndSaltResult[0]["passwordHash"]
		passwordSalt = passwordHashAndSaltResult[0]["passwordSalt"]
	
		if passwordHash==hashString(adminId,passwordSalt)
			return true
		else
			return false
		end
	end

	def userPasswordCorrect?(userId,password)
		userIdHash = userIdHashFromUserId(userId)
	
		passwordHashAndSaltResult = sql.query("SELECT passwordHash,passwordSalt FROM users WHERE userIdHash=#{userIdHash}")
		passwordHash = passwordHashAndSaltResult[0]["passwordHash"]
		passwordSalt = passwordHashAndSaltResult[0]["passwordSalt"]
	
		if passwordHash==hashString(userId,passwordSalt)
			return true
		else
			return false
		end
	end

	def confirmiIdFormatCorrect(userId)
		#enforce a minimum and maximum username length
		if userId.length<MIN_USERNAME_LENGTH
			raise "Username must be at least #{MIN_USERNAME_LENGTH} characters"
		elsif userId.length>MAX_USERNAME_LENGTH
			raise "Username must be at most #{MAX_USERNAME_LENGTH} characters"
		end
	
		#enforce a certain character set - underscores and alphanumerics
		if !(userId =~ /[a-zA-Z0-9_]{userId.length}/)
			raise "Cannot use username with invalid characters"
		end
	end

	def confirmPasswordFormatCorrect(password)
		#enforce a minimum and maximum password length
		if password.length<MIN_PASSWORD_LENGTH
			raise "Password must be at least #{MIN_PASSWORD_LENGTH} characters"
		elsif
			raise "Password must be at most #{MAX_PASSWORD_LENGTH} characters"
		end
	
		#enforce a certain character set - same as userId for now
		if !(password =~ /[a-zA-Z0-9_]{userId.length}/)
			raise "Cannot use password with invalid characters"
		end
	end

	#permissions
	def deviceOwned?(deviceId)
		deviceIdHash = deviceIdHashFromDeviceId(deviceId)
	
		numDeviceOwnersResult = sql.query("SELECT COUNT(*) FROM deviceOwnership WHERE deviceIdHash=#{deviceIdHash}")
		if numDeviceOwnersresult[0][0]==0
			return false
		elsif numeDeviceOwnersResult[0][0]==1
			return true
		end
	end

	def userOwnsDevice?(userId,deviceId)
		userIdHash   = userIdHashFromUserId(userId)
		deviceIdHash = deviceIdHashFromDeviceId(deviceId)
	
		numMatchingDeviceOwnershipsResults = sql.query("SELECT COUNT(*) FROM deviceOwnership WHERE ownerIdHash=#{userIdHash} AND deviceIdHash=#{deviceIdHash}")
		if numMatchingDeviceOwnershipsResults[0][0]==0
			return false
		elsif numMatchingDeviceOwnershipsResults[0][0]==1
			return true
		end
	end

	def userCanAccessDevice?(userId,deviceId)
		userIdHash   = userIdHashFromUserId(userId)
		deviceIdHash = deviceIdHashFromDeviceId(deviceId)
	
		numMatchingDeviceUsershipsResults = sql.query("SELECT COUNT(*) FROM deviceUsership WHERE userIdHash=#{userIdHash} AND deviceIdHash=#{deviceIdHash}")
		if numMatchingDeviceUsershipsResults[0][0]==0
			return false
		elsif numMatchingDeviceUsershipsResults[0][0]==1
			return true
		end
	end

	#existence
	def adminExists?(adminId)
		adminIdHash = adminIdHashFromAdminId(adminId)
	
		numMatchingAdminsResult = sql.query("SELECT COUNT(*) FROM admins WHERE adminIdHash=#{adminIdHash}")
		if numMatchingAdminsResult[0][0]==0
			return false
		elsif numMatchingAdminsResult[0][0]==1
			return true
		end
	end

	def userExists?(userId)
		userIdHash = userIdHashFromUserId(userId)
	
		numMatchingUsersResult = sql.query("SELECT COUNT(*) FROM users WHERE userIdHash=#{userIdHash}")
		if numMatchingUsersResult[0][0]==0
			return false
		elsif numMatchingUsersResult[0][0]==1
			return true
		end
	end

	def deviceExists?(deviceId)
		deviceIdHash = deviceIdHashFromDeviceId(deviceId)
	
		numMatchingDevicesResult = sql.query("SELECT COUNT(*) FROM devices WHERE deviceIdHash=#{deviceIdHash}")
		if numMatchingDevicesResult[0][0]==0
			return false
		elsif numMatchingDevicesResult[0][0]==1
			return true
		end
	end

	#heavier db logic - we assume that any poisonous input has already been filtered out
	def addAdminToDb(adminId,password)
		adminSalt    = newSalt()
		adminIdHash  = hashString(adminId,adminSalt)
		passwordSalt = newSalt()
		passwordHash = hashString(password,passwordSalt)
	
		sql.query("INSERT INTO admins (adminIdHash,adminIdSalt,passwordHash,passwordSalt) VALUES(#{adminIdHash},#{adminIdSalt},#{passwordHash},#{passwordSalt})")
	end

	def addUserToDb(userId,password)
		userIdHash   = userIdHashFromUserId(userId)
		passwordSalt = newSalt()
		passwordHash = hashString(password,passwordSalt)
	
		sql.query("INSERT INTO users (userIdHash,passwordHash,passwordSalt) VALUES(#{userIdHash},#{passwordHash},#{passwordSalt})")
	end

	def addDeviceToDb(deviceId)
		deviceIdHash = deviceIdHashFromDeviceId(deviceId)

		sql.query("INSERT INTO devices (deviceIdHash) VALUES(#{deviceIdHash})")
	end

	def setOwnershipInDb(ownerId,deviceId)
		ownerIdHash  = userIdHashFromUserId(ownerId)
		deviceIdHash = deviceIdHashFromDeviceId(deviceId)
	
		sql.query("INSERT INTO deviceOwnership (deviceIdHash,ownerIdHash) VALUES(#{deviceIdHash},#{ownerIdHash})")
		sql.query("INSERT INTO deviceUsership (deviceIdHash,userIdHash,ownerIdHash) VALUES(#{deviceIdHash},#{ownerIdHash},#{ownerIdHash})")
	end

	def setUsershipInDb(owner,userId,deviceId)
		userIdHash   = userIdHashFromUserId(userId)
		ownerIdHash  = userIdHashFromUserId(ownerId)
		deviceIdHash = deviceIdHashFromDeviceId(deviceId)
	
		sql.query("INSERT INTO deviceUsership (deviceIdHash,userIdHash,ownerIdHash) VALUES(#{deviceIdHash},#{userIdHash},#{ownerIdHash})")
	end

	def revokeUsershipInDb(userId,deviceId)
		userIdHash   = userIdHashFromUserId(userId)
		deviceIdHash = deviceIdHashFromDeviceId(deviceId)
	
		sql.query("DELETE FROM deviceUsership  WHERE deviceIdHash=#{deviceIdHash} AND userIdHash=#{ownerIdHash}")
	end

	def revokeOwnershipInDb(ownerId,deviceId)
		ownerIdHash  = userIdHashFromUserId(userId)
		deviceIdHash = deviceIdHashFromDeviceId(ownerId,deviceId)

		sql.query("DELETE FROM deviceOwnership WHERE deviceIdHash=#{deviceIdHash} AND ownerIdHash=#{ownerIdHash}")
		sql.query("DELETE FROM deviceUsership  WHERE deviceIdHash=#{deviceIdHash} AND userIdHash=#{ownerIdHash}")
	end

	def getTagFromDb(userId,password,deviceId)
		deviceIdHash = deviceIdHashFromDeviceId(userId,deviceId)

		tagNullResult = sql.query("SELECT deviceTagCipher FROM deviceUsership WHERE deviceIdHash=#{deviceIdHash}")
		if tagNullResult[0][0]==NULL
			raise "No tag set for this device"
		end

		tagCipherResult = sql.query("SELECT deviceTagCipher FROM deviceUsership WHERE deviceIdHash=#{deviceIdHash}")
		tag = decryptTag(tagCipherResult[0][0],password)
	
		return tag
	end

	def adminIdHashFromAdminId(adminId)
		adminIdHashAndSaltResults = sql.query("SELECT adminIdHash,adminIdSalt FROM admins")
		adminIdHashAndSaltResults.each_hash do |adminIdHashAndSaltResult|
			adminIdHash = adminIdHashAndSaltResult["adminIdHash"]
			adminIdSalt = adminIdHashAndSaltResult["adminIdSalt"]
		
			if hashInt(adminId,adminIdSalt)==adminIdHash
				return adminIdHash
			end
		end
	
		raise "Admin not found"
	end

	def userIdHashFromUserId(userId)
		userIdSaltResult = sql.query("SELECT salt FROM globalSalts WHERE fieldName='userId'")
		userIdHash = hashString(userId,userIdSaltResult[0][0])
	
		return userIdHash
	end

	def deviceIdHashFromDeviceId(deviceId)
		deviceIdSaltResult = sql.query("SELECT salt FROM globalSalts WHERE fieldName='deviceId'")
		deviceIdHash = hashInt(deviceId,deviceIdSaltResult[0][0])
	
		return deviceIdHash
	end

	#exception-throwing filters
	def confirmAdminCredentials(username,password)
		if !adminExists?(adminId)
			raise "Unknown admin"
		elsif !adminPasswordCorrect?(adminId,adminPassword)
			raise "Incorrect password"
		end
	end

	def confirmUserCredentials(username,password)
		if !userExists?(ownerId)
			raise "Unknown user"
		elsif !userPasswordCorrect?(ownerId,ownerPassword)
			raise "Incorrect password"
		end
	end

	def confirmDeviceOwnership(username,deviceId)
		if !deviceExists?(deviceId)
			raise "Device does not exist"
		elsif !userOwnsDevice?(username,deviceId)
			raise "User does not own device"
		end
	end

	def confirmDeviceUsership(userID,deviceId)
		if !deviceExists?(deviceId)
			raise "Device does not exist"
		elsif !userCanAccessDevice?(userId,deviceId)
			raise "User cannot access device"
		end
	end

	#must verify credentials before returning any meaningful information
	def addAdmin(adminId,password)
		if adminExists?(adminId)
			raise "Admin already exists"
		end
	
		confirmUserFormatCorrect(userId)
		confirmPasswordFormatCorrect(password)

		addAdminToDb(userId,password)
	end

	def addUser(userId,password)
		if userExists?(userId)
			raise "User already exists"
		end
	
		confirmUserFormatCorrect(userId)
		confirmPasswordFormatCorrect(password)

		addUserToDb(userId,password)
	end

	def addDevice(adminId,adminPassword,deviceId)
		confirmAdminCredentials(adminId,adminPassword)
	
		if deviceExists?(deviceId)
			raise "Cannot create device - device already exists"
		end
	
		addDeviceToDb(adminId,adminPassword,deviceId)
	end

	def setOwnership(ownerId,ownerPassword,deviceId)
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

	def setUsership(ownerId,ownerPassword,userId,deviceId)
		confirmUserCredentials(ownerId,ownerPassword)
		confirmDeviceOwnership(ownerId,deviceId)

		if !userExists?(userId)
			raise "Cannot assign usership - unknown user"
		end
	
		setUsershipInDb(ownerId,ownerPassword,userId,deviceId)
	end

	def isDeviceOwner?(ownerId,password,deviceId)
		confirmUserCredentials(ownerId,password)

		begin
			confirmDeviceOwnership(ownerID,deviceId)
		rescue
			return false
		end
	
		return true
	end

	def isDeviceUser?(userId,password,deviceId)
		confirmUserCredentials(userId,password)

		begin
			confirmDeviceUsership(userID,deviceId)
		rescue
			return false
		end
	
		return true
	end

	def revokeUsership(ownerId,ownerPassword,userId,deviceId)
		confirmUserCredentials(ownerId,ownerPassword)
		confirmDeviceOwnership(ownerId,deviceId)
	
		if !userExists?(userId)
			raise "Cannot revoke usership - unknown user"
		elsif !userCanAccessDevice?(userId,deviceId)
			raise "User did not have usership rights"
		end
	
		revokeUsershipInDb(userId,deviceId)
	end

	def revokeOwnership(adminId,adminPassword,ownerId,deviceId)
		confirmAdminCredentials(adminId,adminPassword)
		confirmDeviceOwnership(ownerId,deviceId)

		revokeOwnershipInDb(ownerId,deviceId)
	end

	def getTag(userId, password, deviceId)
		confirmUserCredentials(userId,password)
		confirmDeviceUsership(userId,password)

		getTagFromDb(userId,password,deviceId)
	end
end
