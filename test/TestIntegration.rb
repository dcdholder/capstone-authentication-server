require 'test/unit'

class TestIntegration < Test::Unit::Testcase
	ADMIN_NAME     = "Admin123"
	ADMIN_PASSWORD = "Admin123password"
	
	USER_A_NAME     = "UserA123"
	USER_A_PASSWORD = "UserA123Password"
	
	USER_B_NAME     = "UserB123"
	USER_B_PASSWORD = "UserB123Password"
	
	DEVICE_ID_A     = "12345678"
	DEVICE_ID_B     = "01234567"
	
	DEVICE_STRING_A = "This is my device. Deal with it."
	DEVICE_STRING_B = "This is also my device. Deal with it again."

	def createUserTest
		assert_nothing_raised do
			burnEverything()
			
			adminSession = addAdmin(ADMIN_NAME,ADMIN_PASSWORD)
		
			if adminSession.listAllUsers() != nil
				raise("Database reports existing users before first user creation")
			end
		
			userSession = addUser(USER_A_NAME,USER_A_PASSWORD)
		
			if userSession.ownedDevices() != nil
				raise("Database reports existing owned devices in empty user")
			end
			if userSession.usableDevices() != nil
				raise("Database reports existing usable devices in empty user")
			end
		
			if adminSession.listAllUsers.length() != 1
				raise("Should be exactly 1 user in database, found #{adminSession.listAllUsers().length().to_s()}")
			elsif adminSession.listAllUsers[0] != USER_A_NAME
				raise("Should have username #{USER_A_NAME}, found #{adminSession.listAllUsers()[0]}")
			end
		end
	end
	
	def createDeviceTest
		assert_nothing_raised do
			burnEverything()
	
			adminSession = addAdmin(ADMIN_NAME,ADMIN_PASSWORD)
		
			if adminSession.listAllDevices() != nil
				raise("Database reports existing devices before first device creation")
			end
		
			adminSession.createDevice(DEVICE_ID_A)
		
			if adminSession.listAllDevices().length() != 1
				raise("Should be exactly 1 device in database, found #{adminSession.listAllDevices().length()}")
			elsif adminSession.listAllDevices()[0] != DEVICE_ID_A
				raise("Should have device ID #{DEVICE_ID_A}, found #{adminSession.listAllDevices()[0]}")
			end
		end
	end
	
	def listAllUsersTest
		createDeviceTest()
	end
	
	def listAllDevicesTest
		createDeviceTest()
	end
	
	def claimDeviceOwnershipTest
		assert_nothing_raised do
			burnEverything()
	
			adminSession = addAdmin(ADMIN_NAME,ADMIN_PASSWORD)
			adminSession.createDevice(DEVICE_ID_A)
		
			userSession = addUser(USER_A_NAME,USER_A_PASSWORD)
			userSession.claimDevice(DEVICE_ID_A)
		
			if userSession.listAllOwnedDevices().length() != 1
				raise("Should be exactly 1 owned device for user #{USER_A_NAME}, found #{userSession.listAllOwnedDevices().length()}")
			elsif userSession.listAllOwnedDevices()[0] != DEVICE_ID_A
				raise("Should have device ID #{DEVICE_ID_A}, found #{userSession.listAllOwnedDevices()[0]}")
			end
		end
	end
	
	def addDeviceUsershipTest
		burnEverything()
	
		assert_nothing_raised do
			adminSession = addAdmin(ADMIN_NAME,ADMIN_PASSWORD)
			adminSession.createDevice(DEVICE_ID_A)
		
			userSessionA = addUser(USER_A_NAME,USER_A_PASSWORD)
			userSessionA.claimDevice(DEVICE_ID_A)
		
			userSessionB = addUser(USER_B_NAME,USER_B_PASSWORD)
		
			userSessionA.addUserToDevice(DEVICE_ID_A,USER_B_NAME)
			deviceUserMap = userSessionA.mapAllDeviceUsers()
			if deviceUserMap.hasKey?(DEVICE_ID_A)
				if !deviceUserMap.include?(USER_B_NAME)
					raise("Could not find #{USER_B_NAME} in user list for device #{DEVICE_ID_A}")
				end
			else
				raise("Could not find device #{DEVICE_ID_A} in owned device map")
			end
		
			if userSessionB.listAllUsableDevices().length() != 1
				raise("Should be exactly one usable device for user #{USER_B_NAME}, found #{userSessionB.listAllUsableDevices().length()}")
			elsif userSession.listAllUsableDevices()[0] != DEVICE_ID_A
				raise("Should have device ID #{DEVICE_ID_A}, found #{userSessionB.listAllUsableDevices()[0]}")
			end
		end
	end
	
	def createAdminTest #just prove that this doesn't throw an exception
		assert_nothing_raised do
			burnEverything()
	
			adminSession = addAdmin(ADMIN_NAME,ADMIN_PASSWORD)
			adminSession.endSession()
		
			adminSession = startAdminSession(ADMIN_NAME,ADMIN_PASSWORD)
		end
	end
	
	def revokeDeviceUsershipTest
		assert_nothing_raised do
			burnEverything()
	
			adminSession = addAdmin(ADMIN_NAME,ADMIN_PASSWORD)
			adminSession.createDevice(DEVICE_ID_A)
		
			userSessionA = addUser(USER_A_NAME,USER_A_PASSWORD)
			userSessionB = addUser(USER_B_NAME,USER_B_PASSWORD)
			userSessionA.claimDevice(DEVICE_ID_A)
			userSessionA.addUserToDevice(DEVICE_ID_A,USER_B_NAME)
		
			if userSessionB.listAllUsableDevices().length() != 1
				raise("Should be exactly one usable device for user #{USER_B_NAME}, found #{userSessionB.listAllUsableDevices().length()}")
			elsif userSessionB.listAllUsableDevices()[0] != DEVICE_ID_A
				raise("Should have device ID #{DEVICE_ID_A}, found #{userSessionB.listAllUsableDevices()[0]}")
			end
		
			userSessionA.removeUserFromDevice(DEVICE_ID_A,USER_B_NAME)
		
			if userSessionB.listAllUsableDevices() != nil
				raise("Database reports existing usable devices after removing only device")
			end
		end
	end
	
	def setDeviceStringTest
		assert_nothing_raised do
			burnEverything()
	
			adminSession = addAdmin(ADMIN_NAME,ADMIN_PASSWORD)
			adminSession.createDevice(DEVICE_ID_A)
		
			userSessionA = addUser(USER_A_NAME,USER_A_PASSWORD)
			userSessionA.claimDevice(USER_A_NAME)
		
			userSessionA.setDeviceString(DEVICE_ID_A,DEVICE_STRING_A)
			if userSessionA.getDeviceString(DEVICE_ID_A) != DEVICE_STRING
				raise("Device string is #{userSessionA.getDeviceString(DEVICE_ID_A)}, should be #{DEVICE_STRING}")
			end
		end
	end
	
	def getDeviceStringTest
		setDeviceStringTest()
	end
	
	def getAllOwnedDeviceStringsTest
		assert_nothing_raised do
			burnEverything()
	
			adminSession = addAdmin(ADMIN_NAME,ADMIN_PASSWORD)
			adminSession.createDevice(DEVICE_ID_A)
			adminSession.createDevice(DEVICE_ID_B)
		
			userSessionA = addUser(USER_A_NAME,USER_A_PASSWORD)
			userSessionA.claimDevice(DEVICE_ID_A)
			userSessionA.claimDevice(DEVICE_ID_B)
		
			userSessionA.setDeviceString(DEVICE_ID_A,DEVICE_STRING_A)
			userSessionA.setDeviceString(DEVICE_ID_B,DEVICE_STRING_B)
		
			deviceStringsMap = userSessionA.mapAllDeviceStrings()
			if deviceStringsMap.hasKey?(DEVICE_ID_A) && deviceStringsMap.hasKey?(DEVICE_ID_B)
				if deviceStringsMap[DEVICE_ID_A]!=DEVICE_STRING_A || deviceStringsMap[DEVICE_ID_B]!=DEVICE_STRING_B
					raise("Input and output device strings did not match")
				end
			else
				raise("Could not find one or more of the device strings")
			end
		end
	end
	
	def getAllUsableDeviceStringsTest
		assert_nothing_raised do
			burnEverything()
	
			adminSession = addAdmin(ADMIN_NAME,ADMIN_PASSWORD)
			adminSession.createDevice(DEVICE_ID_A)
			adminSession.createDevice(DEVICE_ID_B)
		
			userSessionA = addUser(USER_A_NAME,USER_A_PASSWORD)
			userSessionA.claimDevice(DEVICE_ID_A)
			userSessionA.claimDevice(DEVICE_ID_B)
		
			userSessionA.setDeviceString(DEVICE_ID_A,DEVICE_STRING_A)
			userSessionA.setDeviceString(DEVICE_ID_B,DEVICE_STRING_B)
		
			userSessionB = addUser(USER_B_NAME,USER_B_PASSWORD)
			userSessionA.addUserToDevice(DEVICE_ID_A,USER_B_NAME)
			userSessionA.addUserToDevice(DEVICE_ID_B,USER_B_NAME)
		
			if userSessionB.listAllUsableDeviceStrings().length() != 2
				raise("Should be exactly 2 devices usable by #{USER_B_NAME}, found #{userSessionB.listAllUsableDeviceStrings().length()}")
			end
		
			if !userSessionB.listAllUsableDeviceStrings().include?(DEVICE_STRING_A)
				raise("Could not find #{DEVICE_STRING_A} in list of usable devices")
			end
			if !userSessionB.listAllUsableDeviceStrings().include?(DEVICE_STRING_B)
				raise("Could not find #{DEVICE_STRING_B} in list of usable devices")
			end
		end
	end
	
	def getAllUserDevicePairsOwnedDevicesTest
		getAllOwnedDeviceStringsTest()
	end
end
