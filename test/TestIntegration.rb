require 'test/unit'

require_relative '../lib/Database.rb'
require_relative './UserSession.rb'
require_relative './AdminSession.rb'

class TestIntegration < Test::Unit::TestCase
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

	def testCreateUser
		assert_nothing_raised do
			Database.burnEverything()
			
			adminSession = AdminSession.addAdmin(ADMIN_NAME,ADMIN_PASSWORD)
		
			if adminSession.listAllUserHashes().length()!=0
				raise("Database reports existing users before first user creation")
			end
		
			userSession = UserSession.addUser(USER_A_NAME,USER_A_PASSWORD)
		
			if userSession.ownedDevices().length()!=0
				raise("Database reports existing owned devices in empty user")
			end
			if userSession.usableDevices().length()!=0
				raise("Database reports existing usable devices in empty user")
			end
		
			if adminSession.listAllUserHashes.length()!=1
				raise("Should be exactly 1 user in database, found #{adminSession.listAllUserHashes().length().to_s()}")
			end
		end
	end

	def testCreateAdmin #just prove that this doesn't throw an exception
		assert_nothing_raised do
			Database.burnEverything()
	
			adminSession = AdminSession.addAdmin(ADMIN_NAME,ADMIN_PASSWORD)
			adminSession.endSession()
		
			adminSession = AdminSession.login(ADMIN_NAME,ADMIN_PASSWORD)
		end
	end

	def testCreateDevice
		assert_nothing_raised do
			Database.burnEverything()
	
			adminSession = AdminSession.addAdmin(ADMIN_NAME,ADMIN_PASSWORD)
		
			if adminSession.listAllDeviceHashes().length()!=0
				raise("Database reports existing devices before first device creation")
			end
		
			adminSession.createDevice(DEVICE_ID_A)
		
			if adminSession.listAllDeviceHashes().length() != 1
				raise("Should be exactly 1 device in database, found #{adminSession.listAllDeviceHashes().length()}")
			end
		end
	end

	def testListAllUserHashes
		testCreateDevice()
	end
	
	def testListAllDeviceHashes
		testCreateDevice()
	end
	
	def testClaimDeviceOwnership
		assert_nothing_raised do
			Database.burnEverything()
	
			adminSession = AdminSession.addAdmin(ADMIN_NAME,ADMIN_PASSWORD)
			adminSession.createDevice(DEVICE_ID_A)
		
			userSession = UserSession.addUser(USER_A_NAME,USER_A_PASSWORD)
			userSession.claimDevice(DEVICE_ID_A)
		
			if userSession.ownedDevices().length() != 1
				raise("Should be exactly 1 owned device for user #{USER_A_NAME}, found #{userSession.ownedDevices().length()}")
			elsif !userSession.ownedDevices().has_key?(DEVICE_ID_A)
				raise("Should find device ID #{DEVICE_ID_A}")
			end
		end
	end

	def testAddDeviceUsership
		Database.burnEverything()
	
		assert_nothing_raised do
			adminSession = AdminSession.addAdmin(ADMIN_NAME,ADMIN_PASSWORD)
			adminSession.createDevice(DEVICE_ID_A)
		
			userSessionA = UserSession.addUser(USER_A_NAME,USER_A_PASSWORD)
			userSessionA.claimDevice(DEVICE_ID_A)
		
			userSessionB = UserSession.addUser(USER_B_NAME,USER_B_PASSWORD)
		
			userSessionA.addUserToDevice(DEVICE_ID_A,USER_B_NAME)
			deviceUserMap = userSessionA.mapAllDeviceUsers()
			if deviceUserMap.has_key?(DEVICE_ID_A)
				if !deviceUserMap[DEVICE_ID_A].include?(USER_B_NAME)
					raise("Could not find #{USER_B_NAME} in user list for device #{DEVICE_ID_A}")
				end
			else
				raise("Could not find device #{DEVICE_ID_A} in owned device map")
			end

			if !userSessionB.usableDevices().has_key?(DEVICE_ID_A)
				raise("Should have device ID #{DEVICE_ID_A}")
			end
		end
	end
	
	def testRevokeDeviceUsership
		assert_nothing_raised do
			Database.burnEverything()
	
			adminSession = AdminSession.addAdmin(ADMIN_NAME,ADMIN_PASSWORD)
			adminSession.createDevice(DEVICE_ID_A)
		
			userSessionA = UserSession.addUser(USER_A_NAME,USER_A_PASSWORD)
			userSessionB = UserSession.addUser(USER_B_NAME,USER_B_PASSWORD)
			userSessionA.claimDevice(DEVICE_ID_A)
			userSessionA.addUserToDevice(DEVICE_ID_A,USER_B_NAME)
		
			if userSessionB.usableDevices().length() != 1
				raise("Should be exactly one usable device for user #{USER_B_NAME}, found #{userSessionB.listAllUsableDevices().length()}")
			end
		
			userSessionA.removeUserFromDevice(USER_B_NAME,DEVICE_ID_A)
		
			if userSessionB.usableDevices().length()!=0
				raise("Database reports existing usable devices after removing only device")
			end
		end
	end
	
	def testSetDeviceString
		assert_nothing_raised do
			Database.burnEverything()
	
			adminSession = AdminSession.addAdmin(ADMIN_NAME,ADMIN_PASSWORD)
			adminSession.createDevice(DEVICE_ID_A)
		
			userSessionA = UserSession.addUser(USER_A_NAME,USER_A_PASSWORD)
			userSessionA.claimDevice(DEVICE_ID_A)
		
			userSessionA.setDeviceString(DEVICE_ID_A,DEVICE_STRING_A)
			if userSessionA.getDeviceString(DEVICE_ID_A) != DEVICE_STRING_A
				raise("Device string is #{userSessionA.getDeviceString(DEVICE_ID_A)}, should be #{DEVICE_STRING_A}")
			end
		end
	end

	def testGetDeviceString
		testSetDeviceString()
	end
	
	def testGetAllOwnedDeviceStrings
		assert_nothing_raised do
			Database.burnEverything()
	
			adminSession = AdminSession.addAdmin(ADMIN_NAME,ADMIN_PASSWORD)
			adminSession.createDevice(DEVICE_ID_A)
			adminSession.createDevice(DEVICE_ID_B)
		
			userSessionA = UserSession.addUser(USER_A_NAME,USER_A_PASSWORD)
			userSessionA.claimDevice(DEVICE_ID_A)
			userSessionA.claimDevice(DEVICE_ID_B)
		
			userSessionA.setDeviceString(DEVICE_ID_A,DEVICE_STRING_A)
			userSessionA.setDeviceString(DEVICE_ID_B,DEVICE_STRING_B)
		
			deviceStringsMap = userSessionA.ownedDevices()
			if deviceStringsMap.has_key?(DEVICE_ID_A) && deviceStringsMap.has_key?(DEVICE_ID_B)
				if deviceStringsMap[DEVICE_ID_A]!=DEVICE_STRING_A || deviceStringsMap[DEVICE_ID_B]!=DEVICE_STRING_B
					raise("Input and output device strings did not match: #{deviceStringsMap[DEVICE_ID_A]}, #{deviceStringsMap[DEVICE_ID_B]}")
				end
			else
				raise("Could not find one or more of the device strings")
			end
		end
	end

	def testGetAllUsableDeviceStrings
		assert_nothing_raised do
			Database.burnEverything()
	
			adminSession = AdminSession.addAdmin(ADMIN_NAME,ADMIN_PASSWORD)
			adminSession.createDevice(DEVICE_ID_A)
			adminSession.createDevice(DEVICE_ID_B)
		
			userSessionA = UserSession.addUser(USER_A_NAME,USER_A_PASSWORD)
			userSessionA.claimDevice(DEVICE_ID_A)
			userSessionA.claimDevice(DEVICE_ID_B)
		
			userSessionA.setDeviceString(DEVICE_ID_A,DEVICE_STRING_A)
			userSessionA.setDeviceString(DEVICE_ID_B,DEVICE_STRING_B)
		
			userSessionB = UserSession.addUser(USER_B_NAME,USER_B_PASSWORD)
			userSessionA.addUserToDevice(DEVICE_ID_A,USER_B_NAME)
			userSessionA.addUserToDevice(DEVICE_ID_B,USER_B_NAME)
		
			if !userSessionB.usableDevices().has_key?(DEVICE_ID_A)
				raise("Could not find #{DEVICE_ID_A} in list of usable devices")
			end
			if !userSessionB.usableDevices().has_key?(DEVICE_ID_B)
				raise("Could not find #{DEVICE_ID_B} in list of usable devices")
			end
			
			deviceStringsMap = userSessionB.usableDevices()
			if deviceStringsMap[DEVICE_ID_A]!=DEVICE_STRING_A || deviceStringsMap[DEVICE_ID_B]!=DEVICE_STRING_B
				raise("Input and output device strings did not match: #{deviceStringsMap[DEVICE_ID_A]}, #{deviceStringsMap[DEVICE_ID_B]}")
			end
		end
	end
end
