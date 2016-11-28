require_relative '../lib/Database.rb'

class UserSession
	SESSION_LENGTH = 60*60*1

	def self.addUser(name,pass)
		Database.addUser(name,pass)
		return UserSession.new(name,pass)
	end
	
	def self.login(name,pass)
		if Database.adminPasswordCorrect?(name,pass)
			return UserSession.new(name,pass)
		else
			raise "User username / password incorrect"
		end
	end
	
	def claimDevice(deviceId)
		Database.setOwnership(@username,@password,deviceId)
	end
	
	def addUserToDevice(deviceId,name)
		Database.setUsership(@username,@password,name,deviceId)
	end
	
	def setDeviceString(deviceId,deviceString)
		Database.setTag(@username,@password,deviceId,deviceString)
	end
	
	def getDeviceString(deviceId)
		Database.getTag(@username,@password,deviceId)
	end
	
	def listAllOwnedDevices()
		Database.getAllOwnedDevices(@username,@password)
	end
	
	def listAllUsableDevices()
		Database.getAllUsableDevices(@username,@password)
	end
	
	def removeUserFromDevice(name,deviceId)
		Database.revokeUsership(@username,@password,name,deviceId)
	end
	
	def endSession()
		@remainingTime = 0 #we don't do anything with this right now
	end
	
	def initialize(name,pass)
		@username = name
		@password = pass
		@remainingTime = SESSION_LENGTH #we don't do anything with this right now
	end
end
