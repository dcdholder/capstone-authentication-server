require_relative '../lib/Database.rb'

class AdminSession
	SESSION_LENGTH = 60*60*1

	def self.addAdmin(name,pass)
		Database.addAdmin(name,pass)
		return AdminSession.new(name,pass)
	end
	
	def self.login(name,pass)
		if Database.adminPasswordCorrect?(name,pass)
			return AdminSession.new(name,pass)
		else
			raise "Admin username / password incorrect"
		end
	end
	
	def createDevice(deviceId)
		Database.addDevice(@username,@password,deviceId)
	end
	
	def listAllUserHashes()
		Database.getAllUserHashes(@username,@password)
	end
	
	def listAllDeviceHashes()
		Database.getAllDeviceHashes(@username,@password)
	end
	
	def endSession()
		@remainingTime = 0 #we don't do anything with this right now - end sessions after a certain period
	end
	
	def initialize(name,pass)
		@username = name
		@password = pass
		@remainingTime = SESSION_LENGTH #we don't do anything with this right now - end sessions after a certain period
	end
end
