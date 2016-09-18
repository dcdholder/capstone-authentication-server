require 'benchmark'
require_relative '../lib/Cryptography.rb'

#TODO: move this to benchmark-ips
#TODO: consider making the benchmark credentials a class field
class Benchmarking
	USERNAME_LENGTH = 8
	PASSWORD_LENGTH = 8

	DIGESTION_ITERATIONS = 1000

	#generate a large number of alphanumeric usernames and passwords
	def self.generateCredentials
		credentials   = Array.new
		credentialSet = Hash.new
	
		DIGESTION_ITERATIONS.times do		
			username = [*('A'..'Z'),*('a'..'z'),*('0'..'9')].shuffle[0,USERNAME_LENGTH].join #TODO: how does this work? printf time
			password = [*('A'..'Z'),*('a'..'z'),*('0'..'9')].shuffle[0,PASSWORD_LENGTH].join
			salt     = OpenSSL::Random.random_bytes(Cryptography::SALT_BYTE_LENGTH)
			
			credentialSet = {:username => username, :password => password, :salt => salt}
			credentials << credentialSet
		end
		
		return credentials
	end

	#uses PBKDF
	def self.benchmarkUserCredentialDigestion(credentials)
		totalTime   = 0.0
		longestTime = 0.0
	
		credentials.each do |credential|
			time = Benchmark.realtime do
				Cryptography.digestUserCredentialsWithSalt(credential[:username],credential[:password],credential[:salt])
			end
			
			if time > longestTime
				longestTime = time
			end
			
			totalTime += time
		end
		
		averageTime = totalTime / credentials.length
		
		return averageTime, longestTime
	end
	
	#uses SHA
	def self.benchmarkShaGeneration(credentials)
		totalTime   = 0.0
		longestTime = 0.0
	
		credentials.each do |credential|
			time = Benchmark.realtime do
				Cryptography.digestStringWithSalt(Cryptography.genUserPassPhrase(credential[:username],credential[:password]),credential[:salt])
			end
			
			if time > longestTime
				longestTime = time
			end
			
			totalTime += time
		end
		
		averageTime = totalTime / credentials.length
		
		return averageTime, longestTime
	end
	
	def self.digestBenchmarkReport
		credentials = generateCredentials
	
		averageTimeSha,   longestTimeSha   = benchmarkShaGeneration(credentials)
		averageTimePbkdf, longestTimePbkdf = benchmarkUserCredentialDigestion(credentials)
	
		puts "Average time for PBKDF digestion: " + averageTimePbkdf.to_s
		puts "Longest time for PBKDF digestion: " + longestTimePbkdf.to_s
		
		puts ""
		
		puts "Average time for SHA digestion: " + averageTimeSha.to_s
		puts "Longest time for SHA digestion: " + longestTimeSha.to_s
	end
end
