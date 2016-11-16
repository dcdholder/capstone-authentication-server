require 'sinatra'

#admin methods

get '/admin/create' do
	Admin.new(params[:name],params[:password]) #returns a token
end

get '/admin/login' do
	Admin.login(params[:name],params[:password]) #returns a token
end

get '/admin/devices/list' do
	adminSession = getAdminSession(params[:token])
	adminSession.listAllDevices()
end

get '/admin/devices/create' do
	adminSession = getAdminSession(params[:token])
	adminSession.createDevice(params[:deviceId])
end

get '/admin/users/list' do
	adminSession = getAdminSession(params[:token])
	adminSession.listAllUsers()
end

#user methods

get '/user/create' do
	User.new(params[:name],params[:password])
end

get '/user/devices/list/owned' do
	userSession = getUserSession(params[:token])
	userSession.ownedDevices()
end

get '/user/devices/list/usable' do
	userSession = getUserSession(params[:token])
	userSession.usableDevices()
end

get '/user/devices/claim' do
	userSession = getUserSession(params[:token])
	userSession.claimDevice(params[:deviceId])
end

get '/user/devices/add_user' do
	userSession = getUserSession(params[:token])
	userSession.addUserToDevice(params[:deviceId],params[:name])
end

get '/user/devices/revoke_user' do
	userSession = getUserSession(params[:token])
	userSession.removeUserFromDevice(params[:deviceId],params[:name])
end

get '/user/devices/set_string' do
	userSession = getUserSession(params[:token])
	userSession.setDeviceString(params[:deviceId],params[:deviceString])
end

get '/user/devices/get_string' do
	userSession = getUserSession(params[:token])
	userSession.getDeviceString(params[:deviceId])
end

get '/user/devices/owned_strings' do
	userSession = getUserSession(params[:token])
	userSession.getOwnedDeviceStrings()
end

get '/user/devices/usable_strings' do
	userSession = getUserSession(params[:token])
	userSession.getUsableDeviceStrings()
end
