from Crypto.Cipher import AES
import datetime
import struct
import hashlib

class MyCrypto(object):
	"""docstring for MyCrypto"""
	def __init__(self, key):
		super(MyCrypto, self).__init__()
		# self.key = self.align_16(key)
		self.key = key
		self.lastdata = None

	def get_key(self):
		key = self.key + datetime.datetime.now().strftime('%Y%m%d-%H:%M') 
		# key = self.key
		key = hashlib.md5(key).hexdigest()
		key = key[0:16]
		# print repr(key)
		# key = self.align_16(key)
		# print key
		# print "===", len(key)
		return key

	def align_16(self, data):
		strlen = len(data)
		d = struct.pack("!I", strlen) 
		strlen += len(d) # 4bytes
		data = d + data
		if strlen % 16 != 0:
			data = data +"a"*(16 - strlen%16)
		# print len(data)
		return data

	def trim_align(self, data):
		datalen = len(data)
		if datalen > 4:
			strlen = struct.unpack("!I", data[0:4])[0]
			if strlen+4 > datalen:
				return data
			else:
				return data[4:strlen+4]
		return data

	def get_cry_obj(self):
		aes_cry = AES.new(self.get_key(), AES.MODE_CBC, self.get_key())
		return aes_cry
	
	def packet(self, data):
		# print "packet", len(data)
		data_len = len(data) + 4
		d = struct.pack("!I", data_len)
		return d+data

	def unpacket(self, data):
		# print "unpacket datalen: ", len(data)
		if self.lastdata != None:
			data = self.lastdata + data
			del self.lastdata
			self.lastdata = None
		res_datas = ''
		bas_pos = 0
		while True:
			if len(data[bas_pos:]) >= 4:
				data_len = struct.unpack("!I", data[bas_pos:bas_pos+4])[0]
				# print len(data), data_len
			 	if len(data[bas_pos:]) >= data_len:
			 		tdata = data[bas_pos+4:bas_pos+data_len]
			 		aes_cry = self.get_cry_obj()
					# print "decrypt: ", len(data)
					tdata = aes_cry.decrypt(tdata)
					tdata =  self.trim_align(tdata)
					# print repr(tdata)
			 		res_datas += tdata
			 		bas_pos = bas_pos + data_len
			 		continue
			# print bas_pos
			lastdata = data[bas_pos:]
			break
		# print "====", bas_pos
		return res_datas

	def encrypt(self, data):
		# return data
		# print "==", data, "---"
		# print "encrypt len: ", len(data)
		aes_cry = self.get_cry_obj()
		# data = "123456"*10
		data = self.align_16(data)
		# print "encrypt: ", len(data) % 16
		data = aes_cry.encrypt(data)
		return self.packet(data)

	def decrypt(self, data):
		data = self.unpacket(data)
		# return data
		# aes_cry = self.get_cry_obj()
		# # print "decrypt: ", len(data)
		# data = aes_cry.decrypt(data)
		# data =  self.trim_align(data)
		# print "***", data, "===="
		return data

# crypto = MyCrypto("test")
# data = crypto.encrypt("1234577890")
# print repr(data)
# print crypto.decrypt(data)



# obj = AES.new('This is a key123', AES.MODE_CBC, 'This is an IV456')

# message = "abcdef0123456789abcdef0123456789"
# date = datetime.datetime.now() 
# print dir(date)
# print date.minute
# print date.strftime('%Y-%m-%d %H:%M')
# ciphertext = obj.encrypt(message)

# obj2 = AES.new('This is a key123', AES.MODE_CBC, 'This is an IV456')

# r = obj2.decrypt(ciphertext)
# print r

