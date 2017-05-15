import os
import time 

flag_found = False
count = 0
while not flag_found:
	with open('godeep', 'r') as f:
		text = f.read()

	print(text[:20])
	if 'CrossCTF' in text:
		flag_found = True
		break
		

	file_b64 = False
	for c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ=':
		if c in text:
			file_b64 = True
			os.system("echo '{}' | base64 -d > godeep".format(text))
			break
	if not file_b64:
		os.system("echo '{}' | xxd -r -p > godeep".format(text))

	time.sleep(1)
	count += 1
	print()
	if count > 2:
		break
