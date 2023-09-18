from tkinter import *
from tkinter import ttk, font

import requests 
import hashlib # for sha1 hashing
import sys


def requests_api_data(query_char):
	url = 'https://api.pwnedpasswords.com/range/' + query_char
	res = requests.get(url)
	if res.status_code != 200:
		raise RuntimeError(f'Error fetching: {res.status_code}, check the api again')
	return res


def get_password_leaks_count(hashes, hash_to_check):
	hashes = (line.split(':') for line in hashes.text.splitlines())
	for h, count in hashes:
		if h == hash_to_check:
			return count
	return 0

def pwned_api_check(password):
	sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
	first5_char, tail = sha1password[:5], sha1password[5:]
	response = requests_api_data(first5_char)
	return get_password_leaks_count(response, tail)

def main(password):
	count = pwned_api_check(password)
	if count:
		display_label.configure(text= f'This password was found {count} times.. you should probably change your password')
		print(f"{password} was found {count} times... You should probably change your password")
	else:
		display_label.configure(text = f'This password was not found! Carry on!')
		print(f"{password} was not found! Carry on!")
	return 'done!'

def get_passwords_list():
	with open("passwords.txt", "r") as password_file:
		password_list = password_file.readlines()
		return password_list



def check_password():
    password = password_entry.get().strip()
    # Add code here to store the password in your password manager
    if __name__ == '__main__':
    	main(password)


root = Tk()
root.title("Password Checker")
root.geometry("1000x500") #sets width and height of root window

# label and entry field for the password
password_label = ttk.Label(root, text="Enter Password:", font=('Arial', 18))
password_label.pack()
password_entry = ttk.Entry(root, show="*", font=('Arial', 18))
password_entry.pack()

# button to check the password
check_button = ttk.Button(root, text="Check Password", command=check_password, width=20)
check_button.pack(pady=10)

# label to display the information about the password
display_label = ttk.Label(root, text="This application checks your password", font=('Arial', 16))
display_label.pack()

root.mainloop()
