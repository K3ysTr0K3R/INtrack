import re
import requests

def find_web_form(ip, ports=None, timeout=5):
	detect_form = [
	"""
	<form 
	</form> 
	<button
	"""
	]

	detect_file_upload = []

	for lists in array:
		trip = lists.strip()
		print(trip)