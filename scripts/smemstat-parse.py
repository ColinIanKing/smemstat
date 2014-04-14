#!/usr/bin/python
#
# Copyright (C) 2014 Canonical
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
#
# This script takes json output from power-calibrate and health-check
# to calculate an esimate of power consumption 
#
#
import sys, os, json

def r2tostr(r2):
	if r2 < 0.4:
		return "very poor"
	if r2 < 0.75:
		return "poor"
	if r2 < 0.80:
		return "fair"
	if r2 < 0.90:
		return "good"
	if r2 < 0.95:
		return "very good"
	if r2 < 1.0:
		return "excellent"
	return "perfect"

if len(sys.argv) != 2:
        sys.stderr.write("Usage: " + sys.argv[0] + " smemstat.json\n")
        os._exit(1)

try:
	file = sys.argv[1]
	f = open(file, 'r')
	data = json.load(f)
	f.close()
except:	
	sys.stderr.write("Failed to open and parse JSON file " + file +  "\n");
	os._exit(1)

if not "smemstat" in data:
	sys.stderr.write("Failed to find smemstat json data in file " + file +  "\n");
	os._exit(1)

sm = data["smemstat"]
if "smem-per-process" in sm:
	processes = sm["smem-per-process"]
	for i in processes:
		print str(i["pid"]) + " " + i["user"] + " " + \
			str(i["swap"] / 1024) + " " + \
			str(i["uss"] / 1024) + " " + \
			str(i["pss"] / 1024) + " " + \
			str(i["rss"] / 1024) + " " + \
			i["command"]

	total = sm["smem-total"]
	print "Total: " + \
		str(total["swap"] / 1024) + " " + \
		str(total["uss"] / 1024) + " " + \
		str(total["pss"] / 1024) + " " + \
		str(total["rss"] / 1024) 

if "periodic-samples" in sm:
	samples = sm["periodic-samples"]
	sn = 0
	for s in samples:
		sn = sn + 1
		print "Sample: " + str(sn)
		processes = s["smem-per-process"]
		for i in processes:
			print "  " + str(i["pid"]) + " " + i["user"] + " " + \
				str(i["swap"] / 1024) + " " + \
				str(i["uss"] / 1024) + " " + \
				str(i["pss"] / 1024) + " " + \
				str(i["rss"] / 1024) + " " + \
				str(i["swap-delta"] / 1024) + " " + \
				str(i["uss-delta"] / 1024) + " " + \
				str(i["pss-delta"] / 1024) + " " + \
				str(i["rss-delta"] / 1024) + " " + \
				i["command"]
		total = s["smem-total"]
		print "  Total: " + \
			str(total["swap"] / 1024) + " " + \
			str(total["uss"] / 1024) + " " + \
			str(total["pss"] / 1024) + " " + \
			str(total["rss"] / 1024) + " " + \
			str(total["swap-delta"] / 1024) + " " + \
			str(total["uss-delta"] / 1024) + " " + \
			str(total["pss-delta"] / 1024) + " " + \
			str(total["rss-delta"] / 1024) 
