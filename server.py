# encoding=utf8
import flask
import os
import math
import sqlite3
import json

app = flask.Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True

@app.route('/')
@app.route('/<page>')
def main(page="index"):
    page += '.html'
    if os.path.isfile('templates/' + page):
        return flask.render_template(page)
    return flask.abort(404)


@app.route('/api/logs/<log_type>')
def getLogs(log_type):
	acceptable_types = ['linux', 'router', 'windows', 'records']
	if log_type not in acceptable_types:
		return "Invalid query!"
	page = 1
	statement = "select count(*) from"
	if flask.request.args.get('page', type=int) != None:
		page = flask.request.args.get('page', type=int)
	pages = 1
	rows = 0
	conn = sqlite3.connect("logs.db")
	c = conn.cursor()
	args = []
	if log_type == "records":
		ltype = "" if flask.request.args.get('type', type=str) is None else flask.request.args.get('type', type=str)
		args = [ltype]
		statement += " Log_Records WHERE log_type LIKE ? || '%' "
	elif log_type == "linux":
		ll_Type = "" if flask.request.args.get('type', type=str) is None else flask.request.args.get('type', type=str)
		date_time = "" if flask.request.args.get('date_time', type=str) is None else flask.request.args.get('date_time', type=str)
		data = "" "" if flask.request.args.get('data', type=str) is None else flask.request.args.get('data', type=str)
		args = [ll_Type, date_time, data]
		statement += " Linux_Logs WHERE log_type LIKE ? || '%' AND date_time LIKE ? || '%' AND data LIKE '%' || ? || '%'"
	elif log_type == "router":
		sip = "" if flask.request.args.get('sip', type=str) is None else flask.request.args.get('sip', type=str)
		dip = "" if flask.request.args.get('dip', type=str) is None else flask.request.args.get('dip', type=str)

		sport = 0 if flask.request.args.get('sport', type=int) is None else flask.request.args.get('sport', type=int)
		use_sport = True if flask.request.args.get('sport', type=int) is not None else False
		
		dport = 0 if flask.request.args.get('dport', type=int) is None else flask.request.args.get('dport', type=int)
		use_dport = True if flask.request.args.get('dport', type=int) is not None else False
		
		proto = 0 if flask.request.args.get('proto', type=int) is None else flask.request.args.get('proto', type=int)
		use_proto = True if flask.request.args.get('proto', type=int) is not None else False
		
		packets = 0 if flask.request.args.get('packets', type=int) is None else flask.request.args.get('packets', type=int)
		use_packets = True if flask.request.args.get('packets', type=int) is not None else False
		
		bytess = 0 if flask.request.args.get('bytes', type=int) is None else flask.request.args.get('bytes', type=int)
		use_bytess = True if flask.request.args.get('bytes', type=int) is not None else False
		
		start_time = "" if flask.request.args.get('stime', type=str) is None else flask.request.args.get('stime', type=str)
		duration = 0.0 if flask.request.args.get('duration', type=float) is None else flask.request.args.get('duration', type=float)
		use_duration = True if flask.request.args.get('duration', type=int) is not None else False
		
		end_time = "" if flask.request.args.get('etime', type=str) is None else flask.request.args.get('etime', type=str)
		sensor = "" if flask.request.args.get('sensor', type=str) is None else flask.request.args.get('sensor', type=str)
		flags = "" if flask.request.args.get('flags', type=str) is None else flask.request.args.get('flags', type=str)
		
		statement += " Router_Logs WHERE source_address LIKE ? || '%' AND destination_address LIKE ? || '%' AND start_time LIKE ? || '%' AND end_time LIKE ? || '%' AND sensor LIKE ? || '%' AND flags like ? || '%'"

		args = [sip, dip, start_time, end_time, sensor, flags]

		if use_sport:
			statement += " AND source_port = ?"
			args.append(sport)
		if use_dport:
			statement += " AND destination_port = ?"
			args.append(dport)
		if use_proto:
			statement += " AND protocol = ?"
			args.append(proto)
		if use_packets:
			statement += " AND packets = ?"
			args.append(packets)
		if use_bytess:
			statement += " AND bytes = ?"
			args.append(bytess)
		if use_duration:
			statement += " AND duration LIKE ? || '%' "
			args.append(duration)
	else:
		keywords = "" if flask.request.args.get('keywords', type=str) is None else flask.request.args.get('keywords', type=str)
		date_time = "" if flask.request.args.get('date_time', type=str) is None else flask.request.args.get('date_time', type=str)
		source = "" if flask.request.args.get('source', type=str) is None else flask.request.args.get('source', type=str)

		event_id = 0 if flask.request.args.get('event_id', type=int) is None else flask.request.args.get('event_id', type=int)
		use_event_id = True if flask.request.args.get('event_id', type=int) is not None else False

		task_category = "" if flask.request.args.get('category', type=str) is None else flask.request.args.get('category', type=str)
		task_description = "" if flask.request.args.get('description', type=str) is None else flask.request.args.get('description', type=str)

		args = [keywords, date_time, task_category, task_description, source]
		statement += " Windows_Logs WHERE keywords LIKE '%' || ? || '%' AND date_time LIKE '%' || ? || '%' AND task_category LIKE '%' || ? || '%' AND task_description LIKE '%' || ? || '%' AND source LIKE '%' || ? || '%'"
		if use_event_id:
			statement += ' AND event_id = ?'
			args.append(event_id)
	rows = c.execute(statement, args).fetchone()
	statement = statement.replace("count(*)", "*")
	pages = math.ceil(rows[0] / 30)
	offset = 0
	if (page > pages):
		page = 1
	if (page > 1):
		offset = (page * 30) - 30
	statement += " LIMIT 30 OFFSET {};".format(offset)
	data = c.execute(statement, args).fetchall()
	data_json = []
	if log_type == "records":
		for d in data:
			j = {
				'id': d[0],
				'log_type': d[1],
				'windows_log_id': d[2],
				'linux_log_id': d[3],
				'router_log_id': d[4]
			}
			data_json.append(j)
	elif log_type == "linux":
		for d in data:
			j = {
				'id': d[0],
				'log_type': d[1],
				'date_time': d[2],
				'data': json.loads(d[3])
			}
			data_json.append(j)
	elif log_type == "router":
		for d in data:
			j = {
				'id': d[0],
				'source_address': d[1],
				'destination_address': d[2],
				'source_port': d[3],
				'destination_port': d[4],
				'protocol': d[5],
				'packets': d[6],
				'bytes': d[7],
				'flags': d[8],
				'start_time': d[9],
				'duration': d[10],
				'end_time': d[11],
				'sensor': d[12]
			}
			data_json.append(j)
	else:
		for d in data:
			j = {
				'id': d[0],
				'keywords': d[1],
				'date_time': d[2],
				'source': d[3],
				'event_id': d[4],
				'task_category': d[5],
				'task_description': d[6]
			}
			data_json.append(j)
	conn.close()
	return flask.jsonify({'page': page, 'total_pages': pages, 'total_records': rows[0], 'data': data_json})
	
@app.route('/api/stats/<log_type>')
def log_stats(log_type):
	acceptable_types = ['linux', 'router', 'windows', 'records']
	if log_type not in acceptable_types:
		return "Invalid query!"
	conn = sqlite3.connect("logs.db")
	c = conn.cursor()
	stats = {}
	if log_type == "records":
		stats = {
			"total_records": c.execute("select count(*) from Log_Records").fetchone()[0],
			"total_linux_logs": c.execute("select count(*) from Log_Records WHERE linux_log_id IS NOT NULL").fetchone()[0],
			"total_windows_logs": c.execute("select count(*) from Log_Records WHERE windows_log_id IS NOT NULL").fetchone()[0],
			"total_router_logs": c.execute("select count(*) from Log_Records WHERE router_log_id IS NOT NULL").fetchone()[0],
		}
	elif log_type == "windows":
		stats = {
			"successful_audits": c.execute("select count(*) from Windows_Logs where Keywords LIKE '%Success%'").fetchone()[0],
			"failed_audits": c.execute("select count(*) from Windows_Logs where Keywords LIKE '%Failure%'").fetchone()[0],
			"event_id_totals": {},
			"task_category_totals": {}
		}
		for row in c.execute("select distinct event_id from Windows_Logs").fetchall():
			stats['event_id_totals'][str(row[0])] = c.execute("select count(*) from Windows_Logs where event_id = " + str(row[0]) + ";").fetchone()[0]
		for row in c.execute("select distinct task_category from Windows_Logs").fetchall():
			stats['task_category_totals'][row[0]] = {
				"amount": c.execute("select count(*) from Windows_Logs where task_category = '" + row[0] + "';").fetchone()[0],
				"successful": c.execute("select count(*) from Windows_Logs where task_category = '" + row[0] + "' AND Keywords LIKE '%Success%' ;").fetchone()[0],
				"failed": {
					"failed_count": c.execute("select count(*) from Windows_Logs where task_category = '" + row[0] + "' AND Keywords LIKE '%Failure%' ;").fetchone()[0],
					"failed_ids": c.execute("select log_id from Windows_Logs where task_category = '" + row[0] + "' AND Keywords LIKE '%Failure%' ;").fetchall(),
				}
			}
	elif log_type == "linux":
		stats = {
			"type_counts": {}
		}
		for row in c.execute("select distinct log_type from Linux_Logs").fetchall():
			stats['type_counts'][row[0]] = c.execute("select count(*) from Linux_Logs where log_type = '" + row[0] + "';").fetchone()[0]
	else:
		stats = {
			"unique_ips": [],
			"unique_ports": [],
			"total_bytes": c.execute("select sum(bytes) from Router_Logs").fetchone()[0],
			"total_packets": c.execute("select sum(packets) from Router_Logs").fetchone()[0]
		}
		tmp = []
		for row in c.execute("select source_address, destination_address from Router_Logs;").fetchall():
			if row[0] not in tmp:
				tmp.append(row[0])
				stats['unique_ips'].append({
					"ip": row[0],
					"source_ip_count": c.execute("select count(*) from Router_Logs where source_address = ?", [row[0]]).fetchone()[0],
					"destination_ip_count": c.execute("select count(*) from Router_Logs where destination_address = ?", [row[0]]).fetchone()[0],
					"total_packets": c.execute("select sum(packets) from Router_Logs where destination_address = ? OR source_address = ?", [row[0], row[0]]).fetchone()[0],
					"total_bytes": c.execute("select sum(bytes) from Router_Logs where destination_address = ? OR source_address = ?", [row[0], row[0]]).fetchone()[0]
				})

			if row[1] not in tmp:
				tmp.append(row[1])
				stats['unique_ips'].append({
					"ip": row[1],
					"source_ip_count": c.execute("select count(*) from Router_Logs where source_address = ?", [row[1]]).fetchone()[0],
					"destination_ip_count": c.execute("select count(*) from Router_Logs where destination_address = ?", [row[1]]).fetchone()[0]
				})
				

	return flask.jsonify({'stats': stats})

@app.route('/api/log_view/<log_type>/<log_id>')
def view_log(log_type, log_id):
	acceptable_types = ['linux', 'router', 'windows']
	if log_type not in acceptable_types:
		return "Invalid query!"
	table = ""
	conn = sqlite3.connect("logs.db")
	c = conn.cursor()
	log = {}
	if log_type == "windows":
		table = "Windows_Logs"
	elif log_type == "linux":
		table = "Linux_Logs"
	else:
		table = "Router_Logs"
	data = c.execute("select * from " + table + " where log_id = ?;", [log_id]).fetchone()
	if data == None:
		return flask.jsonify({"result": {"error": True, "message": "no data found!"}})
	if log_type == "windows":
		log = {
				'id': data[0],
				'keywords': data[1],
				'date_time': data[2],
				'source': data[3],
				'event_id': data[4],
				'task_category': data[5],
				'task_description': data[6]
		}
	elif log_type == "router":
		log = {
				'id': data[0],
				'source_address': data[1],
				'destination_address': data[2],
				'source_port': data[3],
				'destination_port': data[4],
				'protocol': data[5],
				'packets': data[6],
				'bytes': data[7],
				'flags': data[8],
				'start_time': data[9],
				'duration': data[10],
				'end_time': data[11],
				'sensor': data[12]
		}
	else:
		log = {
				'id': data[0],
				'log_type': data[1],
				'date_time': data[2],
				'data': json.loads(data[3])
		}
	return flask.jsonify({"result": {"error": False, "result": log}})



if __name__ == '__main__':
	app.run(host="0.0.0.0", port=5000, debug=True, load_dotenv=True)
