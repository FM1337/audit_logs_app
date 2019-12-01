Vue.component('paginate', VuejsPaginate) 


var dynamicColors = function() {
	var r = Math.floor(Math.random() * 255);
	var g = Math.floor(Math.random() * 255);
	var b = Math.floor(Math.random() * 255);
	return "rgb(" + r + "," + g + "," + b + ")";
 };


Vue.component('records-chart', {
	extends: VueChartJs.Bar,
	mounted() {
		this.renderChart({
			labels: ["Log Amount"],
			datasets: [
				{
					"data": [this.$root.windows_logs_count],
					"label": "Windows",
					"backgroundColor": "#0078D7"
				},
				{
					"data": [this.$root.linux_logs_count],
					"label": "Linux",
					"backgroundColor": "orange"
				},
				{
					"data": [this.$root.router_logs_count],
					"label": "Router",
					"backgroundColor": "brown"
				}
			]
		},
			{
				responsive: true,
				maintainAspectRatio: true,
				title: {
					"text": "Log Counts Per System"
				},
		})
	},
})


Vue.component('linux-records-chart', {
	extends: VueChartJs.Bar,
	data() {
		return {
		  "stats": [],
		  "loaded": false,
		}
	},
	mounted() {
		axios.get('/api/stats/linux').then(response => {
			this.stats = response.data.stats
			this.renderChart({
				labels: ["Log Amount"],
				datasets: [
					{
						"data": [this.stats.type_counts.AVC],
						"label": "AVC",
						"backgroundColor": dynamicColors()
					},
					{
						"data": [this.stats.type_counts.BPRM_FCAPS],
						"label": "BPRM_FCAPS",
						"backgroundColor": dynamicColors()
					},
					{
						"data": [this.stats.type_counts.CRED_ACQ],
						"label": "CRED_ACQ",
						"backgroundColor": dynamicColors()
					},
					{
						"data": [this.stats.type_counts.CRED_DISP],
						"label": "CRED_DISP",
						"backgroundColor": dynamicColors()
					},
					{
						"data": [this.stats.type_counts.CRED_REFR],
						"label": "CRED_REFR",
						"backgroundColor": dynamicColors()
					},
					{
						"data": [this.stats.type_counts.DAEMON_START],
						"label": "DAEMON_START",
						"backgroundColor": dynamicColors()
					},
					{
						"data": [this.stats.type_counts.DAEMON_END],
						"label": "DAEMON_END",
						"backgroundColor": dynamicColors()
					},
					{
						"data": [this.stats.type_counts.DAEMON_ROTATE],
						"label": "DAEMON_ROTATE",
						"backgroundColor": dynamicColors()
					},
					{
						"data": [this.stats.type_counts.EXECVE],
						"label": "EXECVE",
						"backgroundColor": dynamicColors()
					},
					{
						"data": [this.stats.type_counts.KERN_MODULE],
						"label": "KERN_MODULE",
						"backgroundColor": dynamicColors()
					},
					{
						"data": [this.stats.type_counts.LOGIN],
						"label": "LOGIN",
						"backgroundColor": dynamicColors()
					},
					{
						"data": [this.stats.type_counts.PATH],
						"label": "PATH",
						"backgroundColor": dynamicColors()
					},
					{
						"data": [this.stats.type_counts.PROCTITLE],
						"label": "PROCTITLE",
						"backgroundColor": dynamicColors()
					},
					{
						"data": [this.stats.type_counts.SERVICE_START],
						"label": "SERVICE_START",
						"backgroundColor": dynamicColors()
					},
					{
						"data": [this.stats.type_counts.SERVICE_STOP],
						"label": "SERVICE_STOP",
						"backgroundColor": dynamicColors()
					},
					{
						"data": [this.stats.type_counts.SYSCALL],
						"label": "SYSCALL",
						"backgroundColor": dynamicColors()
					},
					{
						"data": [this.stats.type_counts.SYSTEM_BOOT],
						"label": "SYSTEM_BOOT",
						"backgroundColor": dynamicColors()
					},
					{
						"data": [this.stats.type_counts.SYSTEM_RUNLEVEL],
						"label": "SYSTEM_RUNLEVEL",
						"backgroundColor": dynamicColors()
					},
					{
						"data": [this.stats.type_counts.SYSTEM_SHUTDOWN],
						"label": "SYSTEM_SHUTDOWN",
						"backgroundColor": dynamicColors()
					},
					{
						"data": [this.stats.type_counts.USER_ACCT],
						"label": "USER_ACCT",
						"backgroundColor": dynamicColors()
					},
					{
						"data": [this.stats.type_counts.USER_AUTH],
						"label": "USER_AUTH",
						"backgroundColor": dynamicColors()
					},
					{
						"data": [this.stats.type_counts.USER_CMD],
						"label": "USER_CMD",
						"backgroundColor": dynamicColors()
					},
					{
						"data": [this.stats.type_counts.USER_END],
						"label": "USER_END",
						"backgroundColor": dynamicColors()
					},
					{
						"data": [this.stats.type_counts.USER_LOGIN],
						"label": "USER_LOGIN",
						"backgroundColor": dynamicColors()
					},
					{
						"data": [this.stats.type_counts.USER_START],
						"label": "USER_START",
						"backgroundColor": dynamicColors()
					},
				]
			},
				{
					responsive: true,
					maintainAspectRatio: false,
					title: {
						"text": "Log Counts Per System"
					},
			})
		})
	},
})

Vue.component('log-records', {
	data() {
		return {
			page: 1,
			pages: 0,
			searchQuery: "",
			records: null
		}
	},
	mounted() {
		axios.get('/api/logs/records').then(response => {
			this.records = response.data.data
			this.pages = response.data.total_pages
		})
	},
	methods: {
		fetch: function () {
			axios.get('/api/logs/records?page=' + this.page + '&' + this.searchQuery).then(response => {
				this.records = response.data.data
				this.pages = response.data.total_pages
			})
		},
		paging: function (pageNum) {
            this.page = pageNum
            this.fetch()
		},
		changeFilter: function (filter) {
			this.searchQuery = "type=" + filter.target.value
			if (filter.target.value == "all") {
				this.searchQuery = ""
			}
			this.fetch()
			this.page = 1
		}
	}
})

Vue.component('windows-logs', {
	data() {
		return {
			"logs": null,
			"searchQuery": "",
			"pages": 0,
			"page": 1
		}
	},
	methods: {
		fetch: function () {
			axios.get('/api/logs/windows?page=' + this.page + '&' + this.searchQuery).then(response => {
				this.logs = response.data.data
				this.pages = response.data.total_pages
			})
		},
		paging: function (pageNum) {
			this.page = pageNum
			this.fetch()
		},
		search: function () {
			let keywords = $("#keywords").val()
			let date_time = $("#date_time").val()
			let source = $("#source").val()
			let event_id = $("#event_id").val()
			let category = $("#category").val()
			let description = $("#description").val()

			this.searchQuery = "keywords=" + keywords + "&date_time=" + date_time + "&source=" + source + "&event_id=" + event_id + "&category=" + category + "&description=" + description
 			this.page = 1
			this.fetch()
		},
		view_description: function (id) {
			axios.get('/api/log_view/windows/' + id).then(response => {
				$("#current-event").text(id)
				$('#descriptionModal').modal({
					show: true
				})
				$("#description-text").html(response.data.result.log.task_description)
			})

		}
	},
	mounted() {
		this.fetch()
	}
})

Vue.component('linux-logs', {
	data() {
		return {
			"logs": null,
			"type": "AVC",
			"pages": 0,
			"page": 1,
			"searchQuery": "",
		}
	},
	methods: {
		fetch: function () {
			axios.get('/api/logs/linux?type=' + this.type + '&page=' + this.page + '&' + this.searchQuery).then(response => {
				this.logs = response.data.data
				this.pages = response.data.total_pages
			})
		},
		paging: function (pageNum) {
			this.page = pageNum
			this.logs = []
			this.fetch()
		},
		changeFilter: function (filter) {
			this.type = filter.target.value
			this.logs = []
			this.page = 1
			this.fetch()
		},
		search: function () {
			let date_time = $("#date_time").val()
			let data = $("#data").val()
			this.searchQuery = "date_time=" + date_time + "&data=" + data
			 this.page = 1
			 this.logs = []
			this.fetch()
		},
	},
	mounted() {
		this.fetch()
	}
})

Vue.component('router-logs', {
	data() {
		return {
			"logs": null,
			"searchQuery": "",
			"pages": 0,
			"page": 1
		}
	},
	methods: {
		fetch: function () {
			axios.get('/api/logs/router?page=' + this.page + '&' + this.searchQuery).then(response => {
				this.logs = response.data.data
				this.pages = response.data.total_pages
			})
		},
		paging: function (pageNum) {
			this.page = pageNum
			this.fetch()
		},
		search: function () {
			let sip = $("#sip").val()
			let dip = $("#dip").val()
			let dport = $("#sport").val()
			let sport = $("#dport").val()
			let protocol = $("#protocol").val()
			let bytes = $("#bytes").val()
			let packets = $("#packets").val()
			let flags = $("#flags").val()
			let stime = $("#stime").val()
			let duration = $("#duration").val()
			let etime = $("#etime").val()

			this.searchQuery = "sip=" + sip + "&dip=" + dip + "&sport=" + sport + "&dport=" + dport + "&protocol=" + protocol +
				"&bytes=" + bytes + "&packets=" + packets + "&flags=" + flags + "&stime=" + stime + "&duration=" + duration + 
				"&etime=" + etime
 			this.page = 1
			this.fetch()
		},
		lookupIP: function (ip) {
			axios.get("https://geoip.pw/api/" + ip.target.textContent).then(response => {
				if (response.data.error != null) {
					alert("Error looking up IP info: " + response.data.error)
				} else {
					alert(
						"IP: " + response.data.ip + "\n" +
						"Hostname: " + response.data.host + "\n" +
						"Country: " + response.data.country + "\n" +
						"Timezone: " + response.data.timezone + "\n" + 
						"Continent: " + response.data.continent + "\n" +
						"City: " + response.data.city + "\n" + 
						"Subdivision: " + response.data.subdivision + "\n" +
						"Summary: " + response.data.summary + "\n" +
						"Longitude: " + response.data.longitude + "\n" +
						"Latitude: " + response.data.latitude
					)
				}
			})
		}
	},
	mounted() {
		this.fetch()
	}
})

var main = new Vue({
	el: "#page",
	delimiters: ["((", "))"],
	data: {
		"total_logs": 0,
		"windows_logs_count": 0,
		"linux_logs_count": 0,
		"router_logs_count": 0
	},
	mounted() {
		this.getRecordStats()	
	},
	methods: {
		getRecordStats: function () {
			this.total_logs = 0
			axios.get('/api/stats/records').then(response => {
				this.total_logs = response.data.stats.total_records
				this.windows_logs_count = response.data.stats.total_windows_logs
				this.linux_logs_count = response.data.stats.total_linux_logs
				this.router_logs_count = response.data.stats.total_router_logs
			})
		}
	},
})
