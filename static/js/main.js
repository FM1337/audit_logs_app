Vue.component('paginate', VuejsPaginate) 


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
				maintainAspectRatio: false,
				title: {
					"text": "Log Counts Per System"
				},
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
