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
