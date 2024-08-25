(() => {
    dayjs.extend(window.dayjs_plugin_duration)
    const el = document.getElementById('realtime_duration')
    // 改成自己的时间
    const date = dayjs('2024-08-04')
  
    setInterval(() => {
      const dur = dayjs.duration(dayjs().diff(date))
      const days = String(Math.floor(dur.asDays()))
      const beat = String(Math.floor(dur.asSeconds()))
      el.innerHTML = '已运行' + days + dur.format('天HH时mm分ss秒')+',是'+beat+'次<i id="heartbeat" class="fa fas fa-heartbeat"></i>'
    }, 1000)
  })()