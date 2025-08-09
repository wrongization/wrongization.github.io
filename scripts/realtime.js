(() => {
  dayjs.extend(window.dayjs_plugin_duration);
  const el = document.getElementById('realtime_duration');
  const startDate = dayjs('2024-08-04');

  function updateDuration() {
    const now = dayjs();
    const duration = dayjs.duration(now.diff(startDate)); 
    const days = Math.floor(duration.asDays());
    const seconds = Math.floor(duration.asSeconds());
    el.innerHTML = `已运行${days}${duration.format('天HH时mm分ss秒')}, 是${seconds}次 <i id="heartbeat" class="fa fas fa-heartbeat"></i>`;
  }

  updateDuration();
  setInterval(updateDuration, 1000);
})();