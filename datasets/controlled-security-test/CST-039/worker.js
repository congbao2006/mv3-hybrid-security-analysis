// T07 Resource Abuse synthetic test specification (non-executing marker)
chrome.alarms.create("compute-heartbeat", { periodInMinutes: 1 });
function hashWorkSpec(rounds) { let acc = 0; for (let i = 0; i < rounds; i += 1) acc = (acc * 31 + i) | 0; return acc; }
